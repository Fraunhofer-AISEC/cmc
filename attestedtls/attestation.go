// Copyright (c) 2021 Fraunhofer AISEC
// Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package attestedtls

import (
	"crypto/tls"
	"fmt"

	"github.com/sirupsen/logrus"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

type AtlsHandshakeRequest struct {
	Attest         AttestSelect `json:"attest" cbor:"0,keyasint"`
	Cached         []string     `json:"cached" cbor:"1,keyasint"`
	ExtendedReport bool         `json:"extendedReport" cbor:"2,keyasint"`
}

type AtlsHandshakeResponse struct {
	Attest      AttestSelect      `json:"attest" cbor:"0,keyasint"`
	Error       string            `json:"error" cbor:"1,keyasint"`
	Report      []byte            `json:"report" cbor:"2,keyasint"`
	Metadata    map[string][]byte `json:"metadata" cbor:"3,keyasint"`
	CacheMisses []string          `json:"cacheMisses,omitempty" cbor:"4,keyasint"`
}

type AtlsHandshakeComplete struct {
	Success bool   `json:"success" cbor:"0,keyasint"`
	Error   string `json:"error" cbor:"1,keyasint"`
}

var log = logrus.WithField("service", "atls")

func atlsHandshakeStart(conn *tls.Conn, chbindings []byte, fingerprint string, cc CmcConfig, endpoint Endpoint) error {

	var err error
	var cache []string

	ownAddr := conn.LocalAddr().String()
	peerAddr := conn.RemoteAddr().String()

	log.Debugf("Performing atls handshake with %v", peerAddr)

	if cc.ApiSerializer == nil {
		return fmt.Errorf("internal error: API serializer is nil")
	}

	attestSelf, attestPeer := convertAttestMode(cc.Attest, endpoint)

	if attestPeer {
		if fingerprint == "" {
			return fmt.Errorf("internal error: TLS peer cert fingerprint is nil")
		}

		cache, err = cc.CmcApi.fetchPeerCache(cc, fingerprint)
		if err != nil {
			return fmt.Errorf("failed to fetch peer cache: %w", err)
		}
	}

	// Send attestation request
	log.Debugf("Verifier %v: sending atls handshake request mode %v to %v",
		ownAddr, cc.Attest.String(), peerAddr)
	err = sendAtlsRequest(conn, cc.ApiSerializer, cc.Attest, cache)
	if err != nil {
		return fmt.Errorf("verifer %v: failed to send atls handshake request to %v: %w",
			ownAddr, peerAddr, err)
	}

	// Wait for attestation request to be received
	log.Debugf("Prover %v: waiting for atls handshake request mode %v from %v",
		ownAddr, cc.Attest.String(), peerAddr)
	req, err := receiveAtlsRequest(conn)
	if err != nil {
		return fmt.Errorf("prover %v: failed to receive attestation request from %v: %w",
			ownAddr, peerAddr, err)
	}
	log.Debugf("Prover %v: received atls handshake request mode %v from %v",
		ownAddr, req.Attest.String(), peerAddr)

	// Check that configured attestation mode matches peers attestation mode
	err = checkAttestationMode(cc.Attest, req.Attest)
	if err != nil {
		return err
	}

	ownResp := AtlsHandshakeResponse{
		Attest: cc.Attest,
	}

	// Generate attestation report of own endpoint if configured
	if attestSelf {
		log.Debugf("Prover %v: attesting own endpoint", ownAddr)
		// Obtain attestation report from local cmcd
		ownResp.Report, ownResp.Metadata, ownResp.CacheMisses, err = cc.CmcApi.obtainAR(cc, chbindings, req.Cached)
		if err != nil {
			ownResp.Error = fmt.Errorf("internal error: prover %v: could not obtain own AR: %w", ownAddr, err).Error()
			log.Warn(ownResp.Error)
		} else {
			log.Debugf("Prover %v: Created report length %v, metadata items %v, cache misses %v",
				ownAddr, len(ownResp.Report), len(ownResp.Metadata), len(ownResp.CacheMisses))
		}
	} else {
		log.Debugf("Prover %v: Skipping own attestation", ownAddr)
	}

	// Send created atls handshake response to listener asynchronously to avoid TCP deadlock
	log.Debugf("Prover %v: sending atls handshake response with report length %v to %v",
		ownAddr, len(ownResp.Report), peerAddr)
	errChan := make(chan error)
	go func() {
		err := sendAtlsResponse(conn, cc.ApiSerializer, ownResp)
		errChan <- err
		close(errChan)
	}()

	// Wait for atls response with report from peer
	log.Debugf("Verifier %v: waiting for atls handshake response from %v", ownAddr, peerAddr)
	peerResp, err := receiveAtlsResponse(conn)
	if err != nil {
		return fmt.Errorf("verifier: failed to receive atls handshake response from %v: %w",
			peerAddr, err)
	}
	// Check error message from peer
	if peerResp.Error != "" {
		return fmt.Errorf("atls response returned error: %v", peerResp.Error)
	}
	log.Debugf("Verifier %v: received atls handshake response mode %v from %v",
		ownAddr, peerResp.Attest.String(), peerAddr)

	// Wait until sending of own handshake response is finished
	log.Debugf("Prover %v: Waiting for atls handshake response sending to be completed", ownAddr)
	err = <-errChan
	if err != nil {
		return fmt.Errorf("prover %v: failed to send atls handshake response: %w", ownAddr, err)
	}
	log.Debugf("Prover %v: finished sending atls handshake response to %v",
		ownAddr, peerAddr)

	// Check that configured attestation mode matches peers attestation mode
	err = checkAttestationMode(cc.Attest, req.Attest)
	if err != nil {
		return err
	}

	// Verify attestation report from peer if configured
	if attestPeer {

		// Verify AR from listener with own channel bindings
		log.Debugf("Verifier %v: verifying attestation report from %v", ownAddr, peerAddr)
		err = cc.CmcApi.verifyAR(cc, peerResp.Report, chbindings, cc.Ca, cc.Policies, fingerprint,
			peerResp.CacheMisses, peerResp.Metadata)
		if err != nil {
			return fmt.Errorf("verifier %v: failed to attest %v: %w", ownAddr, peerAddr, err)
		}
		log.Debugf("Verifier %v: attestation report verification from %v successful", ownAddr, peerAddr)
	} else {
		log.Debugf("Verifier %v: skipping peer verification", ownAddr)
	}

	return nil
}

func aTlsHandshakeComplete(conn *tls.Conn, s ar.Serializer, handshakeError error) error {

	if s == nil {
		return fmt.Errorf("internal error: API serializer is nil")
	}

	// Finally send and receive handshake complete
	complete := AtlsHandshakeComplete{
		Success: handshakeError == nil,
	}
	if handshakeError != nil {
		complete.Error = handshakeError.Error()
	}

	log.Debugf("Prover %v: sending atls handshake complete to %v",
		conn.LocalAddr().String(), conn.RemoteAddr().String())
	err := sendAtlsComplete(conn, s, complete)
	if err != nil {
		return fmt.Errorf("%v: failed to send handshake complete to %v: %w",
			conn.LocalAddr().String(), conn.RemoteAddr().String(), err)
	}

	log.Debugf("Verifier %v: waiting for atls handshake complete from %v",
		conn.LocalAddr().String(), conn.RemoteAddr().String())
	resp, err := receiveAtlsComplete(conn)
	if err != nil {
		return fmt.Errorf("%v: failed to receive handshake complete from %v: %w",
			conn.LocalAddr().String(), conn.RemoteAddr().String(), err)
	}

	if handshakeError == nil && resp.Success {
		log.Debug("atls handshake successful")
	} else {
		if handshakeError != nil {
			return fmt.Errorf("%v: attestation with peer %v failed: %v", conn.LocalAddr().String(),
				conn.RemoteAddr().String(), handshakeError.Error())
		}
		if !resp.Success {
			return fmt.Errorf("%v: peer %v reports failed attestation: %v", conn.LocalAddr().String(),
				conn.RemoteAddr().String(), resp.Error)
		}
	}

	return nil
}

func receiveAtlsResponse(conn *tls.Conn) (*AtlsHandshakeResponse, error) {

	// Receive data
	data, err := Read(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	s, err := ar.DetectSerialization(data)
	if err != nil {
		return nil, fmt.Errorf("failed to detect atls response serializationt: %v", err)
	}

	// Unmarshal handshake response
	resp := new(AtlsHandshakeResponse)
	err = s.Unmarshal(data, resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ATLS handshake response: %w", err)
	}

	return resp, nil
}

func receiveAtlsRequest(conn *tls.Conn) (*AtlsHandshakeRequest, error) {

	// Receive data
	data, err := Read(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	s, err := ar.DetectSerialization(data)
	if err != nil {
		return nil, fmt.Errorf("failed to detect atls complete serializationt: %v", err)
	}

	// Unmarshal handshake request
	req := new(AtlsHandshakeRequest)
	err = s.Unmarshal(data, req)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ATLS handshake response: %w", err)
	}

	return req, nil
}

func receiveAtlsComplete(conn *tls.Conn) (*AtlsHandshakeComplete, error) {

	// Receive data
	data, err := Read(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read handshake complete: %w", err)
	}

	s, err := ar.DetectSerialization(data)
	if err != nil {
		return nil, fmt.Errorf("failed to detect atls complete serializationt: %v", err)
	}

	// Unmarshal handshake request
	complete := new(AtlsHandshakeComplete)
	err = s.Unmarshal(data, complete)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal atls handshake complete: %w", err)
	}

	return complete, nil
}

func sendAtlsRequest(conn *tls.Conn, s ar.Serializer, attest AttestSelect, cache []string) error {

	// Create request
	// TODO Extended report and cached metadata configuration
	req := &AtlsHandshakeRequest{
		Attest:         attest,
		ExtendedReport: false,
		Cached:         cache,
	}

	// Marshal payload
	payload, err := s.Marshal(&req)
	if err != nil {
		return fmt.Errorf("failed to marshal atls handshake request: %w", err)
	}

	// Send payload to peer
	err = Write(payload, conn)
	if err != nil {
		return fmt.Errorf("failed to send: %w", err)
	}

	return nil
}

func sendAtlsResponse(conn *tls.Conn, s ar.Serializer, resp AtlsHandshakeResponse) error {

	// Marshal payload
	payload, err := s.Marshal(&resp)
	if err != nil {
		return fmt.Errorf("internal error: failed to marshal atls handshake request: %w", err)
	}

	log.Debugf("Sending atls handshake response length %v", len(payload))

	// Send payload to peer
	err = Write(payload, conn)
	if err != nil {
		return fmt.Errorf("failed to send: %w", err)
	}

	return nil
}

func sendAtlsComplete(conn *tls.Conn, s ar.Serializer, complete AtlsHandshakeComplete) error {

	// Marshal payload
	payload, err := s.Marshal(&complete)
	if err != nil {
		return fmt.Errorf("internal error: failed to marshal atls handshake request: %w", err)
	}

	// Send payload to peer
	err = Write(payload, conn)
	if err != nil {
		return fmt.Errorf("failed to send: %w", err)
	}

	return nil
}

func convertAttestMode(attest AttestSelect, endpoint Endpoint) (bool, bool) {
	attestSelf := true
	attestPeer := true
	if attest == Attest_None {
		attestSelf = false
		attestPeer = false
	}
	if endpoint == Endpoint_Server {
		if attest == Attest_Server {
			attestPeer = false
		}
		if attest == Attest_Client {
			attestSelf = false
		}
	}
	if endpoint == Endpoint_Client {
		if attest == Attest_Server {
			attestSelf = false
		}
		if attest == Attest_Client {
			attestPeer = false
		}
	}
	return attestSelf, attestPeer
}

func checkAttestationMode(own, peer AttestSelect) error {
	if own == peer {
		log.Tracef("Matching attestation mode: [%v]", own.String())
	} else {
		return fmt.Errorf("mismatching attestation mode, local set to: [%v], while remote is set to: [%v]",
			own.String(), peer.String())
	}
	return nil
}
