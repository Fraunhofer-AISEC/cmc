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

//go:build !nodefaults || socket

package attestedtls

import (
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/fxamacker/cbor/v2"

	// local modules
	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

type SocketApi struct{}

func init() {
	log.Trace("Adding Socket API to APIs")
	CmcApis[CmcApi_Socket] = SocketApi{}
}

// Obtains attestation report from cmcd
func (a SocketApi) obtainAR(cc CmcConfig, chbindings []byte, cached []string) (*api.AttestationResponse, error) {

	// Establish connection
	log.Tracef("Sending attestation request to cmcd via %v on %v", cc.Network, cc.CmcAddr)
	conn, err := net.Dial(cc.Network, cc.CmcAddr)
	if err != nil {
		return nil, fmt.Errorf("error dialing cmcd: %w", err)
	}

	req := &api.AttestationRequest{
		Nonce:  chbindings,
		Cached: cached,
	}

	// Marshal request
	payload, err := cbor.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send request
	err = api.Send(conn, payload, api.TypeAttest)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to cmcd: %w", err)
	}

	// Read reply
	payload, mtype, err := api.Receive(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive from cmcd: %w", err)
	}

	if mtype == api.TypeError {
		resp := new(api.SocketError)
		err = cbor.Unmarshal(payload, resp)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal error response from cmcd: %w", err)
		}
		return nil, fmt.Errorf("received error from cmcd: %v", resp.Msg)
	} else if mtype != api.TypeAttest {
		return nil, fmt.Errorf("unexpected response type %v from cmcd", api.TypeToString(mtype))
	}

	resp := new(api.AttestationResponse)
	err = cbor.Unmarshal(payload, resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal cmcd attestation response body: %w", err)
	}

	return resp, nil
}

// Sends attestation report to cmcd for verification
func (a SocketApi) verifyAR(cc CmcConfig, req *api.VerificationRequest) error {

	// Establish connection
	log.Tracef("Sending verification request to cmcd via %v on %v", cc.Network, cc.CmcAddr)
	conn, err := net.Dial(cc.Network, cc.CmcAddr)
	if err != nil {
		return fmt.Errorf("error dialing: %w", err)
	}

	// Marshal Verification request
	payload, err := cbor.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Perform verification request
	err = api.Send(conn, payload, api.TypeVerify)
	if err != nil {
		return fmt.Errorf("failed to send request to cmcd: %w", err)
	}

	// Read reply
	payload, mtype, err := api.Receive(conn)
	if err != nil {
		return fmt.Errorf("failed to receive from cmcd: %v", err)
	}

	if mtype == api.TypeError {
		resp := new(api.SocketError)
		err = cbor.Unmarshal(payload, resp)
		if err != nil {
			return fmt.Errorf("failed to unmarshal error response from cmcd: %w", err)
		}
		return fmt.Errorf("received error from cmcd: %v", resp.Msg)
	} else if mtype != api.TypeVerify {
		return fmt.Errorf("unexpected response type %v from cmcd", api.TypeToString(mtype))
	}

	// Unmarshal verify response
	var verifyResp api.VerificationResponse
	err = cbor.Unmarshal(payload, &verifyResp)
	if err != nil {
		return fmt.Errorf("failed to unmarshal cmcd verify response: %w", err)
	}

	// Parse VerificationResult (always json)
	result := new(ar.VerificationResult)
	err = json.Unmarshal(verifyResp.VerificationResult, result)
	if err != nil {
		return fmt.Errorf("could not parse verification result: %w", err)
	}

	// Return attestation result via callback if specified
	if cc.ResultCb != nil {
		cc.ResultCb(result)
	} else {
		log.Tracef("Will not return attestation result: no callback specified")
	}

	// Check results
	if !result.Success {
		return errors.New("attestation report verification failed")
	}
	return nil
}

func (a SocketApi) fetchSignature(cc CmcConfig, digest []byte, opts crypto.SignerOpts) ([]byte, error) {

	// Establish connection
	log.Tracef("Contacting cmcd via %v on %v", cc.Network, cc.CmcAddr)
	conn, err := net.Dial(cc.Network, cc.CmcAddr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %w", err)
	}

	hash, err := api.SignerOptsToHash(opts)
	if err != nil {
		return nil, fmt.Errorf("sign request creation failed: %w", err)
	}

	req := api.TLSSignRequest{
		Content:  digest,
		Hashtype: hash,
	}

	// Parse additional signing options - not implemented fields assume recommend defaults
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		req.PssOpts = &api.PSSOptions{SaltLength: int32(pssOpts.SaltLength)}
	}

	// Marshal payload
	payload, err := cbor.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send sign request
	err = api.Send(conn, payload, api.TypeTLSSign)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read reply
	payload, mtype, err := api.Receive(conn)
	if err != nil {
		log.Fatalf("failed to receive: %v", err)
	}

	if mtype == api.TypeError {
		resp := new(api.SocketError)
		err = cbor.Unmarshal(payload, resp)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal error response from cmcd: %w", err)
		}
		return nil, fmt.Errorf("received error from cmcd: %v", resp.Msg)
	} else if mtype != api.TypeTLSSign {
		return nil, fmt.Errorf("unexpected response type %v from cmcd", api.TypeToString(mtype))
	}

	// Unmarshal sign response
	var signResp api.TLSSignResponse
	err = cbor.Unmarshal(payload, &signResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return signResp.SignedContent, nil
}

func (a SocketApi) fetchCerts(cc CmcConfig) ([][]byte, error) {

	// Establish connection
	log.Tracef("Contacting cmcd via %v on %v", cc.Network, cc.CmcAddr)
	conn, err := net.Dial(cc.Network, cc.CmcAddr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %w", err)
	}

	// Create TLS certificate request
	req := api.TLSCertRequest{}

	// Marshal payload
	payload, err := cbor.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send cert request
	err = api.Send(conn, payload, api.TypeTLSCert)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read reply
	payload, mtype, err := api.Receive(conn)
	if err != nil {
		log.Fatalf("failed to receive: %v", err)
	}

	if mtype == api.TypeError {
		resp := new(api.SocketError)
		err = cbor.Unmarshal(payload, resp)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal error response from cmcd: %w", err)
		}
		return nil, fmt.Errorf("received error from cmcd: %v", resp.Msg)
	} else if mtype != api.TypeTLSCert {
		return nil, fmt.Errorf("unexpected response type %v from cmcd", api.TypeToString(mtype))
	}

	// Unmarshal cert response
	var certResp api.TLSCertResponse
	err = cbor.Unmarshal(payload, &certResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return certResp.Certificate, nil
}

func (a SocketApi) fetchPeerCache(cc CmcConfig, fingerprint string) ([]string, error) {

	// Establish connection
	log.Tracef("Contacting cmcd via %v on %v", cc.Network, cc.CmcAddr)
	conn, err := net.Dial(cc.Network, cc.CmcAddr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %w", err)
	}

	req := api.PeerCacheRequest{
		Peer: fingerprint,
	}

	// Marshal payload
	payload, err := cbor.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send cert request
	err = api.Send(conn, payload, api.TypePeerCache)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read reply
	payload, mtype, err := api.Receive(conn)
	if err != nil {
		log.Fatalf("failed to receive: %v", err)
	}

	if mtype == api.TypeError {
		resp := new(api.SocketError)
		err = cbor.Unmarshal(payload, resp)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal error response from cmcd: %w", err)
		}
		return nil, fmt.Errorf("received error from cmcd: %v", resp.Msg)
	} else if mtype != api.TypePeerCache {
		return nil, fmt.Errorf("unexpected response type %v from cmcd", api.TypeToString(mtype))
	}

	// Unmarshal cert response
	var cacheResp api.PeerCacheResponse
	err = cbor.Unmarshal(payload, &cacheResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return cacheResp.Cache, nil
}
