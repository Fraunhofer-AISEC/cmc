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
	"errors"
	"fmt"
	"net"

	// local modules
	"github.com/Fraunhofer-AISEC/cmc/api"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

type SocketApi struct{}

func init() {
	log.Trace("Adding Socket API to APIs")
	CmcApis[CmcApi_Socket] = SocketApi{}
}

// Obtains attestation report from cmcd
func (a SocketApi) obtainAR(cc CmcConfig, chbindings []byte, cached []string) ([]byte, map[string][]byte, []string, error) {

	network, addr, err := internal.GetNetworkAndAddr(cc.CmcAddr)
	if err != nil {
		log.Fatalf("Failed to get network and address: %v", err)
	}

	// Establish connection
	log.Debugf("Sending attestation request to cmcd via %v on %v", network, addr)
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error dialing cmcd: %w", err)
	}

	req := &api.AttestationRequest{
		Version: api.GetVersion(),
		Nonce:   chbindings,
		Cached:  cached,
	}

	// Marshal request
	payload, err := cc.ApiSerializer.Marshal(req)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send request
	err = api.Send(conn, payload, api.TypeAttest)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to send request to cmcd: %w", err)
	}

	// Read reply
	payload, mtype, err := api.Receive(conn)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to receive from cmcd: %w", err)
	}

	if mtype == api.TypeError {
		resp := new(api.SocketError)
		err = cc.ApiSerializer.Unmarshal(payload, resp)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to unmarshal error response from cmcd: %w", err)
		}
		return nil, nil, nil, fmt.Errorf("received error from cmcd: %v", resp.Msg)
	} else if mtype != api.TypeAttest {
		return nil, nil, nil, fmt.Errorf("unexpected response type %v from cmcd", api.TypeToString(mtype))
	}

	resp := new(api.AttestationResponse)
	err = cc.ApiSerializer.Unmarshal(payload, resp)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal cmcd attestation response body: %w", err)
	}

	if err := resp.CheckVersion(); err != nil {
		return nil, nil, nil, err
	}

	return resp.Report, resp.Metadata, resp.CacheMisses, nil
}

// Sends attestation report to cmcd for verification
func (a SocketApi) verifyAR(
	cc CmcConfig,
	report, nonce, ca, policies []byte,
	peer string,
	cacheMisses []string,
	metadata map[string][]byte,
) error {

	network, addr, err := internal.GetNetworkAndAddr(cc.CmcAddr)
	if err != nil {
		log.Fatalf("Failed to get network and address: %v", err)
	}

	// Establish connection
	log.Debugf("Sending verification request to cmcd via %v on %v", network, addr)
	conn, err := net.Dial(network, addr)
	if err != nil {
		return fmt.Errorf("error dialing: %w", err)
	}

	req := &api.VerificationRequest{
		Version:     api.GetVersion(),
		Nonce:       nonce,
		Report:      report,
		Metadata:    metadata,
		Ca:          ca,
		Peer:        peer,
		CacheMisses: cacheMisses,
		Policies:    policies,
	}

	// Marshal Verification request
	payload, err := cc.ApiSerializer.Marshal(req)
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
		err = cc.ApiSerializer.Unmarshal(payload, resp)
		if err != nil {
			return fmt.Errorf("failed to unmarshal error response from cmcd: %w", err)
		}
		return fmt.Errorf("received error from cmcd: %v", resp.Msg)
	} else if mtype != api.TypeVerify {
		return fmt.Errorf("unexpected response type %v from cmcd", api.TypeToString(mtype))
	}

	// Unmarshal verify response
	var verifyResp api.VerificationResponse
	err = cc.ApiSerializer.Unmarshal(payload, &verifyResp)
	if err != nil {
		return fmt.Errorf("failed to unmarshal cmcd verify response: %w", err)
	}

	if err := verifyResp.CheckVersion(); err != nil {
		return err
	}

	// Return attestation result via callback if specified
	if cc.ResultCb != nil {
		cc.ResultCb(&verifyResp.Result)
	} else {
		log.Tracef("Will not return attestation result: no callback specified")
	}

	// Check results
	if !verifyResp.Result.Success {
		return errors.New("attestation report verification failed")
	}
	return nil
}

func (a SocketApi) fetchSignature(cc CmcConfig, digest []byte, opts crypto.SignerOpts) ([]byte, error) {

	network, addr, err := internal.GetNetworkAndAddr(cc.CmcAddr)
	if err != nil {
		log.Fatalf("Failed to get network and address: %v", err)
	}

	// Establish connection
	log.Debugf("Sending TLS sign request to cmcd via %v on %v", network, addr)
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %w", err)
	}

	hash, err := api.SignerOptsToHash(opts)
	if err != nil {
		return nil, fmt.Errorf("sign request creation failed: %w", err)
	}

	req := api.TLSSignRequest{
		Version:  api.GetVersion(),
		Content:  digest,
		Hashtype: hash,
	}

	// Parse additional signing options - not implemented fields assume recommend defaults
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		req.PssOpts = &api.PSSOptions{SaltLength: int32(pssOpts.SaltLength)}
	}

	// Marshal payload
	payload, err := cc.ApiSerializer.Marshal(req)
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
		err = cc.ApiSerializer.Unmarshal(payload, resp)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal error response from cmcd: %w", err)
		}
		return nil, fmt.Errorf("received error from cmcd: %v", resp.Msg)
	} else if mtype != api.TypeTLSSign {
		return nil, fmt.Errorf("unexpected response type %v from cmcd", api.TypeToString(mtype))
	}

	// Unmarshal sign response
	var signResp api.TLSSignResponse
	err = cc.ApiSerializer.Unmarshal(payload, &signResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if err := signResp.CheckVersion(); err != nil {
		return nil, err
	}

	return signResp.SignedContent, nil
}

func (a SocketApi) fetchCerts(cc CmcConfig) ([][]byte, error) {

	network, addr, err := internal.GetNetworkAndAddr(cc.CmcAddr)
	if err != nil {
		log.Fatalf("Failed to get network and address: %v", err)
	}

	// Establish connection
	log.Debugf("Sending TLS certificate request to cmcd via %v on %v", network, addr)
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %w", err)
	}

	// Create TLS certificate request
	req := api.TLSCertRequest{
		Version: api.GetVersion(),
	}

	// Marshal payload
	payload, err := cc.ApiSerializer.Marshal(req)
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
		err = cc.ApiSerializer.Unmarshal(payload, resp)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal error response from cmcd: %w", err)
		}
		return nil, fmt.Errorf("received error from cmcd: %v", resp.Msg)
	} else if mtype != api.TypeTLSCert {
		return nil, fmt.Errorf("unexpected response type %v from cmcd", api.TypeToString(mtype))
	}

	// Unmarshal cert response
	var certResp api.TLSCertResponse
	err = cc.ApiSerializer.Unmarshal(payload, &certResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if err := certResp.CheckVersion(); err != nil {
		return nil, err
	}

	return certResp.Certificate, nil
}

func (a SocketApi) fetchPeerCache(cc CmcConfig, fingerprint string) ([]string, error) {

	network, addr, err := internal.GetNetworkAndAddr(cc.CmcAddr)
	if err != nil {
		log.Fatalf("Failed to get network and address: %v", err)
	}

	// Establish connection
	log.Debugf("Sending peer cache request to cmcd via %v on %v", network, addr)
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %w", err)
	}

	req := api.PeerCacheRequest{
		Version: api.GetVersion(),
		Peer:    fingerprint,
	}

	// Marshal payload
	payload, err := cc.ApiSerializer.Marshal(req)
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
		err = cc.ApiSerializer.Unmarshal(payload, resp)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal error response from cmcd: %w", err)
		}
		return nil, fmt.Errorf("received error from cmcd: %v", resp.Msg)
	} else if mtype != api.TypePeerCache {
		return nil, fmt.Errorf("unexpected response type %v from cmcd", api.TypeToString(mtype))
	}

	// Unmarshal cert response
	var cacheResp api.PeerCacheResponse
	err = cc.ApiSerializer.Unmarshal(payload, &cacheResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if err := cacheResp.CheckVersion(); err != nil {
		return nil, err
	}

	return cacheResp.Cache, nil
}
