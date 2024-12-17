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

//go:build !nodefaults || coap

package attestedtls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/plgd-dev/go-coap/v3/udp"

	// local modules
	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

type CoapApi struct{}

func init() {
	log.Trace("Adding CoAP API to APIs")
	CmcApis[CmcApi_COAP] = CoapApi{}
}

// Obtains attestation report from cmcd
func (a CoapApi) obtainAR(cc CmcConfig, chbindings []byte, cached []string) (*api.AttestationResponse, error) {

	path := "/Attest"

	// Establish connection
	log.Tracef("Sending attestation request to cmcd on %v", cc.CmcAddr)
	conn, err := udp.Dial(cc.CmcAddr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req := &api.AttestationRequest{
		Nonce:  chbindings,
		Cached: cached,
	}

	// Marshal request
	payload, err := cc.ApiSerializer.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send CoAP POST request
	coapResp, err := conn.Post(ctx, path, ar.GetMediaType(cc.ApiSerializer), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read CoAP reply body
	body, err := coapResp.ReadBody()
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	// Unmarshal response
	resp := new(api.AttestationResponse)
	err = cc.ApiSerializer.Unmarshal(body, resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal body: %w", err)
	}

	return resp, nil
}

// Sends attestationreport to cmcd for verification
func (a CoapApi) verifyAR(cc CmcConfig, req *api.VerificationRequest) error {

	path := "/Verify"

	// Establish connection
	log.Tracef("Sending verification request to cmcd on %v", cc.CmcAddr)
	conn, err := udp.Dial(cc.CmcAddr)
	if err != nil {
		return fmt.Errorf("error dialing: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Marshal verification request
	payload, err := cc.ApiSerializer.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Perform verification request
	resp, err := conn.Post(ctx, path, ar.GetMediaType(cc.ApiSerializer), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	payload, err = resp.ReadBody()
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}

	// Unmarshal verify response
	var verifyResp api.VerificationResponse
	err = cc.ApiSerializer.Unmarshal(payload, &verifyResp)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
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

	// check results
	if !result.Success {
		return errors.New("attestation report verification failed")
	}

	return nil
}

func (a CoapApi) fetchSignature(cc CmcConfig, digest []byte, opts crypto.SignerOpts) ([]byte, error) {

	path := "/TLSSign"

	// Establish connection
	log.Tracef("Sending TLSSign request to cmcd on %v", cc.CmcAddr)
	conn, err := udp.Dial(cc.CmcAddr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

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
	payload, err := cc.ApiSerializer.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send sign request
	resp, err := conn.Post(ctx, path, ar.GetMediaType(cc.ApiSerializer), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	payload, err = resp.ReadBody()
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	// Unmarshal sign response
	var signResp api.TLSSignResponse
	err = cc.ApiSerializer.Unmarshal(payload, &signResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return signResp.SignedContent, nil
}

func (a CoapApi) fetchCerts(cc CmcConfig) ([][]byte, error) {

	path := "/TLSCert"

	// Establish connection
	log.Tracef("Sending TLSCert request to cmcd on %v", cc.CmcAddr)
	conn, err := udp.Dial(cc.CmcAddr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Create TLS certificate request
	req := api.TLSCertRequest{}

	// Marshal payload
	payload, err := cc.ApiSerializer.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send cert request
	resp, err := conn.Post(ctx, path, ar.GetMediaType(cc.ApiSerializer), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	payload, err = resp.ReadBody()
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	// Unmarshal cert response
	var certResp api.TLSCertResponse
	err = cc.ApiSerializer.Unmarshal(payload, &certResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return certResp.Certificate, nil
}

// Fetches the peer cache from the cmcd
func (a CoapApi) fetchPeerCache(cc CmcConfig, fingerprint string) ([]string, error) {

	path := "/PeerCache"

	// Establish connection
	log.Tracef("Sending PeerCache request to cmcd on %v", cc.CmcAddr)
	conn, err := udp.Dial(cc.CmcAddr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req := &api.PeerCacheRequest{
		Peer: fingerprint,
	}

	// Marshal request
	payload, err := cc.ApiSerializer.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send CoAP POST request
	coapResp, err := conn.Post(ctx, path, ar.GetMediaType(cc.ApiSerializer), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read CoAP reply body
	body, err := coapResp.ReadBody()
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	// Unmarshal response
	resp := new(api.PeerCacheResponse)
	err = cc.ApiSerializer.Unmarshal(body, resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal body: %w", err)
	}

	return resp.Cache, nil
}
