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

	"github.com/fxamacker/cbor/v2"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/udp"

	// local modules
	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

type CoapApi struct{}

func init() {
	log.Trace("Adding CoAP API to APIs")
	cmcApis[CmcApi_COAP] = CoapApi{}
}

// Obtains attestation report from cmcd
func (a CoapApi) obtainAR(cc cmcConfig, chbindings []byte) ([]byte, error) {

	path := "/Attest"

	// Establish connection
	log.Tracef("Contacting cmcd via coap on %v", cc.cmcAddr)
	conn, err := udp.Dial(cc.cmcAddr)
	if err != nil {
		return nil, fmt.Errorf("Error dialing: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req := &api.AttestationRequest{
		Id:    id,
		Nonce: chbindings,
	}

	// Marshal request
	payload, err := cbor.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send CoAP POST request
	coapResp, err := conn.Post(ctx, path, message.AppCBOR, bytes.NewReader(payload))
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
	err = cbor.Unmarshal(body, resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal body: %w", err)
	}

	return resp.AttestationReport, nil
}

// Sends attestationreport to cmcd for verification
func (a CoapApi) verifyAR(chbindings, report []byte, cc cmcConfig) error {

	path := "/Verify"

	// Establish connection
	log.Tracef("Contacting cmcd via coap on %v", cc.cmcAddr)
	conn, err := udp.Dial(cc.cmcAddr)
	if err != nil {
		return fmt.Errorf("Error dialing: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Create Verification request
	req := &api.VerificationRequest{
		Nonce:             chbindings,
		AttestationReport: report,
		Ca:                cc.ca,
		Policies:          cc.policies,
	}
	payload, err := cbor.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Perform Verify request
	resp, err := conn.Post(ctx, path, message.AppCBOR, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	payload, err = resp.ReadBody()
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}

	// Unmarshal verify response
	var verifyResp api.VerificationResponse
	err = cbor.Unmarshal(payload, &verifyResp)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Parse VerificationResult
	if cc.result == nil {
		cc.result = new(ar.VerificationResult)
	}
	err = json.Unmarshal(verifyResp.VerificationResult, cc.result)
	if err != nil {
		return fmt.Errorf("could not parse verification result: %w", err)
	}

	// check results
	if !cc.result.Success {
		return NewAttestedError(*cc.result, errors.New("verification failed"))
	}

	return nil
}

func (a CoapApi) fetchSignature(cc cmcConfig, digest []byte, opts crypto.SignerOpts) ([]byte, error) {

	path := "/TLSSign"

	// Establish connection
	log.Tracef("Contacting cmcd via coap on %v", cc.cmcAddr)
	conn, err := udp.Dial(cc.cmcAddr)
	if err != nil {
		return nil, fmt.Errorf("Error dialing: %w", err)
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
	payload, err := cbor.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send sign request
	resp, err := conn.Post(ctx, path, message.AppCBOR, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	payload, err = resp.ReadBody()
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	// Unmarshal sign response
	var signResp api.TLSSignResponse
	err = cbor.Unmarshal(payload, &signResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return signResp.SignedContent, nil
}

func (a CoapApi) fetchCerts(cc cmcConfig) ([][]byte, error) {

	path := "/TLSCert"

	// Establish connection
	log.Tracef("Contacting cmcd via coap on %v", cc.cmcAddr)
	conn, err := udp.Dial(cc.cmcAddr)
	if err != nil {
		return nil, fmt.Errorf("Error dialing: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Create TLS certificate request
	req := api.TLSCertRequest{
		// TODO ID currently not used
		Id: "",
	}

	// Marshal payload
	payload, err := cbor.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send cert request
	resp, err := conn.Post(ctx, path, message.AppCBOR, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	payload, err = resp.ReadBody()
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	// Unmarshal cert response
	var certResp api.TLSCertResponse
	err = cbor.Unmarshal(payload, &certResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return certResp.Certificate, nil
}
