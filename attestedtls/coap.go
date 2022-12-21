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
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/udp"

	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	api "github.com/Fraunhofer-AISEC/cmc/coapapi"
)

type CoapApi struct{}

func init() {
	log.Trace("Adding CoAP API to APIs")
	cmcApis[CmcApi_COAP] = CoapApi{}
}

// Creates attestation report request to be sent to peer
func (a CoapApi) createARRequest(nonce []byte) ([]byte, error) {
	// Create AR request with nonce
	req := &api.AttestationRequest{
		Nonce: nonce,
	}
	data, err := cbor.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}
	return data, nil
}

// Parses attestation report response received from peer
func (a CoapApi) parseARResponse(data []byte) ([]byte, error) {
	// Parse response msg
	resp := &api.AttestationResponse{}
	err := cbor.Unmarshal(data, resp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation report response: %w", err)
	}

	return resp.AttestationReport, nil
}

// Obtains attestation report from cmcd
func (a CoapApi) obtainAR(request []byte, cc cmcConfig, cert []byte) ([]byte, error) {

	path := "/Attest"

	// Establish connection
	log.Trace("Contacting cmcd via coap on: " + cc.cmcAddress + ":" + cc.cmcPort)
	conn, err := udp.Dial(cc.cmcAddress + ":" + cc.cmcPort)
	if err != nil {
		return nil, fmt.Errorf("Error dialing: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Unmarshal incoming attestation request to get nonce
	req := &api.AttestationRequest{}
	err = cbor.Unmarshal(request, req)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal CoAP message body: %v", err)
	}

	// Check nonce length
	if len(req.Nonce) != noncelen {
		return nil, fmt.Errorf("nonce (%v) does not have expected size (%v)", len(req.Nonce), noncelen)
	}

	// Generate final nonce through combining the request nonce with the
	// certificate the connection was established to prevent MitM-attacks
	combinedNonce := sha256.Sum256(append(cert[:], req.Nonce[:]...))
	req.Nonce = combinedNonce[:]

	// Marshal request with final nonce again
	payload, err := cbor.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send CoAP POST request
	resp, err := conn.Post(ctx, path, message.AppCBOR, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read CoAP reply body
	payload, err = resp.ReadBody()
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	return payload, nil
}

// Sends attestationreport to cmcd for verification
func (a CoapApi) verifyAR(nonce, report []byte, cc cmcConfig) error {

	path := "/Verify"

	// Establish connection
	log.Trace("Contacting cmcd via coap on: " + cc.cmcAddress + ":" + cc.cmcPort)
	conn, err := udp.Dial(cc.cmcAddress + ":" + cc.cmcPort)
	if err != nil {
		return fmt.Errorf("Error dialing: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Create Verification request
	req := &api.VerificationRequest{
		Nonce:             nonce,
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
	var result ar.VerificationResult
	err = json.Unmarshal(verifyResp.VerificationResult, &result)
	if err != nil {
		return fmt.Errorf("could not parse verification result: %w", err)
	}

	// check results
	if !result.Success {
		return NewAttestedError(result, errors.New("verification failed"))
	}
	return nil
}

func (a CoapApi) fetchSignature(cc cmcConfig, digest []byte, opts crypto.SignerOpts) ([]byte, error) {

	path := "/TLSSign"

	// Establish connection
	log.Trace("Contacting cmcd via coap on: " + cc.cmcAddress + ":" + cc.cmcPort)
	conn, err := udp.Dial(cc.cmcAddress + ":" + cc.cmcPort)
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
	log.Trace("Contacting cmcd via coap on: " + cc.cmcAddress + ":" + cc.cmcPort)
	conn, err := udp.Dial(cc.cmcAddress + ":" + cc.cmcPort)
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
