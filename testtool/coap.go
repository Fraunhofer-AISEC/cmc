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

package main

// Install github packages with "go get [url]"
import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/udp"

	// local modules

	"github.com/Fraunhofer-AISEC/cmc/api"
	"github.com/Fraunhofer-AISEC/cmc/attestedtls"
	m "github.com/Fraunhofer-AISEC/cmc/measure"
)

type CoapApi struct{}

func init() {
	apis["coap"] = CoapApi{}
}

func (a CoapApi) generate(c *config) {

	log.Tracef("Connecting via CoAP to %v", c.CmcAddr)

	// Establish connection
	conn, err := udp.Dial(c.CmcAddr)
	if err != nil {
		log.Fatalf("Error dialing: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	path := "/Attest"

	// Generate random nonce
	nonce := make([]byte, 8)
	_, err = rand.Read(nonce)
	if err != nil {
		log.Fatalf("Failed to read random bytes: %v", err)
	}

	// Generate attestation request
	req := &api.AttestationRequest{
		Nonce: nonce,
	}

	// Marshal CoAP payload
	payload, err := cbor.Marshal(req)
	if err != nil {
		log.Fatalf("failed to marshal payload: %v", err)
	}

	// Send CoAP POST request
	resp, err := conn.Post(ctx, path, message.AppCBOR, bytes.NewReader(payload))
	if err != nil {
		log.Fatalf("failed to send request: %v", err)
	}

	// Read CoAP reply body
	payload, err = resp.ReadBody()
	if err != nil {
		log.Fatalf("failed to read body: %v", err)
	}

	// Unmarshal attestation response
	var attestationResp api.AttestationResponse
	err = cbor.Unmarshal(payload, &attestationResp)
	if err != nil {
		log.Fatalf("failed to unmarshal response")
	}

	// Save the attestation report for the verifier
	err = os.WriteFile(c.ReportFile, attestationResp.AttestationReport, 0644)
	if err != nil {
		log.Fatalf("Failed to save attestation report as %v: %v", c.ReportFile, err)
	}
	log.Infof("Wrote attestation report: %v", c.ReportFile)

	// Save the nonce for the verifier
	os.WriteFile(c.NonceFile, nonce, 0644)
	if err != nil {
		log.Fatalf("Failed to save nonce as %v: %v", c.NonceFile, err)
	}
	log.Infof("Wrote nonce: %v", c.NonceFile)

}

func (a CoapApi) verify(c *config) {

	// Read the attestation report, CA and the nonce previously stored
	data, err := os.ReadFile(c.ReportFile)
	if err != nil {
		log.Fatalf("Failed to read file %v: %v", c.ReportFile, err)
	}

	nonce, err := os.ReadFile(c.NonceFile)
	if err != nil {
		log.Fatalf("Failed to read nonce: %v", err)
	}

	req := &api.VerificationRequest{
		Nonce:             nonce,
		AttestationReport: data,
		Ca:                c.ca,
		Policies:          c.policies,
	}

	resp, err := verifyInternal(c.CmcAddr, req)
	if err != nil {
		log.Fatalf("Failed to verify: %v", err)
	}

	err = saveResult(c.ResultFile, c.Publish, resp.VerificationResult)
	if err != nil {
		log.Fatalf("Failed to save result: %v", err)
	}
}

func (a CoapApi) measure(c *config) {

	ctrConfig, err := os.ReadFile(c.CtrConfig)
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}

	configHash, _, err := m.GetConfigMeasurement("mycontainer", ctrConfig)
	if err != nil {
		log.Fatalf("Failed to measure config: %v", err)
	}

	rootfsHash, err := m.GetRootfsMeasurement(c.CtrRootfs)
	if err != nil {
		log.Fatalf("Failed to measure rootfs: %v", err)
	}

	req := &api.MeasureRequest{
		Name:         c.CtrName,
		ConfigSha256: configHash,
		RootfsSha256: rootfsHash,
	}

	resp, err := measureInternal(c.CmcAddr, req)
	if err != nil {
		log.Fatalf("Failed to verify: %v", err)
	}

	log.Infof("Measure Result: %v", resp.Success)
}

func (a CoapApi) dial(c *config) {
	dialInternal(c, attestedtls.CmcApi_COAP, nil)
}

func (a CoapApi) listen(c *config) {
	listenInternal(c, attestedtls.CmcApi_COAP, nil)
}

func (a CoapApi) request(c *config) {
	requestInternal(c, attestedtls.CmcApi_COAP, nil)
}

func (a CoapApi) serve(c *config) {
	serveInternal(c, attestedtls.CmcApi_COAP, nil)
}

func (a CoapApi) cacerts(c *config) {
	getCaCertsInternal(c)
}

func (a CoapApi) iothub(c *config) {
	// Start coap server
	err := serveHub(c)
	if err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

func verifyInternal(addr string, req *api.VerificationRequest,
) (*api.VerificationResponse, error) {

	log.Tracef("Connecting via CoAP to %v", addr)

	// Establish connection
	conn, err := udp.Dial(addr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	path := "/Verify"

	// Marshal CoAP payload
	payload, err := cbor.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Send CoAP POST request
	resp, err := conn.Post(ctx, path, message.AppCBOR, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}

	// Read CoAP reply body
	payload, err = resp.ReadBody()
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %v", err)
	}

	// Unmarshal attestation response
	verifyResp := new(api.VerificationResponse)
	err = cbor.Unmarshal(payload, verifyResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response")
	}

	return verifyResp, nil
}

func measureInternal(addr string, req *api.MeasureRequest,
) (*api.MeasureResponse, error) {

	log.Tracef("Connecting via CoAP to %v", addr)

	// Establish connection
	conn, err := udp.Dial(addr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	path := "/Measure"

	// Marshal CoAP payload
	payload, err := cbor.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Send CoAP POST request
	resp, err := conn.Post(ctx, path, message.AppCBOR, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}

	// Read CoAP reply body
	payload, err = resp.ReadBody()
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %v", err)
	}

	// Unmarshal attestation response
	measureResp := new(api.MeasureResponse)
	err = cbor.Unmarshal(payload, measureResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response")
	}

	return measureResp, nil
}
