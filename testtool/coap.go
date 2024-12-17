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
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	"github.com/plgd-dev/go-coap/v3/udp"

	// local modules

	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	payload, err := c.apiSerializer.Marshal(req)
	if err != nil {
		log.Fatalf("failed to marshal payload: %v", err)
	}

	// Send CoAP POST request
	resp, err := conn.Post(ctx, path, ar.GetMediaType(c.apiSerializer), bytes.NewReader(payload))
	if err != nil {
		log.Fatalf("failed to send request: %v", err)
	}

	// Read CoAP reply body
	payload, err = resp.ReadBody()
	if err != nil {
		log.Fatalf("failed to read body: %v", err)
	}

	// Save the attestation report for the verifier
	err = saveReport(c, payload, nonce)
	if err != nil {
		log.Fatalf("failed to save report: %v", err)
	}

}

func (a CoapApi) verify(c *config) {

	// Read the attestation report and the nonce previously stored
	report, nonce, err := loadReport(c)
	if err != nil {
		log.Fatalf("Failed to load report: %v", err)
	}

	req := &api.VerificationRequest{
		Nonce:    nonce,
		Report:   report.Report,
		Metadata: report.Metadata,
		Ca:       c.ca,
		Policies: c.policies,
	}

	resp, err := verifyInternal(c, req)
	if err != nil {
		log.Fatalf("Failed to verify: %v", err)
	}

	err = saveResult(c.ResultFile, c.Publish, resp.VerificationResult)
	if err != nil {
		log.Fatalf("Failed to save result: %v", err)
	}
}

func (a CoapApi) measure(c *config) {

	if c.CtrConfig == "" {
		log.Fatalf("Mode measure requires OCI runtime config to be specified")
	}
	if c.CtrRootfs == "" {
		log.Fatalf("Mode measure requires container rootfs to be specified")
	}

	ctrConfig, err := os.ReadFile(c.CtrConfig)
	if err != nil {
		log.Fatalf("Failed to read oci runtime config: %v", err)
	}

	configHash, _, _, err := m.GetSpecMeasurement("mycontainer", ctrConfig)
	if err != nil {
		log.Fatalf("Failed to measure config: %v", err)
	}

	rootfsHash, err := m.GetRootfsMeasurement(c.CtrRootfs)
	if err != nil {
		log.Fatalf("Failed to measure rootfs: %v", err)
	}

	// Create template hash
	tbh := []byte(configHash)
	tbh = append(tbh, rootfsHash...)
	hasher := sha256.New()
	hasher.Write(tbh)
	templateHash := hasher.Sum(nil)

	req := &api.MeasureRequest{
		MeasureEvent: ar.MeasureEvent{
			Sha256:    templateHash,
			EventName: c.CtrName,
			CtrData: &ar.CtrData{
				ConfigSha256: configHash,
				RootfsSha256: rootfsHash,
			},
		},
	}

	resp, err := measureInternal(c, req)
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

func verifyInternal(c *config, req *api.VerificationRequest,
) (*api.VerificationResponse, error) {

	log.Tracef("Connecting via CoAP to %v", c.CmcAddr)

	// Establish connection
	conn, err := udp.Dial(c.CmcAddr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	path := "/Verify"

	// Marshal CoAP payload
	payload, err := c.apiSerializer.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Send CoAP POST request
	resp, err := conn.Post(ctx, path, ar.GetMediaType(c.apiSerializer), bytes.NewReader(payload))
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
	err = c.apiSerializer.Unmarshal(payload, verifyResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response")
	}

	return verifyResp, nil
}

func measureInternal(c *config, req *api.MeasureRequest,
) (*api.MeasureResponse, error) {

	log.Tracef("Connecting via CoAP to %v", c.CmcAddr)

	// Establish connection
	conn, err := udp.Dial(c.CmcAddr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	path := "/Measure"

	// Marshal CoAP payload
	payload, err := c.apiSerializer.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Send CoAP POST request
	resp, err := conn.Post(ctx, path, ar.GetMediaType(c.apiSerializer), bytes.NewReader(payload))
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
	err = c.apiSerializer.Unmarshal(payload, measureResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response")
	}

	return measureResp, nil
}
