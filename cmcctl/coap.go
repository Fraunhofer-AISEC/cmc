// Copyright (c) 2021 - 2024 Fraunhofer AISEC
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

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/udp"

	// local modules

	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/attestedtls"
	m "github.com/Fraunhofer-AISEC/cmc/measure"
	pub "github.com/Fraunhofer-AISEC/cmc/publish"
)

type CoapApi struct{}

func init() {
	apis["coap"] = CoapApi{}
}

func (a CoapApi) generate(c *config) {

	log.Infof("Sending coap request type 'Attest' to %v", c.CmcAddr)

	// Establish connection
	conn, err := udp.Dial(c.CmcAddr)
	if err != nil {
		log.Fatalf("Error dialing: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Generate random nonce
	nonce := make([]byte, 8)
	_, err = rand.Read(nonce)
	if err != nil {
		log.Fatalf("Failed to read random bytes: %v", err)
	}

	// Generate attestation request
	req := &api.AttestationRequest{
		Version: api.GetVersion(),
		Nonce:   nonce,
	}

	// Marshal CoAP payload
	payload, err := c.apiSerializer.Marshal(req)
	if err != nil {
		log.Fatalf("failed to marshal payload: %v", err)
	}

	// Send CoAP POST request
	resp, err := conn.Post(ctx, api.EndpointAttest, ar.GetMediaType(c.apiSerializer), bytes.NewReader(payload))
	if err != nil {
		log.Fatalf("failed to send request: %v", err)
	}

	// Read CoAP reply body
	payload, err = resp.ReadBody()
	if err != nil {
		log.Fatalf("failed to read body: %v", err)
	}

	// Read CoAP code
	if resp.Code() != codes.Content {
		log.Fatalf("Server returned coap error message. Code %v, message %v",
			resp.Code().String(), string(payload))
	}
	log.Debugf("Received coap response code %v", resp.Code().String())

	// Save the attestation report for the verifier
	err = pub.SaveReport(c.ReportFile, c.NonceFile, payload, nonce)
	if err != nil {
		log.Fatalf("failed to save report: %v", err)
	}

}

func (a CoapApi) verify(c *config) {

	log.Infof("Sending coap request type 'Verify' to %v", c.CmcAddr)

	// Read the attestation report and the nonce previously stored
	report, nonce, err := pub.LoadReport(c.ReportFile, c.NonceFile, c.apiSerializer)
	if err != nil {
		log.Fatalf("Failed to load report: %v", err)
	}

	req := &api.VerificationRequest{
		Version:  api.GetVersion(),
		Nonce:    nonce,
		Report:   report.Report,
		Metadata: report.Metadata,
		Policies: c.policies,
	}

	resp, err := verifyInternal(c, req)
	if err != nil {
		log.Fatalf("Failed to verify: %v", err)
	}

	err = resp.CheckVersion()
	if err != nil {
		log.Fatalf("%v", err)
	}

	err = pub.PublishResult(c.Publish, c.publishToken, c.ResultFile, &resp.Result)
	if err != nil {
		log.Fatalf("Failed to save result: %v", err)
	}
}

func (a CoapApi) measure(c *config) {

	log.Infof("Sending coap request type 'Measure' to %v", c.CmcAddr)

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
		Version: api.GetVersion(),
		Event: ar.MeasureEvent{
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
	dial(c, attestedtls.CmcApi_COAP, nil)
}

func (a CoapApi) listen(c *config) {
	listen(c, attestedtls.CmcApi_COAP, nil)
}

func (a CoapApi) request(c *config) {
	request(c, attestedtls.CmcApi_COAP, nil)
}

func (a CoapApi) serve(c *config) {
	serve(c, attestedtls.CmcApi_COAP, nil)
}

func (a CoapApi) updateCerts(c *config) {

	log.Infof("Sending coap request type 'UpdateCerts' to %v", c.CmcAddr)

	// Establish connection
	conn, err := udp.Dial(c.CmcAddr)
	if err != nil {
		log.Fatalf("Error dialing: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Generate attestation request
	req := &api.UpdateCertsRequest{
		Version: api.GetVersion(),
	}

	// Marshal CoAP payload
	payload, err := c.apiSerializer.Marshal(req)
	if err != nil {
		log.Fatalf("failed to marshal payload: %v", err)
	}

	// Send CoAP POST request
	resp, err := conn.Post(ctx, api.EndpointUpdateCerts, ar.GetMediaType(c.apiSerializer), bytes.NewReader(payload))
	if err != nil {
		log.Fatalf("failed to send request: %v", err)
	}

	// Read CoAP reply body
	payload, err = resp.ReadBody()
	if err != nil {
		log.Fatalf("failed to read body: %v", err)
	}

	// Read CoAP code
	if resp.Code() != codes.Content {
		log.Fatalf("Server returned coap error message. Code %v, message %v",
			resp.Code().String(), string(payload))
	}
	log.Debugf("Received coap response code %v", resp.Code().String())

	// Unmarshal response
	updateResp := new(api.UpdateCertsResponse)
	err = c.apiSerializer.Unmarshal(payload, updateResp)
	if err != nil {
		log.Fatalf("Failed to unmarshal verification response: %v", err)
	}

	err = updateResp.CheckVersion()
	if err != nil {
		log.Fatalf("Failed to update certs: %v", err)
	}
	if !updateResp.Success {
		log.Fatalf("UpdateCerts response returned success: %v", updateResp.Success)
	}
}

func (a CoapApi) updateMetadata(c *config) {

	log.Infof("Sending coap request type 'UpdateMetadata' to %v", c.CmcAddr)

	// Establish connection
	conn, err := udp.Dial(c.CmcAddr)
	if err != nil {
		log.Fatalf("Error dialing: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Generate attestation request
	req := &api.UpdateMetadataResponse{
		Version: api.GetVersion(),
	}

	// Marshal CoAP payload
	payload, err := c.apiSerializer.Marshal(req)
	if err != nil {
		log.Fatalf("failed to marshal payload: %v", err)
	}

	// Send CoAP POST request
	resp, err := conn.Post(ctx, api.EndpointUpdateMetadata, ar.GetMediaType(c.apiSerializer), bytes.NewReader(payload))
	if err != nil {
		log.Fatalf("failed to send request: %v", err)
	}

	// Read CoAP reply body
	payload, err = resp.ReadBody()
	if err != nil {
		log.Fatalf("failed to read body: %v", err)
	}

	// Read CoAP code
	if resp.Code() != codes.Content {
		log.Fatalf("Server returned coap error message. Code %v, message %v",
			resp.Code().String(), string(payload))
	}
	log.Debugf("Received coap response code %v", resp.Code().String())

	// Unmarshal response
	updateResp := new(api.UpdateMetadataResponse)
	err = c.apiSerializer.Unmarshal(payload, updateResp)
	if err != nil {
		log.Fatalf("Failed to unmarshal verification response: %v", err)
	}

	err = updateResp.CheckVersion()
	if err != nil {
		log.Fatalf("Failed to update metadata: %v", err)
	}
	if !updateResp.Success {
		log.Fatalf("UpdateMetadata response returned success: %v", updateResp.Success)
	}
}

func verifyInternal(c *config, req *api.VerificationRequest,
) (*api.VerificationResponse, error) {

	// Establish connection
	conn, err := udp.Dial(c.CmcAddr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Marshal CoAP payload
	payload, err := c.apiSerializer.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Send CoAP POST request
	resp, err := conn.Post(ctx, api.EndpointVerify, ar.GetMediaType(c.apiSerializer), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}

	// Read CoAP reply body
	payload, err = resp.ReadBody()
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %v", err)
	}

	// Read CoAP code
	if resp.Code() != codes.Content {
		return nil, fmt.Errorf("server returned coap error message. Code %v, message %v",
			resp.Code().String(), string(payload))
	}
	log.Debugf("Received coap response code %v", resp.Code().String())

	// Unmarshal attestation response
	verifyResp := new(api.VerificationResponse)
	err = c.apiSerializer.Unmarshal(payload, verifyResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal verification response: %w", err)
	}

	err = verifyResp.CheckVersion()
	if err != nil {
		return nil, err
	}

	return verifyResp, nil
}

func measureInternal(c *config, req *api.MeasureRequest,
) (*api.MeasureResponse, error) {

	// Establish connection
	conn, err := udp.Dial(c.CmcAddr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Marshal CoAP payload
	payload, err := c.apiSerializer.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Send CoAP POST request
	resp, err := conn.Post(ctx, api.EndpointVerify, ar.GetMediaType(c.apiSerializer), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}

	// Read CoAP reply body
	payload, err = resp.ReadBody()
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %v", err)
	}

	// Read CoAP code
	if resp.Code() != codes.Content {
		return nil, fmt.Errorf("server returned coap error message. Code %v, message %v",
			resp.Code().String(), string(payload))
	}
	log.Debugf("Received coap response code %v", resp.Code().String())

	// Unmarshal attestation response
	measureResp := new(api.MeasureResponse)
	err = c.apiSerializer.Unmarshal(payload, measureResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response")
	}

	err = measureResp.CheckVersion()
	if err != nil {
		return nil, err
	}

	return measureResp, nil
}
