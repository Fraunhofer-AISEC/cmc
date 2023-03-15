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
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/udp"

	// local modules

	"github.com/Fraunhofer-AISEC/cmc/coapapi"
)

type CoapApi struct{}

func init() {
	apis["coap"] = CoapApi{}
}

func (a CoapApi) generate(c *config) {

	// Establish connection
	conn, err := udp.Dial(c.Addr)
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
	req := &coapapi.AttestationRequest{
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
	var attestationResp coapapi.AttestationResponse
	err = cbor.Unmarshal(payload, &attestationResp)
	if err != nil {
		log.Fatalf("failed to unmarshal response")
	}

	// Save the attestation report for the verifier
	err = os.WriteFile(c.ReportFile, attestationResp.AttestationReport, 0644)
	if err != nil {
		log.Fatalf("Failed to save attestation report as %v: %v", c.ReportFile, err)
	}
	fmt.Println("Wrote attestation report: ", c.ReportFile)

	// Save the nonce for the verifier
	os.WriteFile(c.NonceFile, nonce, 0644)
	if err != nil {
		log.Fatalf("Failed to save nonce as %v: %v", c.NonceFile, err)
	}
	fmt.Println("Wrote nonce: ", c.NonceFile)

}

func (a CoapApi) verify(c *config) {

	// Establish connection
	conn, err := udp.Dial(c.Addr)
	if err != nil {
		log.Fatalf("Error dialing: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	path := "/Verify"

	// Read the attestation report, CA and the nonce previously stored
	data, err := os.ReadFile(c.ReportFile)
	if err != nil {
		log.Fatalf("Failed to read file %v: %v", c.ReportFile, err)
	}

	nonce, err := os.ReadFile(c.NonceFile)
	if err != nil {
		log.Fatalf("Failed to read nonce: %v", err)
	}

	req := &coapapi.VerificationRequest{
		Nonce:             nonce,
		AttestationReport: data,
		Ca:                c.ca,
		Policies:          c.policies,
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
	var verifyResp coapapi.VerificationResponse
	err = cbor.Unmarshal(payload, &verifyResp)
	if err != nil {
		log.Fatalf("failed to unmarshal response")
	}

	var out bytes.Buffer
	json.Indent(&out, verifyResp.VerificationResult, "", "    ")

	// Save the Attestation Result
	os.WriteFile(c.ResultFile, out.Bytes(), 0644)
	fmt.Println("Wrote file ", c.ResultFile)
}
