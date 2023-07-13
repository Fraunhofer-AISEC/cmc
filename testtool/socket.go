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

package main

// Install github packages with "go get [url]"
import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/fxamacker/cbor/v2"

	// local modules

	"github.com/Fraunhofer-AISEC/cmc/api"
	"github.com/Fraunhofer-AISEC/cmc/attestedtls"
)

type SocketApi struct{}

func init() {
	apis["socket"] = SocketApi{}
}

func (a SocketApi) generate(c *config) {

	// Establish connection
	conn, err := net.Dial(c.Network, c.CmcAddr)
	if err != nil {
		log.Fatalf("Error dialing: %v", err)
	}

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

	// Marshal payload
	payload, err := cbor.Marshal(req)
	if err != nil {
		log.Fatalf("failed to marshal payload: %v", err)
	}

	// Send request
	err = api.Send(conn, payload, api.TypeAttest)
	if err != nil {
		log.Fatalf("failed to send request: %v", err)
	}

	// Read reply
	payload, _, err = api.Receive(conn)
	if err != nil {
		log.Fatalf("failed to receive: %v", err)
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
	fmt.Println("Wrote attestation report: ", c.ReportFile)

	// Save the nonce for the verifier
	os.WriteFile(c.NonceFile, nonce, 0644)
	if err != nil {
		log.Fatalf("Failed to save nonce as %v: %v", c.NonceFile, err)
	}
	fmt.Println("Wrote nonce: ", c.NonceFile)

}

func (a SocketApi) verify(c *config) {

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

	resp, err := verifySocketRequest(c.Network, c.CmcAddr, req)
	if err != nil {
		log.Fatalf("Failed to verify: %v", err)
	}

	var out bytes.Buffer
	json.Indent(&out, resp.VerificationResult, "", "    ")

	// Save the Attestation Result
	os.WriteFile(c.ResultFile, out.Bytes(), 0644)
	fmt.Println("Wrote file ", c.ResultFile)
}

func (a SocketApi) dial(c *config) {
	dialInternal(c, attestedtls.CmcApi_Socket, nil)
}

func (a SocketApi) listen(c *config) {
	listenInternal(c, attestedtls.CmcApi_Socket, nil)
}

func (a SocketApi) cacerts(c *config) {
	getCaCertsInternal(c)
}

func (a SocketApi) iothub(c *config) {
	log.Fatalf("IoT hub not implemented for sockets API")
}

func verifySocketRequest(network, addr string, req *api.VerificationRequest,
) (*api.VerificationResponse, error) {
	// Establish connection
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %v", err)
	}

	// Marshal payload
	payload, err := cbor.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Send request
	err = api.Send(conn, payload, api.TypeVerify)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}

	// Read reply
	payload, _, err = api.Receive(conn)
	if err != nil {
		log.Fatalf("failed to receive: %v", err)
	}

	// Unmarshal attestation response
	verifyResp := new(api.VerificationResponse)
	err = cbor.Unmarshal(payload, verifyResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response")
	}

	return verifyResp, nil
}
