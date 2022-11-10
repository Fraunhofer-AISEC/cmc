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

package main

// Install github packages with "go get [url]"
import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/udp"
	"github.com/sirupsen/logrus"

	// local modules
	"github.com/Fraunhofer-AISEC/cmc/coapapi"
)

var log = logrus.WithField("service", "coapclient")

// Mode defines the mode the testclient should run
type Mode int

const (
	// Generate an attestation report (Mode)
	Generate = 0
	// Verify an attestatoin report (Mode)
	Verify = 1
)

func generate(addr, reportFile, nonceFile string) {

	// Establish connection
	conn, err := udp.Dial(addr)
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

	// Unmarshal attetation response
	var attestationResp coapapi.AttestationResponse
	err = cbor.Unmarshal(payload, &attestationResp)
	if err != nil {
		log.Fatalf("failed to unmarshal response")
	}

	// Save the attestation report for the verifier
	err = os.WriteFile(reportFile, attestationResp.AttestationReport, 0644)
	if err != nil {
		log.Fatalf("Failed to save attestation report as %v: %v", reportFile, err)
	}
	fmt.Println("Wrote attestation report: ", reportFile)

	// Save the nonce for the verifier
	os.WriteFile(nonceFile, nonce, 0644)
	if err != nil {
		log.Fatalf("Failed to save nonce as %v: %v", nonceFile, err)
	}
	fmt.Println("Wrote nonce: ", nonceFile)

}

func verify(addr, reportFile, resultFile, nonceFile, caFile string, policies []byte) {

	// Establish connection
	conn, err := udp.Dial(addr)
	if err != nil {
		log.Fatalf("Error dialing: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	path := "/Verify"

	// Read the attestation report, CA and the nonce previously stored
	data, err := os.ReadFile(reportFile)
	if err != nil {
		log.Fatalf("Failed to read file %v: %v", reportFile, err)
	}

	ca, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatalf("Failed to read file %v: %v", caFile, err)
	}

	nonce, err := os.ReadFile(nonceFile)
	if err != nil {
		log.Fatalf("Failed to read nonce: %v", err)
	}

	req := &coapapi.VerificationRequest{
		Nonce:             nonce,
		AttestationReport: data,
		Ca:                ca,
		Policies:          policies,
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

	// Unmarshal attetation response
	var verifyResp coapapi.VerificationResponse
	err = cbor.Unmarshal(payload, &verifyResp)
	if err != nil {
		log.Fatalf("failed to unmarshal response")
	}

	var out bytes.Buffer
	json.Indent(&out, verifyResp.VerificationResult, "", "    ")

	// Save the Attestation Result
	os.WriteFile(resultFile, out.Bytes(), 0644)
	fmt.Println("Wrote file ", resultFile)
}

func main() {
	logrus.SetLevel(logrus.TraceLevel)

	parsedMode := flag.String("mode", "generate", "[generate | verify ]")
	addr := flag.String("addr", "127.0.0.1:9955", "TCP address to connect to the CMC daemon gRPC interface")
	reportFile := flag.String("report", "attestation-report", "Output file for the attestation report")
	resultFile := flag.String("result", "attestation-result.json", "Output file for the attestation result")
	nonceFile := flag.String("nonce", "nonce", "Output file for the nonce")
	rootCACertFile := flag.String("ca", "ca.pem", "TLS Certificate of CA / Entity that is RoT of the connector's TLS certificate")
	policiesFile := flag.String("policies", "", "JSON policies file for custom verification")
	flag.Parse()

	var mode Mode
	if strings.EqualFold(*parsedMode, "generate") {
		mode = Generate
	} else if strings.EqualFold(*parsedMode, "verify") {
		mode = Verify
	} else {
		log.Fatal("Wrong mode. Possible [Generate | Verify]")
	}

	// Add optional policies if present
	var policies []byte = nil
	if mode == Verify {
		var err error
		if *policiesFile != "" {
			log.Debug("Policies specified. Adding them to verification request")
			policies, err = os.ReadFile(*policiesFile)
			if err != nil {
				log.Fatalf("Failed to read policies file: %v", err)
			}
		} else {
			log.Debug("No policies specified. Verifying with default parameters")
		}
	}

	if mode == Generate {
		generate(*addr, *reportFile, *nonceFile)
	} else if mode == Verify {
		verify(*addr, *reportFile, *resultFile, *nonceFile, *rootCACertFile, policies)
	} else {
		log.Println("Unknown mode")
	}
}
