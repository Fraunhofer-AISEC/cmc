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
	"io/ioutil"
	"strings"
	"time"

	"google.golang.org/grpc"

	// local modules
	ci "github.com/Fraunhofer-AISEC/cmc/cmcinterface"

	log "github.com/sirupsen/logrus"
)

// Mode defines the mode the testclient should run
type Mode int

const (
	// Generate an attestation report (Mode)
	Generate = 0
	// Verify an attestatoin report (Mode)
	Verify = 1
)

func main() {
	log.SetLevel(log.TraceLevel)

	parsedMode := flag.String("mode", "generate", "[generate | verify]")
	port := flag.String("port", "9955", "TCP Port to connect to the CMC daemon gRPC interface")
	reportFile := flag.String("report", "attestation-report.json", "Output file for the attestation report")
	resultFile := flag.String("result", "attestation-result.json", "Output file for the attestation result")
	nonceFile := flag.String("nonce", "nonce", "Output file for the nonce")
	flag.Parse()

	var mode Mode
	if strings.ToLower(*parsedMode) == strings.ToLower("generate") {
		mode = Generate
	} else if strings.ToLower(*parsedMode) == strings.ToLower("verify") {
		mode = Verify
	} else {
		log.Fatal("Wrong mode. Possible [Generate | Verify | TLSConn]")
	}

	addr := fmt.Sprintf("localhost:%v", *port)
	conn, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("Failed to connect to cmcd: %v", err)
	}
	defer conn.Close()

	client := ci.NewCMCServiceClient(conn)

	timeoutSec := 20
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	if mode == Generate {

		// Generate random nonce
		nonce := make([]byte, 8)
		_, err = rand.Read(nonce)
		if err != nil {
			log.Fatalf("Failed to read random bytes: %v", err)
		}

		request := ci.AttestationRequest{
			Nonce: nonce,
		}
		response, err := client.Attest(ctx, &request)
		if err != nil {
			log.Fatalf("GRPC Attest Call failed: %v", err)
		}
		if response.GetStatus() != ci.Status_OK {
			log.Fatalf("Failed to generate attestation report. Status %v", response.GetStatus())
		}

		// Save the Attestation Report for the verifier
		ioutil.WriteFile(*reportFile, response.GetAttestationReport(), 0644)
		// Save the nonce for the verifier
		ioutil.WriteFile(*nonceFile, nonce, 0644)

		fmt.Println("Wrote file ", *reportFile)

	} else if mode == Verify {
		// Read the attestation report and the nonce previously stored
		data, err := ioutil.ReadFile(*reportFile)
		if err != nil {
			log.Fatalf("Failed to read file %v: %v", *reportFile, err)
		}

		var nonce []byte
		nonce, err = ioutil.ReadFile(*nonceFile)
		if err != nil {
			log.Fatalf("Failed to read nonce: %v", err)
		}

		request := ci.VerificationRequest{
			Nonce:             nonce,
			AttestationReport: data,
		}

		response, err := client.Verify(ctx, &request)
		if err != nil {
			log.Fatalf("GRPC Verify Call failed: %v", err)
		}
		if response.GetStatus() != ci.Status_OK {
			log.Warnf("Failed to verify attestation report. Status %v", response.GetStatus())
		}

		var out bytes.Buffer
		json.Indent(&out, response.GetVerificationResult(), "", "    ")

		// Save the Attestation Result
		ioutil.WriteFile(*resultFile, out.Bytes(), 0644)
		fmt.Println("Wrote file ", *resultFile)
	} else {
		log.Println("Unknown mode")
	}
}
