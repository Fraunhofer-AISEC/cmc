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

//go:build !nodefaults || grpc

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

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	// local modules

	"github.com/Fraunhofer-AISEC/cmc/attestedtls"
	api "github.com/Fraunhofer-AISEC/cmc/grpcapi"
)

type GrpcApi struct{}

func init() {
	apis["grpc"] = GrpcApi{}
}

func (a GrpcApi) generate(addr, reportFile, nonceFile string) {

	// Establish connection
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		log.Fatalf("Failed to connect to cmcd: %v", err)
	}
	defer conn.Close()
	client := api.NewCMCServiceClient(conn)

	// Generate random nonce
	nonce := make([]byte, 8)
	_, err = rand.Read(nonce)
	if err != nil {
		log.Fatalf("Failed to read random bytes: %v", err)
	}

	request := api.AttestationRequest{
		Nonce: nonce,
	}
	response, err := client.Attest(ctx, &request)
	if err != nil {
		log.Fatalf("GRPC Attest Call failed: %v", err)
	}
	if response.GetStatus() != api.Status_OK {
		log.Fatalf("Failed to generate attestation report. Status %v", response.GetStatus())
	}

	// Save the Attestation Report for the verifier
	err = os.WriteFile(reportFile, response.GetAttestationReport(), 0644)
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

func (a GrpcApi) verify(addr, reportFile, resultFile, nonceFile, caFile string, policies []byte) {

	// Establish connection
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		log.Fatalf("Failed to connect to cmcd: %v", err)
	}
	defer conn.Close()
	client := api.NewCMCServiceClient(conn)

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

	request := api.VerificationRequest{
		Nonce:             nonce,
		AttestationReport: data,
		Ca:                ca,
		Policies:          policies,
	}

	response, err := client.Verify(ctx, &request)
	if err != nil {
		log.Fatalf("GRPC Verify Call failed: %v", err)
	}
	if response.GetStatus() != api.Status_OK {
		log.Warnf("Failed to verify attestation report. Status %v", response.GetStatus())
	}

	var out bytes.Buffer
	json.Indent(&out, response.GetVerificationResult(), "", "    ")

	// Save the Attestation Result
	os.WriteFile(resultFile, out.Bytes(), 0644)
	fmt.Println("Wrote file ", resultFile)
}

func (a GrpcApi) testTLSConn(destAddr, cmcAddr, ca string, mTLS bool, policies []byte) {
	testTLSConnInternal(attestedtls.CmcApi_GRPC, destAddr, cmcAddr, ca, mTLS, policies)
}
