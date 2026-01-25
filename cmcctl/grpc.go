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

//go:build !nodefaults || grpc

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	// local modules

	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/grpcapi"
	pub "github.com/Fraunhofer-AISEC/cmc/publish"
)

type GrpcApi struct{}

func init() {
	apis["grpc"] = GrpcApi{}
}

func (a GrpcApi) generate(c *config) {

	// Establish connection
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec*time.Second)
	defer cancel()

	log.Infof("Sending grpc request type 'Attest' to %v", c.CmcAddr)

	conn, err := grpc.NewClient(c.CmcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect to cmcd: %v", err)
	}
	defer conn.Close()
	client := grpcapi.NewCMCServiceClient(conn)

	// Generate random nonce
	nonce := make([]byte, 8)
	_, err = rand.Read(nonce)
	if err != nil {
		log.Fatalf("Failed to read random bytes: %v", err)
	}

	request := grpcapi.AttestationRequest{
		Version: api.GetVersion(),
		Nonce:   nonce,
	}
	response, err := client.Attest(ctx, &request)
	if err != nil {
		log.Fatalf("GRPC Attest Call failed: %v", err)
	}

	if response.Version != api.GetVersion() {
		log.Fatalf("API version mismatch. Expected AttestationResponse version %v, got %v",
			api.GetVersion(), response.Version)
	}

	// gRPC only: Marshal response as JSON/CBOR for saving it to the file system
	apiResp := &api.AttestationResponse{
		Report:      response.Report,
		Metadata:    response.Metadata,
		CacheMisses: response.CacheMisses,
	}
	data, err := c.apiSerializer.Marshal(apiResp)
	if err != nil {
		log.Fatalf("Failed to marshal attestation response: %v", err)
	}

	// Save the attestation report for the verifier
	err = pub.SaveReport(c.ReportFile, c.NonceFile, data, nonce)
	if err != nil {
		log.Fatalf("failed to save report: %v", err)
	}

}

func (a GrpcApi) verify(c *config) {

	// Establish connection
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec*time.Second)
	defer cancel()

	log.Infof("Sending grpc request type 'Verify' to %v", c.CmcAddr)

	conn, err := grpc.NewClient(c.CmcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect to cmcd: %v", err)
	}
	defer conn.Close()
	client := grpcapi.NewCMCServiceClient(conn)

	// Read the attestation report and the nonce previously stored
	report, nonce, err := pub.LoadReport(c.ReportFile, c.NonceFile, c.apiSerializer)
	if err != nil {
		log.Fatalf("Failed to load report: %v", err)
	}

	request := grpcapi.VerificationRequest{
		Version:  api.GetVersion(),
		Nonce:    nonce,
		Report:   report.Report,
		Metadata: report.Metadata,
		Policies: c.policies,
	}

	response, err := client.Verify(ctx, &request)
	if err != nil {
		log.Fatalf("GRPC Verify Call failed: %v", err)
	}

	if response.Version != api.GetVersion() {
		log.Fatalf("API version mismatch. Expected VerificationResponse version %v, got %v",
			api.GetVersion(), response.Version)
	}

	// grpc only: the verification result is marshalled as JSON, as we do not have protobuf definitions
	result := new(ar.VerificationResult)
	err = json.Unmarshal(response.GetResult(), result)
	if err != nil {
		log.Fatalf("Failed to unmarshal grpc verification result")
	}

	err = pub.PublishResult(c.Publish, c.publishToken, c.ResultFile, result)
	if err != nil {
		log.Fatalf("Failed to save result: %v", err)
	}

	log.Debug("Finished verify")
}

func (a GrpcApi) updateCerts(c *config) {

	// Establish connection
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec*time.Second)
	defer cancel()

	log.Infof("Sending grpc request type 'UpdateCerts' to %v", c.CmcAddr)

	conn, err := grpc.NewClient(c.CmcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect to cmcd: %v", err)
	}
	defer conn.Close()
	client := grpcapi.NewCMCServiceClient(conn)

	request := grpcapi.UpdateCertsRequest{
		Version: api.GetVersion(),
	}
	response, err := client.UpdateCerts(ctx, &request)
	if err != nil {
		log.Fatalf("GRPC UpdateCerts Call failed: %v", err)
	}

	if response.Version != api.GetVersion() {
		log.Fatalf("API version mismatch. Expected UpdateCertsRequest version %v, got %v",
			api.GetVersion(), response.Version)
	}

	if !response.Success {
		log.Fatalf("UpdateCerts response returned success: %v", response.Success)
	}
}

func (a GrpcApi) updateMetadata(c *config) {

	// Establish connection
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec*time.Second)
	defer cancel()

	log.Infof("Sending grpc request type 'UpdateMetadata' to %v", c.CmcAddr)

	conn, err := grpc.NewClient(c.CmcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect to cmcd: %v", err)
	}
	defer conn.Close()
	client := grpcapi.NewCMCServiceClient(conn)

	request := grpcapi.UpdateMetadataRequest{
		Version: api.GetVersion(),
	}
	response, err := client.UpdateMetadata(ctx, &request)
	if err != nil {
		log.Fatalf("GRPC UpdateMetadata Call failed: %v", err)
	}

	if response.Version != api.GetVersion() {
		log.Fatalf("API version mismatch. Expected UpdateMetadataRequest version %v, got %v",
			api.GetVersion(), response.Version)
	}

	if !response.Success {
		log.Fatalf("UpdateMetadata response returned success: %v", response.Success)
	}
}
