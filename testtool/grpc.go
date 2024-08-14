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
	"context"
	"crypto/rand"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	// local modules

	"github.com/Fraunhofer-AISEC/cmc/attestedtls"
	api "github.com/Fraunhofer-AISEC/cmc/grpcapi"
	m "github.com/Fraunhofer-AISEC/cmc/measure"
)

type GrpcApi struct{}

func init() {
	apis["grpc"] = GrpcApi{}
}

func (a GrpcApi) generate(c *config) {

	// Establish connection
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec*time.Second)
	defer cancel()

	log.Tracef("Connecting via gRPC to %v", c.CmcAddr)

	conn, err := grpc.DialContext(ctx, c.CmcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
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
	err = os.WriteFile(c.ReportFile, response.GetAttestationReport(), 0644)
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

func (a GrpcApi) verify(c *config) {

	// Establish connection
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec*time.Second)
	defer cancel()

	log.Tracef("Connecting via gRPC to %v", c.CmcAddr)

	conn, err := grpc.DialContext(ctx, c.CmcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		log.Fatalf("Failed to connect to cmcd: %v", err)
	}
	defer conn.Close()
	client := api.NewCMCServiceClient(conn)

	// Read the attestation report, CA and the nonce previously stored
	data, err := os.ReadFile(c.ReportFile)
	if err != nil {
		log.Fatalf("Failed to read file %v: %v", c.ReportFile, err)
	}

	nonce, err := os.ReadFile(c.NonceFile)
	if err != nil {
		log.Fatalf("Failed to read nonce: %v", err)
	}

	request := api.VerificationRequest{
		Nonce:             nonce,
		AttestationReport: data,
		Ca:                c.ca,
		Policies:          c.policies,
	}

	response, err := client.Verify(ctx, &request)
	if err != nil {
		log.Fatalf("GRPC Verify Call failed: %v", err)
	}
	if response.GetStatus() != api.Status_OK {
		log.Warnf("Failed to verify attestation report. Status %v", response.GetStatus())
	}

	err = saveResult(c.ResultFile, c.Publish, response.GetVerificationResult())
	if err != nil {
		log.Fatalf("Failed to save result: %v", err)
	}

	log.Debug("Finished verify")
}

func (a GrpcApi) measure(c *config) {

	// Establish connection
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec*time.Second)
	defer cancel()

	log.Tracef("Connecting via gRPC to %v", c.CmcAddr)

	conn, err := grpc.DialContext(ctx, c.CmcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		log.Fatalf("Failed to connect to cmcd: %v", err)
	}
	defer conn.Close()
	client := api.NewCMCServiceClient(conn)

	ctrConfig, err := os.ReadFile(c.CtrConfig)
	if err != nil {
		log.Fatalf("Failed to read container config: %v", err)
	}

	configHash, _, _, err := m.GetSpecMeasurement("mycontainer", ctrConfig)
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

	response, err := client.Measure(ctx, req)
	if err != nil {
		log.Fatalf("GRPC Measure Call failed: %v", err)
	}
	if response.GetStatus() != api.Status_OK {
		log.Warnf("Failed to record measurement. Status %v", response.GetStatus())
	}

	log.Debug("Finished measure")
}

func (a GrpcApi) dial(c *config) {
	dialInternal(c, attestedtls.CmcApi_GRPC, nil)
}

func (a GrpcApi) listen(c *config) {
	listenInternal(c, attestedtls.CmcApi_GRPC, nil)
}

func (a GrpcApi) request(c *config) {
	requestInternal(c, attestedtls.CmcApi_GRPC, nil)
}

func (a GrpcApi) serve(c *config) {
	serveInternal(c, attestedtls.CmcApi_GRPC, nil)
}

func (a GrpcApi) cacerts(c *config) {
	getCaCertsInternal(c)
}

func (a GrpcApi) iothub(c *config) {
	log.Fatalf("IoT hub not implemented for gRPC")
}
