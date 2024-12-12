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
	"crypto/sha256"
	"encoding/json"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	// local modules

	"github.com/Fraunhofer-AISEC/cmc/api"
	"github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/grpcapi"
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
	client := grpcapi.NewCMCServiceClient(conn)

	// Generate random nonce
	nonce := make([]byte, 8)
	_, err = rand.Read(nonce)
	if err != nil {
		log.Fatalf("Failed to read random bytes: %v", err)
	}

	request := grpcapi.AttestationRequest{
		Nonce: nonce,
	}
	response, err := client.Attest(ctx, &request)
	if err != nil {
		log.Fatalf("GRPC Attest Call failed: %v", err)
	}

	// gRPC only: Marshal response as JSON for saving it to the file system
	data, err := json.Marshal(api.ConvertAttestationResponse(response))
	if err != nil {
		log.Fatalf("Failed to marshal attestation response: %v", err)
	}

	// Save the attestation report for the verifier
	err = saveReport(c, data, nonce)
	if err != nil {
		log.Fatalf("failed to save report: %v", err)
	}

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
	client := grpcapi.NewCMCServiceClient(conn)

	// Read the attestation report and the nonce previously stored
	report, nonce, err := loadReport(c)
	if err != nil {
		log.Fatalf("Failed to load report: %v", err)
	}

	request := grpcapi.VerificationRequest{
		Nonce:    nonce,
		Report:   report.Report,
		Metadata: report.Metadata,
		Ca:       c.ca,
		Policies: c.policies,
	}

	response, err := client.Verify(ctx, &request)
	if err != nil {
		log.Fatalf("GRPC Verify Call failed: %v", err)
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
	client := grpcapi.NewCMCServiceClient(conn)

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

	// Create template hash
	tbh := []byte(configHash)
	tbh = append(tbh, rootfsHash...)
	hasher := sha256.New()
	hasher.Write(tbh)
	templateHash := hasher.Sum(nil)

	req := &grpcapi.MeasureRequest{
		Sha256:    templateHash,
		EventName: c.CtrName,
		CtrData: &grpcapi.CtrData{
			ConfigSha256: configHash,
			RootfsSha256: rootfsHash,
		},
	}

	response, err := client.Measure(ctx, req)
	if err != nil {
		log.Fatalf("GRPC Measure Call failed: %v", err)
	}
	if !response.Success {
		log.Warn("Failed to record measurement")
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
