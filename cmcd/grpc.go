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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"

	"encoding/hex"
	"encoding/json"

	"google.golang.org/grpc"

	// local modules

	cmcapi "github.com/Fraunhofer-AISEC/cmc/api"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/generate"
	api "github.com/Fraunhofer-AISEC/cmc/grpcapi"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	m "github.com/Fraunhofer-AISEC/cmc/measure"
	"github.com/Fraunhofer-AISEC/cmc/verify"
)

type GrpcServerWrapper struct{}

// GrpcServer is the gRPC server structure
type GrpcServer struct {
	api.UnimplementedCMCServiceServer
	cmc *cmc.Cmc
}

func init() {
	log.Info("Adding gRPC server to supported servers")
	servers["grpc"] = GrpcServerWrapper{}
}

func (wrapper GrpcServerWrapper) Serve(addr string, cmc *cmc.Cmc) error {
	server := &GrpcServer{
		cmc: cmc,
	}

	// Create TCP server
	log.Infof("Starting CMC gRPC Server on %v", addr)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start server on %v: %v", addr, err)
	}

	// Start gRPC server
	s := grpc.NewServer()
	api.RegisterCMCServiceServer(s, server)

	log.Infof("Waiting for requests on %v", listener.Addr())
	err = s.Serve(listener)
	if err != nil {
		return fmt.Errorf("failed to serve: %v", err)
	}

	return nil
}

func (s *GrpcServer) Attest(ctx context.Context, in *api.AttestationRequest) (*api.AttestationResponse, error) {

	log.Debug("Prover: Received gRPC attestation request")

	if len(s.cmc.Drivers) == 0 {
		return &api.AttestationResponse{
			Status: api.Status_FAIL,
		}, errors.New("no valid signers configured")
	}

	if s.cmc.Metadata == nil {
		return &api.AttestationResponse{
			Status: api.Status_FAIL,
		}, errors.New("metadata not specified. Can work only as verifier")
	}

	log.Info("Prover: Generating Attestation Report with nonce: ", hex.EncodeToString(in.Nonce))

	report, err := generate.Generate(in.Nonce, s.cmc.Metadata, s.cmc.Drivers, s.cmc.Serializer)
	if err != nil {
		return &api.AttestationResponse{
			Status: api.Status_FAIL,
		}, fmt.Errorf("failed to generate attestation report: %w", err)
	}

	log.Info("Prover: Signing Attestation Report")
	data, err := generate.Sign(report, s.cmc.Drivers[0], s.cmc.Serializer)
	if err != nil {
		return &api.AttestationResponse{
			Status: api.Status_FAIL,
		}, fmt.Errorf("failed to sign attestion report: %w", err)
	}

	response := &api.AttestationResponse{
		Status:            api.Status_OK,
		AttestationReport: data,
	}

	log.Info("Prover: Finished")

	return response, nil
}

func (s *GrpcServer) Verify(ctx context.Context, in *api.VerificationRequest) (*api.VerificationResponse, error) {

	var status api.Status

	log.Info("Received Connection Request Type 'Verification Request'")

	log.Info("Verifier: Verifying Attestation Report")
	result := verify.Verify(in.AttestationReport, in.Nonce, in.Ca, in.Policies,
		s.cmc.PolicyEngineSelect, s.cmc.IntelStorage)

	log.Info("Verifier: Marshaling Attestation Result")
	data, err := json.Marshal(result)
	if err != nil {
		log.Errorf("Verifier: failed to marshal Attestation Result: %v", err)
		status = api.Status_FAIL
	} else {
		status = api.Status_OK
	}

	response := &api.VerificationResponse{
		Status:             status,
		VerificationResult: data,
	}

	log.Info("Verifier: Finished")

	return response, nil
}

func (s *GrpcServer) Measure(ctx context.Context, in *api.MeasureRequest) (*api.MeasureResponse, error) {

	var status api.Status
	var success bool

	log.Info("Received Connection Request Type 'Measure Request'")

	// TODO better solution? (different but same datatype cmcapi.MeasureRequest and api.MeasureRequest)
	req := &cmcapi.MeasureRequest{
		Name:         in.Name,
		ConfigSha256: in.ConfigSha256,
		RootfsSha256: in.RootfsSha256,
		OciSpec:      in.OciSpec,
	}

	log.Info("Measurer: Recording measurement")
	err := m.Measure(req,
		&m.MeasureConfig{
			Serializer: s.cmc.Serializer,
			Pcr:        s.cmc.CtrPcr,
			LogFile:    s.cmc.CtrLog,
			Driver:     s.cmc.CtrDriver,
		})
	if err != nil {
		log.Errorf("Failed to record measurement: %v", err)
		success = false
		status = api.Status_FAIL
	} else {
		success = true
		status = api.Status_OK
	}

	response := &api.MeasureResponse{
		Status:  status,
		Success: success,
	}

	log.Info("Measure: Finished")

	return response, nil
}

func (s *GrpcServer) TLSSign(ctx context.Context, in *api.TLSSignRequest) (*api.TLSSignResponse, error) {
	var err error
	var sr *api.TLSSignResponse
	var opts crypto.SignerOpts
	var signature []byte
	var tlsKeyPriv crypto.PrivateKey

	if len(s.cmc.Drivers) == 0 {
		return &api.TLSSignResponse{
			Status: api.Status_FAIL,
		}, errors.New("no valid signers configured")
	}

	// get sign opts
	opts, err = convertHash(in.GetHashtype(), in.GetPssOpts())
	if err != nil {
		return &api.TLSSignResponse{Status: api.Status_FAIL},
			fmt.Errorf("failed to find appropriate hash function: %w", err)
	}
	// get key
	tlsKeyPriv, _, err = s.cmc.Drivers[0].GetSigningKeys()
	if err != nil {
		return &api.TLSSignResponse{Status: api.Status_FAIL},
			fmt.Errorf("failed to get IK: %w", err)
	}
	// Sign
	// Convert crypto.PrivateKey to crypto.Signer
	log.Trace("TLSSign using opts: ", opts)
	signature, err = tlsKeyPriv.(crypto.Signer).Sign(rand.Reader, in.GetDigest(), opts)
	if err != nil {
		return &api.TLSSignResponse{Status: api.Status_FAIL},
			fmt.Errorf("failed to perform Signing operation: %w", err)
	}
	// Create response
	sr = &api.TLSSignResponse{
		Status:       api.Status_OK,
		SignedDigest: signature,
	}
	// Return response
	log.Info("Prover: Performed Sign operation.")
	return sr, nil
}

// Loads public key for tls certificate
func (s *GrpcServer) TLSCert(ctx context.Context, in *api.TLSCertRequest) (*api.TLSCertResponse, error) {
	var resp *api.TLSCertResponse = &api.TLSCertResponse{}

	if len(s.cmc.Drivers) == 0 {
		return &api.TLSCertResponse{
			Status: api.Status_FAIL,
		}, errors.New("no valid signers configured")
	}

	// provide TLS certificate chain
	certChain, err := s.cmc.Drivers[0].GetCertChain()
	if err != nil {
		return &api.TLSCertResponse{Status: api.Status_FAIL},
			fmt.Errorf("failed to get cert chain: %w", err)
	}
	resp.Certificate = internal.WriteCertsPem(certChain)
	resp.Status = api.Status_OK
	log.Infof("Prover: Sending back %v TLS Cert(s)", len(resp.Certificate))
	return resp, nil
}

// Converts Protobuf hashtype to crypto.SignerOpts
func convertHash(hashtype api.HashFunction, pssOpts *api.PSSOptions) (crypto.SignerOpts, error) {
	var hash crypto.Hash
	var len int
	switch hashtype {
	case api.HashFunction_SHA256:
		hash = crypto.SHA256
		len = 32
	case api.HashFunction_SHA384:
		hash = crypto.SHA384
		len = 48
	case api.HashFunction_SHA512:
		len = 64
		hash = crypto.SHA512
	default:
		return crypto.SHA512, fmt.Errorf("hash function not implemented: %v", hashtype)
	}
	if pssOpts != nil {
		saltlen := int(pssOpts.SaltLength)
		// go-attestation / go-tpm does not allow -1 as definition for length of hash
		if saltlen < 0 {
			log.Warning("Signature Options: Adapted RSA PSS Salt length to length of hash: ", len)
			saltlen = len
		}
		return &rsa.PSSOptions{SaltLength: saltlen, Hash: hash}, nil
	}
	return hash, nil
}
