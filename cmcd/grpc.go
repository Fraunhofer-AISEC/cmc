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

	"google.golang.org/grpc"

	// local modules

	api "github.com/Fraunhofer-AISEC/cmc/api"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/grpcapi"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	m "github.com/Fraunhofer-AISEC/cmc/measure"
)

type GrpcServerWrapper struct{}

// GrpcServer is the gRPC server structure
type GrpcServer struct {
	grpcapi.UnimplementedCMCServiceServer
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
	grpcapi.RegisterCMCServiceServer(s, server)

	log.Infof("Waiting for requests on %v", listener.Addr())
	err = s.Serve(listener)
	if err != nil {
		return fmt.Errorf("failed to serve: %v", err)
	}

	return nil
}

func (s *GrpcServer) Attest(ctx context.Context, req *grpcapi.AttestationRequest) (*grpcapi.AttestationResponse, error) {

	log.Debug("Prover: Received gRPC attestation request")

	if len(s.cmc.Drivers) == 0 {
		return &grpcapi.AttestationResponse{}, errors.New("no valid signers configured")
	}

	if s.cmc.Metadata == nil {
		return &grpcapi.AttestationResponse{}, errors.New("metadata not specified. Can work only as verifier")
	}

	log.Info("Prover: Generating Attestation Report with nonce: ", hex.EncodeToString(req.Nonce))

	report, misses, err := cmc.Generate(convertAttestationRequest(req), Cmc)
	if err != nil {
		return &grpcapi.AttestationResponse{}, fmt.Errorf("failed to generate attestation report: %w", err)
	}

	response := &grpcapi.AttestationResponse{
		AttestationReport: report,
		CacheMisses:       misses,
	}

	log.Info("Prover: Finished")

	return response, nil
}

func (s *GrpcServer) Verify(ctx context.Context, req *grpcapi.VerificationRequest) (*grpcapi.VerificationResponse, error) {

	log.Info("Received Cconnection request type 'Verification Request'")

	log.Debug("Verifier: verifying attestation report")
	result, err := cmc.Verify(convertVerificationRequest(req), s.cmc)
	if err != nil {
		log.Errorf("verifier: failed to verify: %v", err)
	}

	response := &grpcapi.VerificationResponse{
		VerificationResult: result,
	}

	log.Info("Verifier: finished")

	return response, nil
}

func (s *GrpcServer) Measure(ctx context.Context, req *grpcapi.MeasureRequest) (*grpcapi.MeasureResponse, error) {

	var success bool

	log.Info("Received Connection Request Type 'Measure Request'")

	log.Info("Measurer: Recording measurement")
	err := m.Measure(convertMeasureRequest(req),
		&m.MeasureConfig{
			Serializer: s.cmc.Serializer,
			Pcr:        s.cmc.CtrPcr,
			LogFile:    s.cmc.CtrLog,
			Driver:     s.cmc.CtrDriver,
		})
	if err != nil {
		log.Errorf("Failed to record measurement: %v", err)
		success = false
	} else {
		success = true
	}

	response := &grpcapi.MeasureResponse{
		Success: success,
	}

	log.Info("Measure: Finished")

	return response, nil
}

func (s *GrpcServer) TLSSign(ctx context.Context, in *grpcapi.TLSSignRequest) (*grpcapi.TLSSignResponse, error) {
	var err error
	var sr *grpcapi.TLSSignResponse
	var opts crypto.SignerOpts
	var signature []byte
	var tlsKeyPriv crypto.PrivateKey

	if len(s.cmc.Drivers) == 0 {
		return &grpcapi.TLSSignResponse{}, errors.New("no valid signers configured")
	}

	// get sign opts
	opts, err = convertHash(in.GetHashtype(), in.GetPssOpts())
	if err != nil {
		return &grpcapi.TLSSignResponse{}, fmt.Errorf("failed to find appropriate hash function: %w", err)
	}
	// get key
	tlsKeyPriv, _, err = s.cmc.Drivers[0].GetSigningKeys()
	if err != nil {
		return &grpcapi.TLSSignResponse{},
			fmt.Errorf("failed to get IK: %w", err)
	}
	// Sign
	// Convert crypto.PrivateKey to crypto.Signer
	log.Trace("TLSSign using opts: ", opts)
	signature, err = tlsKeyPriv.(crypto.Signer).Sign(rand.Reader, in.GetContent(), opts)
	if err != nil {
		return &grpcapi.TLSSignResponse{},
			fmt.Errorf("failed to perform Signing operation: %w", err)
	}
	// Create response
	sr = &grpcapi.TLSSignResponse{
		SignedContent: signature,
	}
	// Return response
	log.Info("Prover: Performed Sign operation.")
	return sr, nil
}

// Loads public key for tls certificate
func (s *GrpcServer) TLSCert(ctx context.Context, in *grpcapi.TLSCertRequest) (*grpcapi.TLSCertResponse, error) {
	var resp *grpcapi.TLSCertResponse = &grpcapi.TLSCertResponse{}

	if len(s.cmc.Drivers) == 0 {
		return &grpcapi.TLSCertResponse{}, errors.New("no valid signers configured")
	}

	// provide TLS certificate chain
	certChain, err := s.cmc.Drivers[0].GetCertChain()
	if err != nil {
		return &grpcapi.TLSCertResponse{},
			fmt.Errorf("failed to get cert chain: %w", err)
	}
	resp.Certificate = internal.WriteCertsPem(certChain)
	log.Infof("Prover: Sending back %v TLS Cert(s)", len(resp.Certificate))
	return resp, nil
}

// Converts Protobuf hashtype to crypto.SignerOpts
func convertHash(hashtype grpcapi.HashFunction, pssOpts *grpcapi.PSSOptions) (crypto.SignerOpts, error) {
	var hash crypto.Hash
	var len int
	switch hashtype {
	case grpcapi.HashFunction_SHA256:
		hash = crypto.SHA256
		len = 32
	case grpcapi.HashFunction_SHA384:
		hash = crypto.SHA384
		len = 48
	case grpcapi.HashFunction_SHA512:
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

func convertAttestationRequest(req *grpcapi.AttestationRequest) *api.AttestationRequest {
	return &api.AttestationRequest{
		Id:     req.Id,
		Nonce:  req.Nonce,
		Cached: req.Cached,
	}
}

func convertVerificationRequest(req *grpcapi.VerificationRequest) *api.VerificationRequest {
	return &api.VerificationRequest{
		Nonce:             req.Nonce,
		AttestationReport: req.AttestationReport,
		Ca:                req.Ca,
		Peer:              req.Peer,
		CacheMisses:       req.CacheMisses,
		Policies:          req.Policies,
	}
}

func convertMeasureRequest(req *grpcapi.MeasureRequest) *api.MeasureRequest {
	return &api.MeasureRequest{
		Name:         req.Name,
		ConfigSha256: req.ConfigSha256,
		RootfsSha256: req.RootfsSha256,
		OciSpec:      req.OciSpec,
	}
}
