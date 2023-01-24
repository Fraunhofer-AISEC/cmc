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

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	api "github.com/Fraunhofer-AISEC/cmc/grpcapi"
)

type GrpcServerWrapper struct{}

// GrpcServer is the gRPC server structure
type GrpcServer struct {
	api.UnimplementedCMCServiceServer
	config *ServerConfig
}

func init() {
	log.Info("Adding gRPC server to supported servers")
	servers["grpc"] = GrpcServerWrapper{}
}

func (wrapper GrpcServerWrapper) Serve(addr string, config *ServerConfig) error {
	server := &GrpcServer{
		config: config,
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

	log.Info("Prover: Generating Attestation Report with nonce: ", hex.EncodeToString(in.Nonce))

	report, err := ar.Generate(in.Nonce, s.config.Metadata, s.config.MeasurementInterfaces, s.config.Serializer)
	if err != nil {
		log.Errorf("Failed to generate attestation report: %v", err)
		log.Info("Prover: Finished")
		return &api.AttestationResponse{
			Status: api.Status_FAIL,
		}, nil
	}

	if s.config.Signer == nil {
		log.Error("No valid signer specified in config. Cannot sign attestation report")
		log.Info("Prover: Finished")
		return &api.AttestationResponse{
			Status: api.Status_FAIL,
		}, nil
	}

	log.Info("Prover: Signing Attestation Report")
	var status api.Status
	ok, data := ar.Sign(report, s.config.Signer, s.config.Serializer)
	if !ok {
		log.Error("Prover: failed to sign Attestion Report ")
		status = api.Status_FAIL
	} else {
		status = api.Status_OK
	}

	log.Info("Prover: Finished")

	response := &api.AttestationResponse{
		Status:            status,
		AttestationReport: data,
	}

	return response, nil
}

func (s *GrpcServer) Verify(ctx context.Context, in *api.VerificationRequest) (*api.VerificationResponse, error) {

	var status api.Status

	log.Info("Received Connection Request Type 'Verification Request'")

	log.Info("Verifier: Verifying Attestation Report")
	result := ar.Verify(string(in.AttestationReport), in.Nonce, in.Ca, in.Policies,
		s.config.PolicyEngineSelect, s.config.Serializer)

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

func (s *GrpcServer) TLSSign(ctx context.Context, in *api.TLSSignRequest) (*api.TLSSignResponse, error) {
	var err error
	var sr *api.TLSSignResponse
	var opts crypto.SignerOpts
	var signature []byte
	var tlsKeyPriv crypto.PrivateKey

	// get sign opts
	opts, err = convertHash(in.GetHashtype(), in.GetPssOpts())
	if err != nil {
		log.Errorf("Failed to choose requested hash function: %v", err)
		return &api.TLSSignResponse{Status: api.Status_FAIL}, errors.New("prover: failed to find appropriate hash function")
	}
	// get key
	tlsKeyPriv, _, err = s.config.Signer.GetSigningKeys()
	if err != nil {
		log.Errorf("Failed to get IK: %v", err)
		return &api.TLSSignResponse{Status: api.Status_FAIL}, errors.New("prover: failed to get IK")
	}
	// Sign
	// Convert crypto.PrivateKey to crypto.Signer
	log.Trace("TLSSign using opts: ", opts)
	signature, err = tlsKeyPriv.(crypto.Signer).Sign(rand.Reader, in.GetContent(), opts)
	if err != nil {
		log.Errorf("Failed to sign: %v", err)
		return &api.TLSSignResponse{Status: api.Status_FAIL}, errors.New("prover: failed to perform Signing operation")
	}
	// Create response
	sr = &api.TLSSignResponse{
		Status:        api.Status_OK,
		SignedContent: signature,
	}
	// Return response
	log.Info("Prover: Performed Sign operation.")
	return sr, nil
}

// Loads public key for tls certificate
func (s *GrpcServer) TLSCert(ctx context.Context, in *api.TLSCertRequest) (*api.TLSCertResponse, error) {
	var resp *api.TLSCertResponse = &api.TLSCertResponse{}

	// provide TLS certificate chain
	certChain := s.config.Signer.GetCertChain()
	resp.Certificate = make([][]byte, 0)
	resp.Certificate = append(resp.Certificate, certChain.Leaf)
	resp.Certificate = append(resp.Certificate, certChain.Intermediates...)
	resp.Status = api.Status_OK
	log.Info("Prover: Obtained TLS Cert.")
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
