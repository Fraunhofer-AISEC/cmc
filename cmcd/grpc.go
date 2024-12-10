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

	"golang.org/x/exp/maps"
	"google.golang.org/grpc"

	// local modules

	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
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

	log.Debug("Prover: Received grpc request type 'Attest'")

	if len(s.cmc.Drivers) == 0 {
		return nil, errors.New("no valid signers configured")
	}

	if s.cmc.Metadata == nil {
		return nil, errors.New("metadata not specified. Can work only as verifier")
	}

	log.Debug("Prover: Generating Attestation Report with nonce: ", hex.EncodeToString(req.Nonce))

	resp, err := cmc.Generate(api.ConvertAttestationRequest(req), s.cmc)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation report: %w", err)
	}

	log.Debug("Prover: Finished")

	return resp.Convert(), nil
}

func (s *GrpcServer) Verify(ctx context.Context, req *grpcapi.VerificationRequest) (*grpcapi.VerificationResponse, error) {

	log.Debug("Received grpc request type 'Verify'")

	result, err := cmc.Verify(api.ConvertVerificationRequest(req), s.cmc)
	if err != nil {
		log.Errorf("verifier: failed to verify: %v", err)
	}

	response := &grpcapi.VerificationResponse{
		VerificationResult: result,
	}

	log.Debug("Verifier: finished")

	return response, nil
}

func (s *GrpcServer) Measure(ctx context.Context, req *grpcapi.MeasureRequest) (*grpcapi.MeasureResponse, error) {

	var success bool

	log.Debug("Received grpc request type 'Measure'")

	err := m.Measure(api.ConvertMeasureRequest(req),
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

	log.Debug("Measure: Finished")

	return response, nil
}

// Signs TLS handshake data via hardware-based keys
func (s *GrpcServer) TLSSign(ctx context.Context, req *grpcapi.TLSSignRequest) (*grpcapi.TLSSignResponse, error) {
	var err error
	var sr *grpcapi.TLSSignResponse
	var opts crypto.SignerOpts
	var signature []byte
	var tlsKeyPriv crypto.PrivateKey

	log.Debug("Received grpc request type 'TLSSign'")

	if len(s.cmc.Drivers) == 0 {
		return nil, errors.New("no valid signers configured")
	}
	d := s.cmc.Drivers[0]

	// get sign opts
	opts, err = convertHash(req.GetHashtype(), req.GetPssOpts())
	if err != nil {
		return nil, fmt.Errorf("failed to find appropriate hash function: %w", err)
	}
	// get key
	tlsKeyPriv, _, err = d.GetKeyHandles(ar.IK)
	if err != nil {
		return nil, fmt.Errorf("failed to get IK: %w", err)
	}
	// Sign
	log.Tracef("TLSSign using opts: %v, driver %v", opts, d.Name())
	signature, err = tlsKeyPriv.(crypto.Signer).Sign(rand.Reader, req.GetContent(), opts)
	if err != nil {
		return nil, fmt.Errorf("failed to perform Signing operation: %w", err)
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
func (s *GrpcServer) TLSCert(ctx context.Context, req *grpcapi.TLSCertRequest) (*grpcapi.TLSCertResponse, error) {

	log.Debug("Prover: Received grpc request type 'TLSCert'")

	if len(s.cmc.Drivers) == 0 {
		return nil, errors.New("no valid signers configured")
	}
	d := s.cmc.Drivers[0]

	// provide TLS certificate chain
	certChain, err := d.GetCertChain(ar.IK)
	if err != nil {
		return nil, fmt.Errorf("failed to get cert chain: %w", err)
	}

	resp := &grpcapi.TLSCertResponse{
		Certificate: internal.WriteCertsPem(certChain),
	}
	resp.Certificate = internal.WriteCertsPem(certChain)
	log.Debugf("Prover: Sending back %v TLS Cert(s) from %v", len(resp.Certificate), d.Name())
	return resp, nil
}

// Fetches the peer cache for a specified peer
func (s *GrpcServer) PeerCache(ctx context.Context, req *grpcapi.PeerCacheRequest) (*grpcapi.PeerCacheResponse, error) {

	log.Debug("Prover: Received grpc request type 'PeerCache'")

	log.Trace("Collecting peer cache")
	resp := &grpcapi.PeerCacheResponse{}
	c, ok := s.cmc.CachedPeerMetadata[req.Peer]
	if ok {
		resp.Cache = maps.Keys(c)
	}

	log.Debug("Prover: Finished")

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
