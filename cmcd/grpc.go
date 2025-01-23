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

	"golang.org/x/exp/maps"
	"google.golang.org/grpc"

	// local modules

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	api "github.com/Fraunhofer-AISEC/cmc/grpcapi"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	m "github.com/Fraunhofer-AISEC/cmc/measure"
	oci "github.com/opencontainers/runtime-spec/specs-go"
)

type GrpcServerWrapper struct{}

// GrpcServer is the gRPC server structure
type GrpcServer struct {
	api.UnimplementedCMCServiceServer
	cmc *cmc.Cmc
}

func init() {
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

	log.Infof("Waiting for grpc requests on %v", listener.Addr())
	err = s.Serve(listener)
	if err != nil {
		return fmt.Errorf("failed to serve: %v", err)
	}

	return nil
}

func (s *GrpcServer) Attest(ctx context.Context, req *api.AttestationRequest) (*api.AttestationResponse, error) {

	log.Info("Received grpc request type 'Attest'")

	if len(s.cmc.Drivers) == 0 {
		return nil, errors.New("attest: no drivers configured")
	}

	if s.cmc.Metadata == nil {
		return nil, errors.New("metadata not specified. Can work only as verifier")
	}

	if req.Version != api.GetVersion() {
		return nil, fmt.Errorf("API version mismatch. Expected AttestationRequest version %v, got %v",
			api.GetVersion(), req.Version)
	}

	log.Debug("Prover: Generating Attestation Report with nonce: ", hex.EncodeToString(req.Nonce))

	report, metadata, cacheMisses, err := cmc.Generate(req.Nonce, req.Cached, s.cmc)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation report: %w", err)
	}

	resp := &api.AttestationResponse{
		Version:     api.GetVersion(),
		Report:      report,
		Metadata:    metadata,
		CacheMisses: cacheMisses,
	}

	log.Info("Served grpc request type 'Attest'")

	return resp, nil
}

func (s *GrpcServer) Verify(ctx context.Context, req *api.VerificationRequest) (*api.VerificationResponse, error) {

	log.Info("Received grpc request type 'Verify'")

	if req.Version != api.GetVersion() {
		return nil, fmt.Errorf("API version mismatch. Expected VerificationRequest version %v, got %v",
			api.GetVersion(), req.Version)
	}

	result, err := cmc.Verify(req.Report, req.Nonce, req.Ca, req.Policies, req.Peer, req.CacheMisses, req.Metadata, s.cmc)
	if err != nil {
		log.Errorf("verifier: failed to verify: %v", err)
	}

	// grpc only: marshal verification result in JSON as we do not have protobuf
	// definitions for the verification result
	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verification result")
	}

	response := &api.VerificationResponse{
		Version:            api.GetVersion(),
		VerificationResult: data,
	}

	log.Info("Served grpc request type 'Verify'")

	return response, nil
}

func (s *GrpcServer) Measure(ctx context.Context, req *api.MeasureRequest) (*api.MeasureResponse, error) {

	var success bool

	log.Info("Received grpc request type 'Measure'")

	if req.Version != api.GetVersion() {
		return nil, fmt.Errorf("API version mismatch. Expected MeasureRequest version %v, got %v",
			api.GetVersion(), req.Version)
	}

	// oci spec in protobuf is marshaled as bytes
	spec := new(oci.Spec)
	ser, err := ar.DetectSerialization(req.CtrData.OciSpec)
	if err != nil {
		log.Warnf("failed to detect oci spec serialization: %v", err)
	} else {
		err = ser.Unmarshal(req.CtrData.OciSpec, spec)
		if err != nil {
			log.Warnf("failed to unmarshal grpc oci spec: %v", err)
		}
	}

	err = m.Measure(
		&ar.MeasureEvent{
			Sha256:    req.Sha256,
			EventName: req.EventName,
			CtrData: &ar.CtrData{
				ConfigSha256: req.CtrData.ConfigSha256,
				RootfsSha256: req.CtrData.RootfsSha256,
				OciSpec:      spec,
			},
		},
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

	response := &api.MeasureResponse{
		Version: api.GetVersion(),
		Success: success,
	}

	log.Info("Served grpc request type 'Measure'")

	return response, nil
}

// Signs TLS handshake data via hardware-based keys
func (s *GrpcServer) TLSSign(ctx context.Context, req *api.TLSSignRequest) (*api.TLSSignResponse, error) {
	var err error
	var sr *api.TLSSignResponse
	var opts crypto.SignerOpts
	var signature []byte
	var tlsKeyPriv crypto.PrivateKey

	log.Info("Received grpc request type 'TLSSign'")

	if req.Version != api.GetVersion() {
		return nil, fmt.Errorf("API version mismatch. Expected TLSSignRequest version %v, got %v",
			api.GetVersion(), req.Version)
	}

	if len(s.cmc.Drivers) == 0 {
		return nil, errors.New("TLS sign: no drivers configured")
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
	log.Debugf("TLSSign using opts: %v, driver %v", opts, d.Name())
	signature, err = tlsKeyPriv.(crypto.Signer).Sign(rand.Reader, req.GetContent(), opts)
	if err != nil {
		return nil, fmt.Errorf("failed to perform Signing operation: %w", err)
	}
	// Create response
	sr = &api.TLSSignResponse{
		Version:       api.GetVersion(),
		SignedContent: signature,
	}

	log.Info("Served grpc request type 'TLSSign'")

	return sr, nil
}

// Loads public key for tls certificate
func (s *GrpcServer) TLSCert(ctx context.Context, req *api.TLSCertRequest) (*api.TLSCertResponse, error) {

	log.Info("Received grpc request type 'TLSCert'")

	if req.Version != api.GetVersion() {
		return nil, fmt.Errorf("API version mismatch. Expected TLSCertRequest version %v, got %v",
			api.GetVersion(), req.Version)
	}

	if len(s.cmc.Drivers) == 0 {
		return nil, errors.New("TLS cert: no drivers configured")
	}
	d := s.cmc.Drivers[0]

	// provide TLS certificate chain
	certChain, err := d.GetCertChain(ar.IK)
	if err != nil {
		return nil, fmt.Errorf("failed to get cert chain: %w", err)
	}

	certs := internal.WriteCertsPem(certChain)
	log.Debugf("Obtained %v TLS Cert(s) from %v", len(certs), d.Name())

	resp := &api.TLSCertResponse{
		Version:     api.GetVersion(),
		Certificate: certs,
	}
	resp.Certificate = internal.WriteCertsPem(certChain)

	log.Info("Served grpc request type 'TLSCert'")
	return resp, nil
}

// Fetches the peer cache for a specified peer
func (s *GrpcServer) PeerCache(ctx context.Context, req *api.PeerCacheRequest) (*api.PeerCacheResponse, error) {

	log.Info("Received grpc request type 'PeerCache'")

	if req.Version != api.GetVersion() {
		return nil, fmt.Errorf("API version mismatch. Expected PeerCacheRequest version %v, got %v",
			api.GetVersion(), req.Version)
	}

	log.Debugf("Collecting peer cache for peer %v", req.Peer)
	resp := &api.PeerCacheResponse{
		Version: api.GetVersion(),
	}
	c, ok := s.cmc.CachedPeerMetadata[req.Peer]
	if ok {
		resp.Cache = maps.Keys(c)
	}

	log.Info("Served grpc request type 'PeerCache'")

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
