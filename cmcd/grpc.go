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
	"errors"
	"fmt"
	"net"

	"encoding/json"

	"google.golang.org/grpc"

	// local modules

	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/grpcapi"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/keymgr"
	m "github.com/Fraunhofer-AISEC/cmc/measure"
	"github.com/Fraunhofer-AISEC/cmc/prover"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	oci "github.com/opencontainers/runtime-spec/specs-go"
)

type GrpcServerWrapper struct{}

// GrpcServer is the gRPC server structure
type GrpcServer struct {
	grpcapi.UnimplementedCMCServiceServer
	cmc        *cmc.Cmc
	serializer ar.Serializer
}

func init() {
	servers["grpc"] = GrpcServerWrapper{}
}

func (wrapper GrpcServerWrapper) Serve(addr string, cmc *cmc.Cmc) error {

	// Currently, we do not yet support protobuf-serialized attestation reports
	// Therefore, simply user CBOR, as it is binary as well
	serializer, err := ar.NewCborSerializer()
	if err != nil {
		return fmt.Errorf("failed to init cbor serializer: %w", err)
	}

	server := &GrpcServer{
		cmc:        cmc,
		serializer: serializer,
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

	log.Infof("Waiting for grpc requests on %v", listener.Addr())
	err = s.Serve(listener)
	if err != nil {
		return fmt.Errorf("failed to serve: %v", err)
	}

	return nil
}

func (s *GrpcServer) Attest(ctx context.Context, req *grpcapi.AttestationRequest) (*grpcapi.AttestationResponse, error) {

	log.Info("Received grpc request type 'Attest'")

	if len(s.cmc.Drivers) == 0 {
		return nil, errors.New("attest: no drivers configured")
	}

	if err := grpcapi.CheckVersion(req.Version); err != nil {
		return nil, fmt.Errorf("version check failed: %w", err)
	}

	report, err := prover.Generate(req.Nonce, req.Cached, s.cmc.GetMetadata(), s.cmc.Drivers,
		s.serializer, s.cmc.HashAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation report: %w", err)
	}

	resp := &grpcapi.AttestationResponse{
		Version: grpcapi.GetVersion(),
		Report:  report,
	}

	log.Info("Served grpc request type 'Attest'")

	return resp, nil
}

func (s *GrpcServer) Verify(ctx context.Context, req *grpcapi.VerificationRequest) (*grpcapi.VerificationResponse, error) {

	log.Info("Received grpc request type 'Verify'")

	if err := grpcapi.CheckVersion(req.Version); err != nil {
		return nil, fmt.Errorf("version check failed: %w", err)
	}

	result := verifier.Verify(req.Report, req.Nonce, req.Policies, s.cmc.PolicyEngineSelect,
		s.cmc.PolicyOverwrite, s.cmc.RootCas, s.cmc.PeerCache, req.Peer)

	// grpc only: marshal attestation result in JSON as we do not have protobuf
	// definitions
	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal the attestation result")
	}

	response := &grpcapi.VerificationResponse{
		Version: grpcapi.GetVersion(),
		Result:  data,
	}

	log.Info("Served grpc request type 'Verify'")

	return response, nil
}

func (s *GrpcServer) Measure(ctx context.Context, req *grpcapi.MeasureRequest) (*grpcapi.MeasureResponse, error) {

	var success bool

	log.Info("Received grpc request type 'Measure'")

	if err := grpcapi.CheckVersion(req.Version); err != nil {
		return nil, fmt.Errorf("version check failed: %w", err)
	}

	// oci spec in protobuf is marshaled as bytes
	spec := new(oci.Spec)
	ser, err := ar.DetectSerialization(req.MeasureEvent.CtrData.OciSpec)
	if err != nil {
		log.Warnf("failed to detect oci spec serialization: %v", err)
	} else {
		err = ser.Unmarshal(req.MeasureEvent.CtrData.OciSpec, spec)
		if err != nil {
			log.Warnf("failed to unmarshal grpc oci spec: %v", err)
		}
	}

	err = m.Measure(toComponent(req.MeasureEvent, spec), s.serializer,
		s.cmc.CtrLog, s.cmc.CtrDriver)
	if err != nil {
		log.Errorf("Failed to record measurement: %v", err)
		success = false
	} else {
		success = true
	}

	response := &grpcapi.MeasureResponse{
		Version: grpcapi.GetVersion(),
		Success: success,
	}

	log.Info("Served grpc request type 'Measure'")

	return response, nil
}

func (s *GrpcServer) TLSCreate(ctx context.Context, req *grpcapi.TLSCreateRequest) (*grpcapi.TLSCreateResponse, error) {

	log.Info("Received grpc request type 'TLSCreate'")

	log.Tracef("Enrolling new key type %v, alg %v", req.KeyConfig.Type, req.KeyConfig.Alg)

	keyId, err := s.cmc.KeyMgr.EnrollKey(&keymgr.KeyEnrollmentParams{
		KeyConfig: api.TLSKeyConfig{
			Type:        req.KeyConfig.Type,
			Alg:         req.KeyConfig.Alg,
			Cn:          req.KeyConfig.Cn,
			DNSNames:    req.KeyConfig.DnsNames,
			IPAddresses: req.KeyConfig.IpAddresses,
		},
		Metadata:   s.cmc.GetMetadata(),
		Drivers:    s.cmc.Drivers,
		Serializer: s.serializer,
		ArHashAlg:  s.cmc.HashAlg,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create key: %v", err)
	}

	sr := &grpcapi.TLSCreateResponse{
		Version: grpcapi.GetVersion(),
		KeyId:   keyId,
	}

	log.Info("Served grpc request type 'TLSCreate'")

	return sr, nil
}

// Signs TLS handshake data via hardware-based keys
func (s *GrpcServer) TLSSign(ctx context.Context, req *grpcapi.TLSSignRequest) (*grpcapi.TLSSignResponse, error) {

	log.Info("Received grpc request type 'TLSSign'")

	if err := grpcapi.CheckVersion(req.Version); err != nil {
		return nil, fmt.Errorf("version check failed: %w", err)
	}

	signature, err := Sign(s.cmc.KeyMgr, req.KeyId, req.HashAlg, req.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Create response
	sr := &grpcapi.TLSSignResponse{
		Version:       grpcapi.GetVersion(),
		SignedContent: signature,
	}

	log.Info("Served grpc request type 'TLSSign'")

	return sr, nil
}

// Loads public key for tls certificate
func (s *GrpcServer) TLSCert(ctx context.Context, req *grpcapi.TLSCertRequest) (*grpcapi.TLSCertResponse, error) {

	log.Info("Received grpc request type 'TLSCert'")

	if err := grpcapi.CheckVersion(req.Version); err != nil {
		return nil, fmt.Errorf("version check failed: %w", err)
	}

	if len(s.cmc.Drivers) == 0 {
		return nil, errors.New("TLS cert: no drivers configured")
	}
	d := s.cmc.Drivers[0]

	// provide TLS certificate chain
	certChain, err := s.cmc.KeyMgr.GetCertChain(req.KeyId)
	if err != nil {
		return nil, fmt.Errorf("failed to get cert chain: %w", err)
	}

	certs := internal.WriteCertsPem(certChain)
	log.Debugf("Obtained %v TLS Cert(s) from %v", len(certs), d.Name())

	resp := &grpcapi.TLSCertResponse{
		Version:     grpcapi.GetVersion(),
		Certificate: certs,
	}
	resp.Certificate = internal.WriteCertsPem(certChain)

	log.Info("Served grpc request type 'TLSCert'")
	return resp, nil
}

// Fetches the peer cache for a specified peer
func (s *GrpcServer) PeerCache(ctx context.Context, req *grpcapi.PeerCacheRequest) (*grpcapi.PeerCacheResponse, error) {

	log.Info("Received grpc request type 'PeerCache'")

	if err := grpcapi.CheckVersion(req.Version); err != nil {
		return nil, fmt.Errorf("version check failed: %w", err)
	}

	log.Debugf("Collecting peer cache for peer %v", req.Peer)
	resp := &grpcapi.PeerCacheResponse{
		Version: grpcapi.GetVersion(),
		Cache:   s.cmc.PeerCache.GetKeys(req.Peer),
	}

	log.Info("Served grpc request type 'PeerCache'")

	return resp, nil
}

func toComponent(c *grpcapi.Component, spec *oci.Spec) *ar.Component {
	return &ar.Component{
		Type:        c.Type,
		Name:        c.Name,
		Index:       int(c.Index),
		Hashes:      toGRPCHashes(c.Hashes),
		Version:     c.Version,
		Optional:    c.Optional,
		Description: c.Description,
		CtrData: &ar.CtrData{
			ConfigSha256: c.CtrData.ConfigSha256,
			RootfsSha256: c.CtrData.RootfsSha256,
			OciSpec:      spec,
		},
	}
}

func toGRPCHashes(hashes []*grpcapi.Hash) []ar.ReferenceHash {
	out := make([]ar.ReferenceHash, 0, len(hashes))
	for _, h := range hashes {
		out = append(out, ar.ReferenceHash{
			Alg:     h.Alg,
			Content: h.Content,
		})
	}
	return out
}
