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

package attestedtls

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	api "github.com/Fraunhofer-AISEC/cmc/grpcapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type GrpcApi struct{}

func init() {
	CmcApis["grpc"] = GrpcApi{}
}

// Creates connection with cmcd at specified address
func getCMCServiceConn(cc *CmcConfig) (api.CMCServiceClient, *grpc.ClientConn, error) {
	if cc == nil {
		return nil, nil, fmt.Errorf("internal error: cmc config object is nil")
	}
	conn, err := grpc.NewClient(cc.CmcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect: %v", err)
	}

	return api.NewCMCServiceClient(conn), conn, nil
}

// Obtains attestation report from CMCd
func (a GrpcApi) obtainAR(cc *CmcConfig, chbindings []byte, cached []string) ([]byte, map[string][]byte, []string, error) {

	// Get backend connection
	log.Debugf("Sending attestation request to cmcd on %v", cc.CmcAddr)
	cmcClient, cmcconn, err := getCMCServiceConn(cc)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to establish connection: %w", err)
	}
	defer cmcconn.Close()

	log.Debug("Contacting backend to obtain AR.")

	req := &api.AttestationRequest{
		Version: api.GetVersion(),
		Nonce:   chbindings,
		Cached:  cached,
	}

	// Call Attest request
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec*time.Second)
	defer cancel()
	resp, err := cmcClient.Attest(ctx, req)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to obtain AR: %w", err)
	}

	if resp.Version != api.GetVersion() {
		return nil, nil, nil, fmt.Errorf("API version mismatch. Expected AttestationResponse version '%v', got '%v'", api.GetVersion(), resp.Version)
	}

	// Return response
	return resp.Report, resp.Metadata, resp.CacheMisses, nil
}

// Checks Attestation report by calling the CMC to Verify and checking its status response
func (a GrpcApi) verifyAR(
	cc *CmcConfig,
	report, nonce, policies []byte,
	peer string,
	cacheMisses []string,
	metadata map[string][]byte,
) error {

	// Get backend connection
	log.Debugf("Sending verification request to cmcd on %v", cc.CmcAddr)
	cmcClient, conn, err := getCMCServiceConn(cc)
	if err != nil {
		return fmt.Errorf("failed to establish connection: %w", err)
	}
	defer conn.Close()
	log.Debug("Contacting backend for AR verification")

	req := &api.VerificationRequest{
		Version:     api.GetVersion(),
		Nonce:       nonce,
		Report:      report,
		Metadata:    metadata,
		Peer:        peer,
		CacheMisses: cacheMisses,
		Policies:    policies,
	}

	// Perform Verify request
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec*time.Second)
	defer cancel()
	resp, err := cmcClient.Verify(ctx, req)
	if err != nil {
		return fmt.Errorf("could not obtain verification result: %w", err)
	}

	if resp.Version != api.GetVersion() {
		return fmt.Errorf("API version mismatch. Expected VerificationResponse version '%v', got '%v'", api.GetVersion(), resp.Version)
	}

	// grpc only: the attestation result is marshalled as JSON, as we do not have protobuf definitions
	result := new(ar.VerificationResult)
	err = json.Unmarshal(resp.GetResult(), result)
	if err != nil {
		return fmt.Errorf("could not parse verification result: %w", err)
	}

	// Return attestation result via callback if specified
	if cc.ResultCb != nil {
		cc.ResultCb(result)
	} else {
		log.Tracef("Will not return attestation result: no callback specified")
	}

	// Check results
	switch result.Summary.Status {
	case ar.StatusSuccess:
		log.Debugf("Attestation report verification successful")
	case ar.StatusWarn:
		log.Debugf("Attestation report verification passed with warnings")
	default:
		return errors.New("attestation report verification failed")
	}
	return nil
}

func (a GrpcApi) fetchSignature(cc *CmcConfig, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Get backend connection
	log.Debugf("Sending TLS sign request to cmcd on %v", cc.CmcAddr)
	cmcClient, conn, err := getCMCServiceConn(cc)
	if err != nil {
		return nil, fmt.Errorf("failed to establish connection: %w", err)
	}
	defer conn.Close()
	log.Debug("Contacting backend for sign Operation")

	// Create Sign request
	req := api.TLSSignRequest{
		Version: api.GetVersion(),
		Content: digest,
		HashAlg: opts.HashFunc().String(),
	}

	// parse additional signing options - not implemented fields assume recommend defaults
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		req.PssOpts = &api.PSSOptions{SaltLength: int32(pssOpts.SaltLength)}
	}

	// Send Sign request
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec*time.Second)
	defer cancel()
	resp, err := cmcClient.TLSSign(ctx, &req)
	if err != nil {
		return nil, fmt.Errorf("sign request failed: %w", err)
	}

	if resp.Version != api.GetVersion() {
		return nil, fmt.Errorf("API version mismatch. Expected TLSSignResponse version '%v', got '%v'", api.GetVersion(), resp.Version)
	}

	log.Tracef("Signature: %v", hex.EncodeToString(resp.GetSignedContent()))
	return resp.GetSignedContent(), nil
}

func (a GrpcApi) fetchCerts(cc *CmcConfig) ([][]byte, error) {
	// Get backend connection
	log.Debugf("Sending TLS certificate request to cmcd on %v", cc.CmcAddr)
	cmcClient, cmcconn, err := getCMCServiceConn(cc)
	if err != nil {
		return nil, fmt.Errorf("failed to establish connection: %w", err)
	}
	defer cmcconn.Close()

	// Create TLSCert request
	req := api.TLSCertRequest{
		Version: api.GetVersion(),
	}

	// Call TLSCert request
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec*time.Second)
	defer cancel()
	resp, err := cmcClient.TLSCert(ctx, &req)
	if err != nil {
		return nil, fmt.Errorf("failed to request TLS certificate: %w", err)
	}

	if resp.Version != api.GetVersion() {
		return nil, fmt.Errorf("API version mismatch. Expected TLSCertResponse version '%v', got '%v'", api.GetVersion(), resp.Version)
	}

	if len(resp.GetCertificate()) == 0 {
		return nil, errors.New("grpc call returned 0 certificates")
	}

	return resp.GetCertificate(), nil
}

// Fetches the peer cache from the cmcd
func (a GrpcApi) fetchPeerCache(cc *CmcConfig, fingerprint string) ([]string, error) {

	// Get backend connection
	log.Debugf("Sending peer cache request for peer %v to cmcd on %v", fingerprint, cc.CmcAddr)
	cmcClient, cmcconn, err := getCMCServiceConn(cc)
	if err != nil {
		return nil, fmt.Errorf("failed to establish connection: %w", err)
	}
	defer cmcconn.Close()

	req := &api.PeerCacheRequest{
		Version: api.GetVersion(),
		Peer:    fingerprint,
	}

	// Call peer cache API
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec*time.Second)
	defer cancel()
	resp, err := cmcClient.PeerCache(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch peer cache: %w", err)
	}

	if resp.Version != api.GetVersion() {
		return nil, fmt.Errorf("API version mismatch. Expected PeerCacheResponse version '%v', got '%v'", api.GetVersion(), resp.Version)
	}

	return resp.Cache, nil
}
