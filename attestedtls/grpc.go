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

	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/grpcapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type GrpcApi struct{}

func init() {
	log.Trace("Adding gRPC API to APIs")
	CmcApis[CmcApi_GRPC] = GrpcApi{}
}

// Creates connection with cmcd at specified address
func getCMCServiceConn(cc CmcConfig) (grpcapi.CMCServiceClient, *grpc.ClientConn, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec*time.Second)
	conn, err := grpc.DialContext(ctx, cc.CmcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		log.Errorf("failed to connect: %v", err)
		cancel()
		return nil, nil, nil
	}

	return grpcapi.NewCMCServiceClient(conn), conn, cancel
}

// Obtains attestation report from CMCd
func (a GrpcApi) obtainAR(cc CmcConfig, chbindings []byte, cached []string) (*api.AttestationResponse, error) {

	// Get backend connection
	log.Tracef("Obtaining AR from local cmcd on %v", cc.CmcAddr)
	cmcClient, cmcconn, cancel := getCMCServiceConn(cc)
	if cmcClient == nil {
		return nil, errors.New("failed to establish connection to obtain AR")
	}
	defer cmcconn.Close()
	defer cancel()
	log.Trace("Contacting backend to obtain AR.")

	req := &grpcapi.AttestationRequest{
		Nonce:  chbindings,
		Cached: cached,
	}

	// Call Attest request
	resp, err := cmcClient.Attest(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain AR: %w", err)
	}

	// Return response
	return api.ConvertAttestationResponse(resp), nil
}

// Checks Attestation report by calling the CMC to Verify and checking its status response
func (a GrpcApi) verifyAR(cc CmcConfig, req *api.VerificationRequest) error {
	// Get backend connection
	log.Tracef("Verifying remote AR via local cmcd on %v", cc.CmcAddr)
	cmcClient, conn, cancel := getCMCServiceConn(cc)
	if cmcClient == nil {
		return errors.New("failed to establish connection to obtain attestation result")
	}
	defer conn.Close()
	defer cancel()
	log.Trace("Contacting backend for AR verification")

	// Perform Verify request
	resp, err := cmcClient.Verify(context.Background(), req.Convert())
	if err != nil {
		return fmt.Errorf("could not obtain verification result: %w", err)
	}

	// Parse VerificationResult
	result := new(ar.VerificationResult)
	err = json.Unmarshal(resp.GetVerificationResult(), result)
	if err != nil {
		return fmt.Errorf("could not parse verification result: %w", err)
	}

	// Return attestation result via callback if specified
	if cc.ResultCb != nil {
		cc.ResultCb(result)
	} else {
		log.Tracef("Will not return attestation result: no callback specified")
	}

	// check results
	if !result.Success {
		return errors.New("attestation report verification failed")
	}
	return nil
}

func (a GrpcApi) fetchSignature(cc CmcConfig, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Get backend connection
	log.Tracef("Fetching signature from local cmcd on %v", cc.CmcAddr)
	cmcClient, conn, cancel := getCMCServiceConn(cc)
	if cmcClient == nil {
		return nil, errors.New("connection failed. No signing performed")
	}
	defer conn.Close()
	defer cancel()
	log.Trace("contacting backend for Sign Operation")

	// Create Sign request
	hash, err := convertHash(opts)
	if err != nil {
		return nil, fmt.Errorf("sign request creation failed: %w", err)
	}
	req := grpcapi.TLSSignRequest{
		Content:  digest,
		Hashtype: hash,
	}

	// parse additional signing options - not implemented fields assume recommend defaults
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		req.PssOpts = &grpcapi.PSSOptions{SaltLength: int32(pssOpts.SaltLength)}
	}

	// Send Sign request
	resp, err := cmcClient.TLSSign(context.Background(), &req)
	if err != nil {
		return nil, fmt.Errorf("sign request failed: %w", err)
	}

	log.Trace("signature: \n ", hex.EncodeToString(resp.GetSignedContent()))
	return resp.GetSignedContent(), nil
}

func (a GrpcApi) fetchCerts(cc CmcConfig) ([][]byte, error) {
	// Get backend connection
	log.Tracef("Fetching certificates from local cmcd on %v", cc.CmcAddr)
	cmcClient, cmcconn, cancel := getCMCServiceConn(cc)
	if cmcClient == nil {
		return nil, errors.New("failed to establish connection to cmcd")
	}
	defer cmcconn.Close()
	defer cancel()

	// Create TLSCert request
	req := grpcapi.TLSCertRequest{}

	// Call TLSCert request
	resp, err := cmcClient.TLSCert(context.Background(), &req)
	if err != nil {
		return nil, fmt.Errorf("failed to request TLS certificate: %w", err)
	}

	if len(resp.GetCertificate()) == 0 {
		return nil, errors.New("grpc call returned 0 certificates")
	}

	return resp.GetCertificate(), nil
}

// Fetches the peer cache from the cmcd
func (a GrpcApi) fetchPeerCache(cc CmcConfig, fingerprint string) ([]string, error) {

	// Get backend connection
	log.Tracef("Fetching peer cache from local cmcd on %v", cc.CmcAddr)
	cmcClient, cmcconn, cancel := getCMCServiceConn(cc)
	if cmcClient == nil {
		return nil, errors.New("failed to establish connection to obtain AR")
	}
	defer cmcconn.Close()
	defer cancel()
	log.Tracef("Contacting backend to fetch peer cache for peer %v", fingerprint)

	req := &grpcapi.PeerCacheRequest{
		Peer: fingerprint,
	}

	// Call peer cache API
	resp, err := cmcClient.PeerCache(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch peer cache: %w", err)
	}

	return resp.Cache, nil
}

// Converts Hash Types from crypto.SignerOpts to the types specified in the CMC interface
func convertHash(opts crypto.SignerOpts) (grpcapi.HashFunction, error) {
	switch opts.HashFunc() {
	case crypto.MD4:
		return grpcapi.HashFunction_MD4, nil
	case crypto.MD5:
		return grpcapi.HashFunction_MD5, nil
	case crypto.SHA1:
		return grpcapi.HashFunction_SHA1, nil
	case crypto.SHA224:
		return grpcapi.HashFunction_SHA224, nil
	case crypto.SHA256:
		return grpcapi.HashFunction_SHA256, nil
	case crypto.SHA384:
		return grpcapi.HashFunction_SHA384, nil
	case crypto.SHA512:
		return grpcapi.HashFunction_SHA512, nil
	case crypto.MD5SHA1:
		return grpcapi.HashFunction_MD5SHA1, nil
	case crypto.RIPEMD160:
		return grpcapi.HashFunction_RIPEMD160, nil
	case crypto.SHA3_224:
		return grpcapi.HashFunction_SHA3_224, nil
	case crypto.SHA3_256:
		return grpcapi.HashFunction_SHA3_256, nil
	case crypto.SHA3_384:
		return grpcapi.HashFunction_SHA3_384, nil
	case crypto.SHA3_512:
		return grpcapi.HashFunction_SHA3_512, nil
	case crypto.SHA512_224:
		return grpcapi.HashFunction_SHA512_224, nil
	case crypto.SHA512_256:
		return grpcapi.HashFunction_SHA512_256, nil
	case crypto.BLAKE2s_256:
		return grpcapi.HashFunction_BLAKE2s_256, nil
	case crypto.BLAKE2b_256:
		return grpcapi.HashFunction_BLAKE2b_256, nil
	case crypto.BLAKE2b_384:
		return grpcapi.HashFunction_BLAKE2b_384, nil
	case crypto.BLAKE2b_512:
		return grpcapi.HashFunction_BLAKE2b_512, nil
	default:
	}
	return grpcapi.HashFunction_SHA512, errors.New("could not determine correct Hash function")
}
