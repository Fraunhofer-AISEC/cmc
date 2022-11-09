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

package grpcapi

// Install github packages with "go get [url]"
import (
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"net"

	"encoding/hex"
	"encoding/json"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	// local modules
	"github.com/Fraunhofer-AISEC/cmc/api"
	ip "github.com/Fraunhofer-AISEC/cmc/attestationpolicies"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	ci "github.com/Fraunhofer-AISEC/cmc/cmcinterface"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// GrpcServer is the gRPC server structure
type GrpcServer struct {
	ci.UnimplementedCMCServiceServer
	config *api.ServerConfig
}

func NewServer(config *api.ServerConfig) ci.CMCServiceServer {
	server := &GrpcServer{
		config: config,
	}

	return server
}

func (server *GrpcServer) Serve(addr string) error {

	// Create TCP server
	log.Infof("Starting CMC gRPC Server on %v", addr)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start server on %v: %v", addr, err)
	}

	// Start gRPC server
	s := grpc.NewServer()
	ci.RegisterCMCServiceServer(s, server)

	log.Infof("Waiting for requests on %v", listener.Addr())
	err = s.Serve(listener)
	if err != nil {
		return fmt.Errorf("failed to serve: %v", err)
	}

	return nil
}

func (s *GrpcServer) Attest(ctx context.Context, in *ci.AttestationRequest) (*ci.AttestationResponse, error) {

	log.Info("Prover: Generating Attestation Report with nonce: ", hex.EncodeToString(in.Nonce))

	report, err := ar.Generate(in.Nonce, s.config.Metadata, s.config.MeasurementInterfaces, s.config.Serializer)
	if err != nil {
		log.Errorf("Failed to generate attestation report: %v", err)
		log.Info("Prover: Finished")
		return &ci.AttestationResponse{
			Status: ci.Status_FAIL,
		}, nil
	}

	if s.config.Signer == nil {
		log.Error("No valid signer specified in config. Cannot sign attestation report")
		log.Info("Prover: Finished")
		return &ci.AttestationResponse{
			Status: ci.Status_FAIL,
		}, nil
	}

	log.Info("Prover: Signing Attestation Report")
	var status ci.Status
	ok, data := ar.Sign(report, s.config.Signer, s.config.Serializer)
	if !ok {
		log.Error("Prover: failed to sign Attestion Report ")
		status = ci.Status_FAIL
	} else {
		status = ci.Status_OK
	}

	log.Info("Prover: Finished")

	response := &ci.AttestationResponse{
		Status:            status,
		AttestationReport: data,
	}

	return response, nil
}

func (s *GrpcServer) Verify(ctx context.Context, in *ci.VerificationRequest) (*ci.VerificationResponse, error) {

	var status ci.Status

	log.Info("Received Connection Request Type 'Verification Request'")

	// The verifying party can optionally specify custom policies that should be verified
	// If present, create a policy validator to be handed over to Verify()
	var policies []ar.Policies
	if in.Policies != nil {
		log.Trace("Policies specified. Creating policy validator for remote attestation")
		policies = append(policies, ip.NewPolicyValidator(in.Policies))
	} else {
		log.Trace("No policies specified. Performing default remote attestation")
	}

	log.Info("Verifier: Verifying Attestation Report")
	result := ar.Verify(string(in.AttestationReport), in.Nonce, in.Ca, policies, s.config.Serializer)

	log.Info("Verifier: Marshaling Attestation Result")
	data, err := json.Marshal(result)
	if err != nil {
		log.Errorf("Verifier: failed to marshal Attestation Result: %v", err)
		status = ci.Status_FAIL
	} else {
		status = ci.Status_OK
	}

	response := &ci.VerificationResponse{
		Status:             status,
		VerificationResult: data,
	}

	log.Info("Verifier: Finished")

	return response, nil
}

func (s *GrpcServer) TLSSign(ctx context.Context, in *ci.TLSSignRequest) (*ci.TLSSignResponse, error) {
	var err error
	var sr *ci.TLSSignResponse
	var opts crypto.SignerOpts
	var signature []byte
	var tlsKeyPriv crypto.PrivateKey

	// get sign opts
	opts, err = internal.ConvertHash(in.GetHashtype(), in.GetPssOpts())
	if err != nil {
		log.Error("[Prover] failed to choose requested hash function.", err.Error())
		return &ci.TLSSignResponse{Status: ci.Status_FAIL}, errors.New("prover: failed to find appropriate hash function")
	}
	// get key
	tlsKeyPriv, _, err = s.config.Signer.GetSigningKeys()
	if err != nil {
		log.Error("[Prover] failed to get TLS key. ", err.Error())
		return &ci.TLSSignResponse{Status: ci.Status_FAIL}, errors.New("prover: failed to get TLS key")
	}
	// Sign
	// Convert crypto.PrivateKey to crypto.Signer
	log.Trace("[Prover] TLSSign using opts: ", opts)
	signature, err = tlsKeyPriv.(crypto.Signer).Sign(rand.Reader, in.GetContent(), opts)
	if err != nil {
		log.Error("[Prover] ", err.Error())
		return &ci.TLSSignResponse{Status: ci.Status_FAIL}, errors.New("prover: failed to perform Signing operation")
	}
	// Create response
	sr = &ci.TLSSignResponse{
		Status:        ci.Status_OK,
		SignedContent: signature,
	}
	// Return response
	log.Info("Prover: Performed Sign operation.")
	return sr, nil
}

// Loads public key for tls certificate
func (s *GrpcServer) TLSCert(ctx context.Context, in *ci.TLSCertRequest) (*ci.TLSCertResponse, error) {
	var resp *ci.TLSCertResponse = &ci.TLSCertResponse{}

	// provide TLS certificate chain
	certChain := s.config.Signer.GetCertChain()
	resp.Certificate = make([][]byte, 0)
	resp.Certificate = append(resp.Certificate, certChain.Leaf)
	resp.Certificate = append(resp.Certificate, certChain.Intermediates...)
	resp.Status = ci.Status_OK
	log.Info("Prover: Obtained TLS Cert.")
	return resp, nil
}
