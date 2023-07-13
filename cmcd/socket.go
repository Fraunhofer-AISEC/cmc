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

//go:build !nodefaults || socket

package main

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"encoding/hex"
	"encoding/json"

	"github.com/fxamacker/cbor/v2"

	// local modules
	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// Server is the server structure
type SocketServer struct{}

func init() {
	log.Info("Adding unix domain socket server to supported servers")
	servers["socket"] = SocketServer{}
}

func (s SocketServer) Serve(addr string, cmc *cmc.Cmc) error {

	log.Infof("Waiting for requests on %v (%v)", addr, cmc.Network)

	socket, err := net.Listen(cmc.Network, addr)
	if err != nil {
		return fmt.Errorf("failed to listen on unix domain soket: %w", err)
	}
	defer socket.Close()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		os.Remove(addr)
		os.Exit(1)
	}()

	for {
		conn, err := socket.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}

		go handleIncoming(conn, cmc)
	}
}

func handleIncoming(conn net.Conn, cmc *cmc.Cmc) {
	defer conn.Close()

	payload, reqType, err := api.Receive(conn)
	if err != nil {
		api.SendError(conn, "Failed to receive: %v", err)
		return
	}

	// Handle request
	switch reqType {
	case api.TypeAttest:
		attest(conn, payload, cmc)
	case api.TypeVerify:
		verify(conn, payload, cmc)
	case api.TypeTLSCert:
		tlscert(conn, payload, cmc)
	case api.TypeTLSSign:
		tlssign(conn, payload, cmc)
	default:
		api.SendError(conn, "Invalid Type: %v", reqType)
	}
}

func attest(conn net.Conn, payload []byte, cmc *cmc.Cmc) {

	log.Debug("Prover: Received attestation request")

	if len(cmc.Drivers) == 0 {
		api.SendError(conn, "no valid signers configured")
		return
	}

	req := new(api.AttestationRequest)
	err := cbor.Unmarshal(payload, req)
	if err != nil {
		api.SendError(conn, "failed to unmarshal attestation request: %v", err)
		return
	}

	log.Debugf("Prover: Generating Attestation Report with nonce: %v", hex.EncodeToString(req.Nonce))

	report, err := ar.Generate(req.Nonce, cmc.Metadata, cmc.Drivers, cmc.Serializer)
	if err != nil {
		api.SendError(conn, "failed to generate attestation report: %v", err)
		return
	}

	log.Debug("Prover: Signing Attestation Report")
	r, err := ar.Sign(report, cmc.Drivers[0], cmc.Serializer)
	if err != nil {
		api.SendError(conn, "Failed to sign attestation report: %v", err)
		return
	}

	// Serialize payload
	resp := &api.AttestationResponse{
		AttestationReport: r,
	}
	data, err := cbor.Marshal(resp)
	if err != nil {
		api.SendError(conn, "failed to marshal message: %v", err)
		return
	}

	api.Send(conn, data, api.TypeAttest)

	log.Debug("Prover: Finished")
}

func verify(conn net.Conn, payload []byte, cmc *cmc.Cmc) {

	log.Debug("Received Connection Request Type 'Verification Request'")

	req := new(api.VerificationRequest)
	err := cbor.Unmarshal(payload, req)
	if err != nil {
		api.SendError(conn, "Failed to unmarshal verification request: %v", err)
		return
	}

	log.Debug("Verifier: Verifying Attestation Report")
	result := ar.Verify(req.AttestationReport, req.Nonce, req.Ca, req.Policies,
		cmc.PolicyEngineSelect)

	log.Debug("Verifier: Marshaling Attestation Result")
	r, err := json.Marshal(result)
	if err != nil {
		api.SendError(conn, "Verifier: failed to marshal Attestation Result: %v", err)
		return
	}

	// Serialize payload
	resp := api.VerificationResponse{
		VerificationResult: r,
	}
	data, err := cbor.Marshal(&resp)
	if err != nil {
		api.SendError(conn, "failed to marshal message: %v", err)
		return
	}

	api.Send(conn, data, api.TypeVerify)

	log.Debug("Verifier: Finished")
}

func tlssign(conn net.Conn, payload []byte, cmc *cmc.Cmc) {

	log.Debug("Received TLS sign request")

	if len(cmc.Drivers) == 0 {
		api.SendError(conn, "no valid signers configured")
		return
	}

	// Parse the message and return the TLS signing request
	req := new(api.TLSSignRequest)
	err := cbor.Unmarshal(payload, req)
	if err != nil {
		api.SendError(conn, "failed to unmarshal payload: %v", err)
		return
	}

	// Get signing options from request
	opts, err := api.HashToSignerOpts(req.Hashtype, req.PssOpts)
	if err != nil {
		api.SendError(conn, "failed to choose requested hash function: %v", err)
		return
	}

	// Get key handle from (hardware) interface
	tlsKeyPriv, _, err := cmc.Drivers[0].GetSigningKeys()
	if err != nil {
		api.SendError(conn, "failed to get IK: %v", err)
		return
	}

	// Sign
	log.Trace("TLSSign using opts: ", opts)
	signature, err := tlsKeyPriv.(crypto.Signer).Sign(rand.Reader, req.Content, opts)
	if err != nil {
		api.SendError(conn, "failed to sign: %v", err)
		return
	}

	// Create response
	resp := &api.TLSSignResponse{
		SignedContent: signature,
	}
	data, err := cbor.Marshal(&resp)
	if err != nil {
		api.SendError(conn, "failed to marshal message: %v", err)
		return
	}

	api.Send(conn, data, api.TypeTLSSign)

	log.Debug("Performed signing")
}

func tlscert(conn net.Conn, payload []byte, cmc *cmc.Cmc) {

	log.Debug("Received TLS cert request")

	if len(cmc.Drivers) == 0 {
		api.SendError(conn, "no valid signers configured")
		return
	}

	// Parse the message and return the TLS signing request
	req := new(api.TLSSignRequest)
	err := cbor.Unmarshal(payload, req)
	if err != nil {
		api.SendError(conn, "failed to unmarshal payload: %v", err)
		return
	}
	// TODO ID is currently not used
	log.Tracef("Received TLS cert request with ID %v", req.Id)

	// Retrieve certificates
	certChain, err := cmc.Drivers[0].GetCertChain()
	if err != nil {
		api.SendError(conn, "failed to get certchain: %v", err)
		return
	}

	// Create response
	resp := &api.TLSCertResponse{
		Certificate: internal.WriteCertsPem(certChain),
	}
	data, err := cbor.Marshal(&resp)
	if err != nil {
		api.SendError(conn, "failed to marshal message: %v", err)
		return
	}

	api.Send(conn, data, api.TypeTLSCert)

	log.Debug("Obtained TLS cert")
}
