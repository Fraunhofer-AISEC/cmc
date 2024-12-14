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

	// local modules
	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	c "github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	m "github.com/Fraunhofer-AISEC/cmc/measure"
	"golang.org/x/exp/maps"
)

// Server is the server structure
type SocketServer struct{}

func init() {
	log.Info("Adding socket server to supported servers (TCP, Unix Domain Socket)")
	servers["socket"] = SocketServer{}
}

func (s SocketServer) Serve(addr string, cmc *c.Cmc) error {

	log.Infof("Waiting for requests on %v (%v)", addr, cmc.Network)

	socket, err := net.Listen(cmc.Network, addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
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

func handleIncoming(conn net.Conn, cmc *c.Cmc) {
	defer conn.Close()

	log.Infof("Received request from %v", conn.RemoteAddr().String())

	payload, reqType, err := api.Receive(conn)
	if err != nil {
		log.Errorf("Failed to receive: %v", err)
		return
	}

	s, err := ar.DetectSerialization(payload)
	if err != nil {
		log.Errorf("Failed to detect serialization of request: %v", err)
		return
	}

	// Handle request
	switch reqType {
	case api.TypeAttest:
		attest(conn, payload, cmc, s)
	case api.TypeVerify:
		validate(conn, payload, cmc, s)
	case api.TypeMeasure:
		measure(conn, payload, cmc, s)
	case api.TypeTLSCert:
		tlscert(conn, payload, cmc, s)
	case api.TypeTLSSign:
		tlssign(conn, payload, cmc, s)
	case api.TypePeerCache:
		fetchPeerCache(conn, payload, cmc, s)
	default:
		sendError(conn, s, "Invalid Type: %v", reqType)
	}
}

func attest(conn net.Conn, payload []byte, cmc *c.Cmc, s ar.Serializer) {

	log.Debug("Received socket connection request type 'Attest'")

	if len(cmc.Drivers) == 0 {
		sendError(conn, s, "no valid signers configured")
		return
	}

	if cmc.Metadata == nil {
		log.Warn("Generating AR without any metadata")
	}

	req := new(api.AttestationRequest)
	err := s.Unmarshal(payload, req)
	if err != nil {
		sendError(conn, s, "failed to unmarshal attestation request: %v", err)
		return
	}

	log.Debugf("Prover: Generating Attestation Report with nonce: %v", hex.EncodeToString(req.Nonce))

	resp, err := c.Generate(req, cmc)
	if err != nil {
		sendError(conn, s, "failed to generate attestation report: %v", err)
		return
	}

	// Serialize payload
	data, err := s.Marshal(resp)
	if err != nil {
		sendError(conn, s, "failed to marshal message: %v", err)
		return
	}

	err = api.Send(conn, data, api.TypeAttest)
	if err != nil {
		sendError(conn, s, "failed to send: %v", err)
	}

	log.Debug("Prover: Finished")
}

func validate(conn net.Conn, payload []byte, cmc *c.Cmc, s ar.Serializer) {

	log.Debug("Received socket connection request type 'Verify'")

	req := new(api.VerificationRequest)
	err := s.Unmarshal(payload, req)
	if err != nil {
		sendError(conn, s, "Failed to unmarshal verification request: %v", err)
		return
	}

	log.Debug("verifying attestation report")
	result, err := c.Verify(req, cmc)
	if err != nil {
		sendError(conn, s, "failed to verify: %v", err)
		return
	}

	// Serialize payload
	resp := api.VerificationResponse{
		VerificationResult: result,
	}
	data, err := s.Marshal(&resp)
	if err != nil {
		sendError(conn, s, "failed to marshal message: %v", err)
		return
	}

	err = api.Send(conn, data, api.TypeVerify)
	if err != nil {
		sendError(conn, s, "failed to send: %v", err)
	}

	log.Debug("Verifier: Finished")
}

func measure(conn net.Conn, payload []byte, cmc *c.Cmc, s ar.Serializer) {

	log.Debug("Received Connection Request Type 'Measure Request'")

	req := new(api.MeasureRequest)
	err := s.Unmarshal(payload, req)
	if err != nil {
		sendError(conn, s, "Failed to unmarshal measure request: %v", err)
		return
	}

	log.Debug("Measurer: recording measurement")
	var success bool
	err = m.Measure(req,
		&m.MeasureConfig{
			Serializer: cmc.Serializer,
			Pcr:        cmc.CtrPcr,
			LogFile:    cmc.CtrLog,
			Driver:     cmc.CtrDriver,
		})
	if err != nil {
		log.Errorf("Failed to measure: %v", err)
		success = false
	} else {
		success = true
	}

	// Serialize payload
	resp := api.MeasureResponse{
		Success: success,
	}
	data, err := s.Marshal(&resp)
	if err != nil {
		sendError(conn, s, "failed to marshal message: %v", err)
		return
	}

	err = api.Send(conn, data, api.TypeMeasure)
	if err != nil {
		sendError(conn, s, "failed to send: %v", err)
	}

	log.Debug("Measurer: Finished")
}

func tlssign(conn net.Conn, payload []byte, cmc *c.Cmc, s ar.Serializer) {

	log.Debug("Received TLS sign request")

	if len(cmc.Drivers) == 0 {
		sendError(conn, s, "no valid signers configured")
		return
	}
	d := cmc.Drivers[0]

	// Parse the message and return the TLS signing request
	req := new(api.TLSSignRequest)
	err := s.Unmarshal(payload, req)
	if err != nil {
		sendError(conn, s, "failed to unmarshal payload: %v", err)
		return
	}

	// Get signing options from request
	opts, err := api.HashToSignerOpts(req.Hashtype, req.PssOpts)
	if err != nil {
		sendError(conn, s, "failed to choose requested hash function: %v", err)
		return
	}

	// Get key handle from (hardware) interface
	tlsKeyPriv, _, err := d.GetKeyHandles(ar.IK)
	if err != nil {
		sendError(conn, s, "failed to get IK: %v", err)
		return
	}

	// Sign
	log.Tracef("TLSSign using opts: %v, driver %v", opts, d.Name())
	signature, err := tlsKeyPriv.(crypto.Signer).Sign(rand.Reader, req.Content, opts)
	if err != nil {
		sendError(conn, s, "failed to sign: %v", err)
		return
	}

	// Create response
	resp := &api.TLSSignResponse{
		SignedContent: signature,
	}
	data, err := s.Marshal(&resp)
	if err != nil {
		sendError(conn, s, "failed to marshal message: %v", err)
		return
	}

	err = api.Send(conn, data, api.TypeTLSSign)
	if err != nil {
		sendError(conn, s, "failed to send: %v", err)
	}

	log.Debug("Performed signing")
}

func tlscert(conn net.Conn, payload []byte, cmc *c.Cmc, s ar.Serializer) {

	log.Debug("Received TLS cert request")

	if len(cmc.Drivers) == 0 {
		sendError(conn, s, "no valid signers configured")
		return
	}
	d := cmc.Drivers[0]

	// Parse the message and return the TLS signing request
	req := new(api.TLSSignRequest)
	err := s.Unmarshal(payload, req)
	if err != nil {
		sendError(conn, s, "failed to unmarshal payload: %v", err)
		return
	}

	log.Tracef("Received TLS cert request")

	// Retrieve certificates
	certChain, err := d.GetCertChain(ar.IK)
	if err != nil {
		sendError(conn, s, "failed to get certchain: %v", err)
		return
	}

	// Create response
	resp := &api.TLSCertResponse{
		Certificate: internal.WriteCertsPem(certChain),
	}
	data, err := s.Marshal(&resp)
	if err != nil {
		sendError(conn, s, "failed to marshal message: %v", err)
		return
	}

	err = api.Send(conn, data, api.TypeTLSCert)
	if err != nil {
		sendError(conn, s, "failed to send: %v", err)
	}

	log.Debugf("Obtained TLS cert from %v", d.Name())
}

func fetchPeerCache(conn net.Conn, payload []byte, cmc *c.Cmc, s ar.Serializer) {

	log.Debug("Received Connection Request Type 'Peer Cache'")

	req := new(api.PeerCacheRequest)
	err := s.Unmarshal(payload, req)
	if err != nil {
		sendError(conn, s, "Failed to unmarshal peer cache request: %v", err)
		return
	}

	log.Debug("Collecting peer cache")
	resp := api.PeerCacheResponse{}
	c, ok := cmc.CachedPeerMetadata[req.Peer]
	if ok {
		resp.Cache = maps.Keys(c)
	}

	log.Tracef("Collected peer cache with %v elements", len(cmc.CachedPeerMetadata[req.Peer]))

	data, err := s.Marshal(&resp)
	if err != nil {
		sendError(conn, s, "failed to marshal message: %v", err)
		return
	}

	err = api.Send(conn, data, api.TypePeerCache)
	if err != nil {
		sendError(conn, s, "failed to send: %v", err)
	}

	log.Debug("Peer cache: Finished")
}

func sendError(conn net.Conn, s ar.Serializer, format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	log.Warn(msg)
	resp := &api.SocketError{
		Msg: msg,
	}
	payload, err := s.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal error response: %v", err)
	}

	return api.Send(conn, payload, api.TypeError)
}
