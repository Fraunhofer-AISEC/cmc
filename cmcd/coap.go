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

//go:build !nodefaults || coap

package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"fmt"

	"encoding/hex"
	"encoding/json"

	"github.com/fxamacker/cbor/v2"
	coap "github.com/plgd-dev/go-coap/v3"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/mux"

	// local modules
	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// CoapServer is the CoAP server structure
type CoapServer struct{}

var Cmc *cmc.Cmc

func init() {
	log.Info("Adding CoAP server to supported servers")
	servers["coap"] = CoapServer{}
}

func (s CoapServer) Serve(addr string, c *cmc.Cmc) error {

	Cmc = c

	log.Infof("Starting CMC CoAP Server on %v", addr)
	r := mux.NewRouter()
	r.Use(loggingMiddleware)
	r.Handle("/Attest", mux.HandlerFunc(Attest))
	r.Handle("/Verify", mux.HandlerFunc(Verify))
	r.Handle("/TLSSign", mux.HandlerFunc(TlsSign))
	r.Handle("/TLSCert", mux.HandlerFunc(TlsCert))

	log.Infof("Waiting for requests on %v", addr)

	err := coap.ListenAndServe("udp", addr, r)
	if err != nil {
		return fmt.Errorf("failed to serve: %v", err)
	}

	return nil
}

func SendCoapResponse(w mux.ResponseWriter, r *mux.Message, payload []byte) {
	customResp := w.Conn().AcquireMessage(r.Context())
	defer w.Conn().ReleaseMessage(customResp)
	customResp.SetCode(codes.Content)
	customResp.SetToken(r.Token())
	customResp.SetContentFormat(message.TextPlain)
	customResp.SetBody(bytes.NewReader(payload))
	err := w.Conn().WriteMessage(customResp)
	if err != nil {
		log.Errorf("cannot set response: %v", err)
	}
}

func sendCoapError(w mux.ResponseWriter, r *mux.Message, code codes.Code,
	format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	customResp := w.Conn().AcquireMessage(r.Context())
	defer w.Conn().ReleaseMessage(customResp)
	customResp.SetCode(code)
	customResp.SetToken(r.Token())
	customResp.SetContentFormat(message.TextPlain)
	customResp.SetBody(bytes.NewReader([]byte(msg)))
	err := w.Conn().WriteMessage(customResp)
	if err != nil {
		log.Errorf("cannot set response: %v", err)
	}
}

func Attest(w mux.ResponseWriter, r *mux.Message) {

	log.Debug("Prover: Received CoAP attestation request")

	if len(Cmc.Drivers) == 0 {
		sendCoapError(w, r, codes.InternalServerError,
			"Failed to generate attestation report: No valid drivers specified in config")
		return
	}

	var req api.AttestationRequest
	err := unmarshalCoapPayload(r, &req)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError, "failed to unmarshal CoAP payload: %v",
			err)

		return
	}

	log.Debug("Prover: Generating Attestation Report with nonce: ", hex.EncodeToString(req.Nonce))

	report, err := ar.Generate(req.Nonce, Cmc.Metadata, Cmc.Drivers, Cmc.Serializer)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError,
			"failed to generate attestation report: %v", err)
		return
	}

	log.Debug("Prover: Signing Attestation Report")
	data, err := ar.Sign(report, Cmc.Drivers[0], Cmc.Serializer)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError,
			"Failed to sign attestation report: %v", err)
		return
	}

	// Serialize CoAP payload
	resp := api.AttestationResponse{
		AttestationReport: data,
	}
	payload, err := cbor.Marshal(&resp)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError, "failed to marshal message: %v", err)
		return
	}

	// CoAP response
	SendCoapResponse(w, r, payload)

	log.Debug("Prover: Finished")
}

func Verify(w mux.ResponseWriter, r *mux.Message) {

	log.Debug("Received Connection Request Type 'Verification Request'")

	var req api.VerificationRequest
	err := unmarshalCoapPayload(r, &req)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError,
			"failed to unmarshal CoAP payload: %v", err)
		return
	}

	log.Debug("Verifier: Verifying Attestation Report")
	result := ar.Verify(req.AttestationReport, req.Nonce, req.Ca, req.Policies,
		Cmc.PolicyEngineSelect)

	log.Debug("Verifier: Marshaling Attestation Result")
	data, err := json.Marshal(result)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError,
			"Verifier: failed to marshal Attestation Result: %v", err)
		return
	}

	// Serialize CoAP payload
	resp := api.VerificationResponse{
		VerificationResult: data,
	}
	payload, err := cbor.Marshal(&resp)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError, "failed to marshal message: %v", err)
		return
	}

	// CoAP response
	SendCoapResponse(w, r, payload)

	log.Debug("Verifier: Finished")
}

func TlsSign(w mux.ResponseWriter, r *mux.Message) {

	log.Debug("Received CoAP TLS sign request")

	if len(Cmc.Drivers) == 0 {
		sendCoapError(w, r, codes.InternalServerError,
			"Failed to sign: No valid drivers specified in config")
		return
	}

	// Parse the CoAP message and return the TLS signing request
	var req api.TLSSignRequest
	err := unmarshalCoapPayload(r, &req)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError,
			"failed to unmarshal CoAP payload: %v", err)

		return
	}

	// Get signing options from request
	opts, err := api.HashToSignerOpts(req.Hashtype, req.PssOpts)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError,
			"failed to choose requested hash function: %v", err)
		return
	}

	// Get key handle from (hardware) interface
	tlsKeyPriv, _, err := Cmc.Drivers[0].GetSigningKeys()
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError, "failed to get IK: %v", err)
		return
	}

	// Sign
	log.Trace("TLSSign using opts: ", opts)
	signature, err := tlsKeyPriv.(crypto.Signer).Sign(rand.Reader, req.Content, opts)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError, "failed to sign: %v", err)
		return
	}

	// Create response
	resp := &api.TLSSignResponse{
		SignedContent: signature,
	}
	payload, err := cbor.Marshal(&resp)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError, "failed to marshal message: %v", err)
		return
	}

	// CoAP response
	SendCoapResponse(w, r, payload)

	log.Debug("Performed signing")
}

func TlsCert(w mux.ResponseWriter, r *mux.Message) {

	log.Debug("Received CoAP TLS cert request")

	if len(Cmc.Drivers) == 0 {
		sendCoapError(w, r, codes.InternalServerError,
			"Failed to sign: No valid drivers specified in config")
		return
	}

	// Parse the CoAP message and return the TLS signing request
	var req api.TLSCertRequest
	err := unmarshalCoapPayload(r, &req)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError,
			"failed to unmarshal CoAP payload: %v", err)
		return
	}
	// TODO ID is currently not used
	log.Tracef("Received COAP TLS cert request with ID %v", req.Id)

	// Retrieve certificates
	certChain, err := Cmc.Drivers[0].GetCertChain()
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError, "failed to get cert chain: %v", err)
		return
	}

	// Create response
	resp := &api.TLSCertResponse{
		Certificate: internal.WriteCertsPem(certChain),
	}
	payload, err := cbor.Marshal(&resp)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError, "failed to marshal message: %v", err)
		return
	}

	// CoAP response
	SendCoapResponse(w, r, payload)

	log.Debug("Obtained TLS cert")
}

func loggingMiddleware(next mux.Handler) mux.Handler {
	return mux.HandlerFunc(func(w mux.ResponseWriter, r *mux.Message) {
		log.Printf("ClientAddress %v, %v\n", w.Conn().RemoteAddr(), r.String())
		next.ServeCOAP(w, r)
	})
}

func unmarshalCoapPayload(r *mux.Message, payload interface{}) error {
	// Read CoAP message body
	body, err := r.Message.ReadBody()
	if err != nil {
		return fmt.Errorf("failed to read CoAP message body: %v", err)
	}
	err = cbor.Unmarshal(body, payload)
	if err != nil {
		return fmt.Errorf("failed to unmarshal CoAP message body: %v", err)
	}
	return nil
}
