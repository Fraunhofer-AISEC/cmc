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

package coapapi

import (
	"bytes"
	"fmt"

	"encoding/hex"
	"encoding/json"

	"github.com/fxamacker/cbor/v2"
	coap "github.com/plgd-dev/go-coap/v3"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/mux"
	log "github.com/sirupsen/logrus"

	// local modules
	"github.com/Fraunhofer-AISEC/cmc/api"
	ip "github.com/Fraunhofer-AISEC/cmc/attestationpolicies"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// CoapServer is the CoAP server structure
type CoapServer struct {
}

type AttestationRequest struct {
	Id    string
	Nonce []byte
}

type AttestationResponse struct {
	// Status            Status
	AttestationReport []byte
}

type VerificationRequest struct {
	Nonce             []byte
	AttestationReport []byte
	Ca                []byte
	Policies          []byte
}

type VerificationResponse struct {
	// Status             Status
	VerificationResult []byte
}

type TLSSignRequest struct {
	Id      string
	Content []byte
	// Hashtype HashFunction
	// PssOpts  *PSSOptions
}

type TLSSignResponse struct {
	// Status        Status
	SignedContent []byte
}

type TLSCertRequest struct {
	Id string
}

type TLSCertResponse struct {
	// Status      Status
	Certificate [][]byte
}

var config *api.ServerConfig

func NewServer(c *api.ServerConfig) *CoapServer {
	server := &CoapServer{}
	config = c
	return server
}

func (server *CoapServer) Serve(addr string) error {

	log.Infof("Starting CMC CoAP Server on %v", addr)
	r := mux.NewRouter()
	r.Use(loggingMiddleware)
	r.Handle("/Attest", mux.HandlerFunc(Attest))
	r.Handle("/Verify", mux.HandlerFunc(Verify))
	// TODO
	// r.Handle("/TLSSign", mux.HandlerFunc(TLSSign))
	// r.Handle("/Verify", mux.HandlerFunc(TLSCert))

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

func SendCoapError(w mux.ResponseWriter, r *mux.Message, code codes.Code, text string) {
	customResp := w.Conn().AcquireMessage(r.Context())
	defer w.Conn().ReleaseMessage(customResp)
	customResp.SetCode(code)
	customResp.SetToken(r.Token())
	customResp.SetContentFormat(message.TextPlain)
	customResp.SetBody(bytes.NewReader([]byte(text)))
	err := w.Conn().WriteMessage(customResp)
	if err != nil {
		log.Errorf("cannot set response: %v", err)
	}
}

func Attest(w mux.ResponseWriter, r *mux.Message) {

	log.Info("Prover: Received CoAP attestation request")

	var req AttestationRequest
	err := unmarshalCoapPayload(r, &req)
	if err != nil {
		msg := fmt.Sprintf("failed to unmarshal CoAP payload: %v", err)
		SendCoapError(w, r, codes.InternalServerError, msg)
		log.Warn(msg)
		return
	}

	log.Info("Prover: Generating Attestation Report with nonce: ", hex.EncodeToString(req.Nonce))

	report, err := ar.Generate(req.Nonce, config.Metadata, config.MeasurementInterfaces, config.Serializer)
	if err != nil {
		msg := fmt.Sprintf("failed to generate attestation report: %v", err)
		SendCoapError(w, r, codes.InternalServerError, msg)
		log.Warn(msg)
		return
	}

	if config.Signer == nil {
		msg := "Failed to sign attestation report: No valid signer specified in config"
		log.Warn(msg)
		SendCoapError(w, r, codes.InternalServerError, msg)
		return
	}

	log.Info("Prover: Signing Attestation Report")
	ok, data := ar.Sign(report, config.Signer, config.Serializer)
	if !ok {
		msg := "Failed to sign attestation report"
		log.Warn(msg)
		SendCoapError(w, r, codes.InternalServerError, msg)
		return
	}

	log.Info("Prover: Finished")

	// Serialize CoAP payload
	resp := AttestationResponse{
		AttestationReport: data,
	}
	payload, err := cbor.Marshal(&resp)
	if err != nil {
		msg := fmt.Sprintf("failed to marshal message: %v", err)
		log.Warn(msg)
		SendCoapError(w, r, codes.InternalServerError, msg)
		return
	}

	// CoAP response
	SendCoapResponse(w, r, payload)

	log.Info("Prover: Finished")
}

func Verify(w mux.ResponseWriter, r *mux.Message) {

	log.Info("Received Connection Request Type 'Verification Request'")

	var req VerificationRequest
	err := unmarshalCoapPayload(r, &req)
	if err != nil {
		msg := fmt.Sprintf("failed to unmarshal CoAP payload: %v", err)
		SendCoapError(w, r, codes.InternalServerError, msg)
		log.Warn(msg)
		return
	}

	// The verifying party can optionally specify custom policies that should be verified
	// If present, create a policy validator to be handed over to Verify()
	var policies []ar.Policies
	if req.Policies != nil {
		log.Trace("Policies specified. Creating policy validator for remote attestation")
		var p ip.Policies
		err := json.Unmarshal(req.Policies, &p)
		if err != nil {
			log.Warnf("Failed to unmarshal data from metadata object %v", err)
		}
		policies = append(policies, ip.NewPolicyValidator(p))
	} else {
		log.Trace("No policies specified. Performing default remote attestation")
	}

	log.Info("Verifier: Verifying Attestation Report")
	result := ar.Verify(string(req.AttestationReport), req.Nonce, req.Ca, policies, config.Serializer)

	log.Info("Verifier: Marshaling Attestation Result")
	data, err := json.Marshal(result)
	if err != nil {
		msg := fmt.Sprintf("Verifier: failed to marshal Attestation Result: %v", err)
		log.Warn(msg)
		SendCoapError(w, r, codes.InternalServerError, msg)
		return
	}

	// Serialize CoAP payload
	resp := VerificationResponse{
		VerificationResult: data,
	}
	payload, err := cbor.Marshal(&resp)
	if err != nil {
		msg := fmt.Sprintf("failed to marshal message: %v", err)
		log.Warn(msg)
		SendCoapError(w, r, codes.InternalServerError, msg)
		return
	}

	// CoAP response
	SendCoapResponse(w, r, payload)

	log.Info("Verifier: Finished")
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
