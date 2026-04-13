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
	"fmt"

	coap "github.com/plgd-dev/go-coap/v3"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/mux"

	// local modules
	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/keymgr"
	m "github.com/Fraunhofer-AISEC/cmc/measure"
	"github.com/Fraunhofer-AISEC/cmc/prover"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
)

// CoapServer is the CoAP server structure
type CoapServer struct {
	cmc *cmc.Cmc
}

func init() {
	servers["coap"] = CoapServer{}
}

func (s CoapServer) Serve(addr string, c *cmc.Cmc) error {

	s.cmc = c

	log.Infof("Starting CMC CoAP Server on %v", addr)
	r := mux.NewRouter()
	r.Use(loggingMiddleware)
	r.Handle(api.EndpointAttest, mux.HandlerFunc(s.Attest))
	r.Handle(api.EndpointVerify, mux.HandlerFunc(s.Verify))
	r.Handle(api.EndpointTLSCreate, mux.HandlerFunc(s.TlsCreate))
	r.Handle(api.EndpointTLSSign, mux.HandlerFunc(s.TlsSign))
	r.Handle(api.EndpointTLSCert, mux.HandlerFunc(s.TlsCert))
	r.Handle(api.EndpointPeerCache, mux.HandlerFunc(s.PeerCache))
	r.Handle(api.EndpointMeasure, mux.HandlerFunc(s.Measure))

	log.Infof("Waiting for requests on %v", addr)

	err := coap.ListenAndServe("udp", addr, r)
	if err != nil {
		return fmt.Errorf("failed to serve: %v", err)
	}

	return nil
}

func (s CoapServer) Attest(w mux.ResponseWriter, r *mux.Message) {

	log.Infof("Received coap request type 'Attest' from %v", w.Conn().RemoteAddr())

	if len(s.cmc.Drivers) == 0 {
		sendCoapError(w, r, codes.InternalServerError,
			"Failed to generate attestation report: No valid drivers specified in config")
		return
	}

	req := new(api.AttestationRequest)
	ser, err := unmarshal(r, req)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError, "failed to unmarshal CoAP payload: %v",
			err)

		return
	}

	err = req.CheckVersion()
	if err != nil {
		sendCoapError(w, r, codes.UnsupportedMediaType, "%v", err)
		return
	}

	report, err := prover.Generate(req.Nonce, req.Cached, s.cmc.GetMetadata(), s.cmc.Drivers,
		ser, s.cmc.HashAlg)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError,
			"failed to generate attestation report: %v", err)
		return
	}

	resp := &api.AttestationResponse{
		Version: api.GetVersion(),
		Report:  report,
	}

	// Serialize CoAP payload
	payload, err := ser.Marshal(resp)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError, "failed to marshal message: %v", err)
		return
	}

	// CoAP response
	SendCoapResponse(w, r, payload)

	log.Infof("Sent coap response type 'Attest' to %v", w.Conn().RemoteAddr())
}

func (s CoapServer) Verify(w mux.ResponseWriter, r *mux.Message) {

	log.Infof("Received coap request type 'Verify' from %v", w.Conn().RemoteAddr())

	req := new(api.VerificationRequest)
	ser, err := unmarshal(r, req)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError,
			"failed to unmarshal CoAP payload: %v", err)
		return
	}

	err = req.CheckVersion()
	if err != nil {
		sendCoapError(w, r, codes.UnsupportedMediaType, "%v", err)
		return
	}

	log.Debug("verifying attestation report")
	result := verifier.Verify(req.Report, req.Nonce, req.Policies, s.cmc.PolicyEngineSelect,
		s.cmc.PolicyOverwrite, s.cmc.MetadataCas, s.cmc.PeerCache, req.Peer)

	resp := &api.VerificationResponse{
		Version: api.GetVersion(),
		Result:  result,
	}

	payload, err := ser.Marshal(&resp)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError, "failed to marshal message: %v", err)
		return
	}

	log.Debug("Verifier: sending attestation response")
	SendCoapResponse(w, r, payload)

	log.Infof("Sent coap response type 'Verify' to %v", w.Conn().RemoteAddr())
}

func (s CoapServer) Measure(w mux.ResponseWriter, r *mux.Message) {

	log.Infof("Received coap request type 'Measure' from %v", w.Conn().RemoteAddr())

	req := new(api.MeasureRequest)
	ser, err := unmarshal(r, req)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError,
			"failed to unmarshal CoAP payload: %v", err)
		return
	}

	err = req.CheckVersion()
	if err != nil {
		sendCoapError(w, r, codes.UnsupportedMediaType, "%v", err)
		return
	}

	log.Debug("Measurer: Recording measurement")
	var success bool
	err = m.Measure(&req.Event, ser, s.cmc.CtrLog, s.cmc.CtrDriver)
	if err != nil {
		log.Errorf("Failed to record measurement: %v", err)
		success = false
	} else {
		success = true
	}

	// Serialize CoAP payload
	resp := api.MeasureResponse{
		Version: api.GetVersion(),
		Success: success,
	}
	payload, err := ser.Marshal(&resp)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError, "failed to marshal message: %v", err)
		return
	}

	// CoAP response
	SendCoapResponse(w, r, payload)

	log.Infof("Sent coap response type 'Measure' to %v", w.Conn().RemoteAddr())
}

func (s CoapServer) TlsCreate(w mux.ResponseWriter, r *mux.Message) {
	log.Infof("Received coap request type 'TLSCreate' from %v", w.Conn().RemoteAddr())

	req := new(api.TLSCreateRequest)
	ser, err := unmarshal(r, req)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError,
			"failed to unmarshal CoAP payload: %v", err)
	}

	err = req.CheckVersion()
	if err != nil {
		sendCoapError(w, r, codes.UnsupportedMediaType, "%v", err)
		return
	}

	keyId, err := s.cmc.KeyMgr.EnrollKey(&keymgr.KeyEnrollmentParams{
		KeyConfig:  req.KeyConfig,
		Metadata:   s.cmc.GetMetadata(),
		Drivers:    s.cmc.Drivers,
		Serializer: ser,
		ArHashAlg:  s.cmc.HashAlg,
	})
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError,
			"failed to enroll key: %v", err)
		return
	}

	resp := &api.TLSCreateResponse{
		Version: api.GetVersion(),
		KeyId:   keyId,
	}

	payload, err := ser.Marshal(&resp)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError, "failed to marshal message: %v", err)
		return
	}

	// CoAP response
	SendCoapResponse(w, r, payload)

	log.Infof("Sent coap response type 'TLSCreate' to %v", w.Conn().RemoteAddr())
}

func (s CoapServer) TlsSign(w mux.ResponseWriter, r *mux.Message) {

	log.Infof("Received coap request type 'TLSSign' from %v", w.Conn().RemoteAddr())

	// Parse the CoAP message and return the TLS signing request
	req := new(api.TLSSignRequest)
	ser, err := unmarshal(r, req)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError,
			"failed to unmarshal CoAP payload: %v", err)
		return
	}

	err = req.CheckVersion()
	if err != nil {
		sendCoapError(w, r, codes.UnsupportedMediaType, "%v", err)
		return
	}

	signature, err := Sign(s.cmc.KeyMgr, req.KeyId, req.HashAlg, req.Content)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError, "failed to sign: %v", err)
		return
	}

	// Create response
	resp := &api.TLSSignResponse{
		Version:       api.GetVersion(),
		SignedContent: signature,
	}
	payload, err := ser.Marshal(&resp)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError, "failed to marshal message: %v", err)
		return
	}

	// CoAP response
	SendCoapResponse(w, r, payload)

	log.Infof("Sent coap response type 'TLSSign' to %v", w.Conn().RemoteAddr())
}

func (s CoapServer) TlsCert(w mux.ResponseWriter, r *mux.Message) {

	log.Infof("Received coap request type 'TLSCert' from %v", w.Conn().RemoteAddr())

	if len(s.cmc.Drivers) == 0 {
		sendCoapError(w, r, codes.InternalServerError,
			"Failed to sign: No valid drivers specified in config")
		return
	}

	// Parse the CoAP message and return the TLS signing request
	req := new(api.TLSCertRequest)
	ser, err := unmarshal(r, req)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError,
			"failed to unmarshal CoAP payload: %v", err)
		return
	}

	err = req.CheckVersion()
	if err != nil {
		sendCoapError(w, r, codes.UnsupportedMediaType, "%v", err)
		return
	}

	// Retrieve certificates
	certChain, err := s.cmc.KeyMgr.GetCertChain(req.KeyId)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError, "failed to get cert chain: %v", err)
		return
	}
	log.Debugf("Obtained TLS cert %v", certChain[0].Subject.CommonName)

	// Create response
	resp := &api.TLSCertResponse{
		Version:     api.GetVersion(),
		Certificate: internal.WriteCertsPem(certChain),
	}
	payload, err := ser.Marshal(&resp)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError, "failed to marshal message: %v", err)
		return
	}

	// CoAP response
	SendCoapResponse(w, r, payload)

	log.Infof("Sent coap response type 'TLSCert' to %v", w.Conn().RemoteAddr())
}

func (s CoapServer) PeerCache(w mux.ResponseWriter, r *mux.Message) {

	log.Infof("Received coap request type 'PeerCache' from %v", w.Conn().RemoteAddr())

	req := new(api.PeerCacheRequest)
	ser, err := unmarshal(r, req)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError,
			"failed to unmarshal CoAP payload: %v", err)
		return
	}

	err = req.CheckVersion()
	if err != nil {
		sendCoapError(w, r, codes.UnsupportedMediaType, "%v", err)
		return
	}

	log.Debug("Collecting peer cache")
	resp := api.PeerCacheResponse{
		Version: api.GetVersion(),
		Cache:   s.cmc.PeerCache.GetKeys(req.Peer),
	}

	payload, err := ser.Marshal(&resp)
	if err != nil {
		sendCoapError(w, r, codes.InternalServerError, "failed to marshal message: %v", err)
		return
	}

	SendCoapResponse(w, r, payload)

	log.Infof("Sent coap response type 'PeerCache' to %v", w.Conn().RemoteAddr())
}

func loggingMiddleware(next mux.Handler) mux.Handler {
	return mux.HandlerFunc(func(w mux.ResponseWriter, r *mux.Message) {
		log.Tracef("ClientAddress %v, %v", w.Conn().RemoteAddr(), r.String())
		next.ServeCOAP(w, r)
	})
}

func unmarshal(r *mux.Message, payload interface{}) (ar.Serializer, error) {
	// Read CoAP message body
	body, err := r.Message.ReadBody()
	if err != nil {
		return nil, fmt.Errorf("failed to read CoAP message body: %v", err)
	}

	// Detect serialization
	s, err := ar.DetectSerialization(body)
	if err != nil {
		return nil, fmt.Errorf("failed to detect serializationt: %v", err)
	}

	err = s.Unmarshal(body, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %v", err)
	}

	return s, nil
}

func SendCoapResponse(w mux.ResponseWriter, r *mux.Message, payload []byte) {
	customResp := w.Conn().AcquireMessage(r.Context())
	defer w.Conn().ReleaseMessage(customResp)
	customResp.SetCode(codes.Content)
	customResp.SetToken(r.Token())
	customResp.SetContentFormat(message.TextPlain)
	customResp.SetBody(bytes.NewReader(payload))
	log.Tracef("Sending coap message type %v, code %v, payload length %v",
		message.TextPlain.String(), codes.Content.String(), len(payload))
	err := w.Conn().WriteMessage(customResp)
	if err != nil {
		log.Errorf("cannot set response: %v", err)
	}
}

func sendCoapError(w mux.ResponseWriter, r *mux.Message, code codes.Code,
	format string, args ...interface{},
) {
	msg := fmt.Sprintf(format, args...)
	log.Warn(msg)
	customResp := w.Conn().AcquireMessage(r.Context())
	defer w.Conn().ReleaseMessage(customResp)
	customResp.SetCode(code)
	customResp.SetToken(r.Token())
	customResp.SetContentFormat(message.TextPlain)
	customResp.SetBody(bytes.NewReader([]byte(msg)))
	log.Tracef("Sending coap error message type %v, code %v, payload length %v",
		message.TextPlain.String(), code.String(), len([]byte(msg)))
	err := w.Conn().WriteMessage(customResp)
	if err != nil {
		log.Errorf("cannot set response: %v", err)
	}
}
