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
	"strconv"

	"github.com/Fraunhofer-AISEC/cmc/api"
	coap "github.com/plgd-dev/go-coap/v3"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/mux"
	// local modules
)

var conf *config

func loggingMiddleware(next mux.Handler) mux.Handler {
	return mux.HandlerFunc(func(w mux.ResponseWriter, r *mux.Message) {
		log.Tracef("ClientAddress %v, %v\n", w.Conn().RemoteAddr(), r.String())
		next.ServeCOAP(w, r)
	})
}

func serveHub(c *config) error {

	conf = c

	addr := ""
	if len(c.Addr) > 0 {
		addr = c.Addr[0]
	}

	log.Infof("Starting IoT Hub CoAP Server on %v", addr)
	r := mux.NewRouter()
	r.Use(loggingMiddleware)
	r.Handle("/attest", mux.HandlerFunc(attestHub))

	log.Infof("Waiting for requests on %v", addr)

	err := coap.ListenAndServe("udp", addr, r)
	if err != nil {
		return fmt.Errorf("failed to serve: %v", err)
	}

	return nil
}

func attestHub(w mux.ResponseWriter, r *mux.Message) {

	log.Debug("Prover: Received CoAP attestation request")

	// Read CoAP message body (attestation report)
	body, err := r.Message.ReadBody()
	if err != nil {
		log.Fatalf("Failed to read CoAP message body: %v", err)
	}

	log.Debug("Verifier: Verifying Attestation Report")

	// Send attestation report to cmcd
	req := &api.VerificationRequest{
		// TODO COAP GET
		Nonce:    []byte{0xde, 0xad},
		Report:   body, // TODO metadata
		Ca:       conf.ca,
		Policies: conf.policies,
	}

	resp, err := verifyInternal(conf, req)
	if err != nil {
		log.Fatalf("Failed to verify: %v", err)
	}

	// CoAP response
	sendCoapResponse(w, r, []byte(strconv.FormatBool(resp.Result.Success)))

	log.Debug("IoT Hub: Finished")
}

func sendCoapResponse(w mux.ResponseWriter, r *mux.Message, payload []byte) {
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
