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

// Install github packages with "go get [url]"
import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/Fraunhofer-AISEC/cmc/coapapi"
	coap "github.com/plgd-dev/go-coap/v3"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/mux"

	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// TODO better solution
var conf *config

func loggingMiddleware(next mux.Handler) mux.Handler {
	return mux.HandlerFunc(func(w mux.ResponseWriter, r *mux.Message) {
		log.Printf("ClientAddress %v, %v\n", w.Conn().RemoteAddr(), r.String())
		next.ServeCOAP(w, r)
	})
}

func serve(c *config) error {

	conf = c

	log.Infof("Starting IoT Hub CoAP Server on %v", c.Addr)
	r := mux.NewRouter()
	r.Use(loggingMiddleware)
	r.Handle("/attest", mux.HandlerFunc(attest))

	log.Infof("Waiting for requests on %v", c.Addr)

	err := coap.ListenAndServe("udp", c.Addr, r)
	if err != nil {
		return fmt.Errorf("failed to serve: %v", err)
	}

	return nil
}

func attest(w mux.ResponseWriter, r *mux.Message) {

	log.Debug("Prover: Received CoAP attestation request")

	// Read CoAP message body (attestation report)
	body, err := r.Message.ReadBody()
	if err != nil {
		log.Fatalf("Failed to read CoAP message body: %v", err)
	}

	log.Debug("Verifier: Verifying Attestation Report")

	// Send attestation report to cmcd
	req := &coapapi.VerificationRequest{
		// TODO COAP GET
		Nonce:             []byte{0xde, 0xad},
		AttestationReport: body,
		Ca:                conf.ca,
		Policies:          conf.policies,
	}

	resp, err := verifyInternal(conf.CmcAddr, req)
	if err != nil {
		log.Fatalf("Failed to verify: %v", err)
	}

	// Check result
	result := new(ar.VerificationResult)
	err = json.Unmarshal(resp.VerificationResult, result)
	if err != nil {
		log.Fatalf("Failed to parse verification result: %v", err)
	}
	success := result.Success

	// TODO send back result
	log.Debugf("Result: %v", success)

	// CoAP response
	sendCoapResponse(w, r, []byte(strconv.FormatBool(success)))

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
