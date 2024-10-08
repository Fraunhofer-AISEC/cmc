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

// Install github packages with "go get [url]"
import (
	"crypto/rand"
	"fmt"
	"net"
	"os"

	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	m "github.com/Fraunhofer-AISEC/cmc/measure"

	"github.com/Fraunhofer-AISEC/cmc/api"
	"github.com/Fraunhofer-AISEC/cmc/attestedtls"
)

type SocketApi struct{}

func init() {
	apis["socket"] = SocketApi{}
}

func (a SocketApi) generate(c *config) {

	log.Tracef("Connecting via %v socket to %v", c.Network, c.CmcAddr)

	// Establish connection
	conn, err := net.Dial(c.Network, c.CmcAddr)
	if err != nil {
		log.Fatalf("Error dialing: %v", err)
	}

	// Generate random nonce
	nonce := make([]byte, 8)
	_, err = rand.Read(nonce)
	if err != nil {
		log.Fatalf("Failed to read random bytes: %v", err)
	}

	// Generate attestation request
	req := &api.AttestationRequest{
		Nonce: nonce,
	}

	// Marshal payload
	payload, err := c.serializer.Marshal(req)
	if err != nil {
		log.Fatalf("failed to marshal payload: %v", err)
	}

	// Send request
	err = api.Send(conn, payload, api.TypeAttest)
	if err != nil {
		log.Fatalf("failed to send request: %v", err)
	}

	// Read reply
	payload, msgType, err := api.Receive(conn)
	if err != nil {
		log.Fatalf("failed to receive: %v", err)
	}
	checkError(msgType, payload, c.serializer)

	// Unmarshal attestation response
	var attestationResp api.AttestationResponse
	err = c.serializer.Unmarshal(payload, &attestationResp)
	if err != nil {
		log.Fatalf("failed to unmarshal response")
	}

	// Save the attestation report for the verifier
	err = os.WriteFile(c.ReportFile, attestationResp.AttestationReport, 0644)
	if err != nil {
		log.Fatalf("Failed to save attestation report as %v: %v", c.ReportFile, err)
	}
	log.Infof("Wrote attestation report: %v", c.ReportFile)

	// Save the nonce for the verifier
	os.WriteFile(c.NonceFile, nonce, 0644)
	if err != nil {
		log.Fatalf("Failed to save nonce as %v: %v", c.NonceFile, err)
	}
	log.Infof("Wrote nonce: %v", c.NonceFile)

}

func (a SocketApi) verify(c *config) {

	// Read the attestation report, CA and the nonce previously stored
	data, err := os.ReadFile(c.ReportFile)
	if err != nil {
		log.Fatalf("Failed to read file %v: %v", c.ReportFile, err)
	}

	nonce, err := os.ReadFile(c.NonceFile)
	if err != nil {
		log.Fatalf("Failed to read nonce: %v", err)
	}

	req := &api.VerificationRequest{
		Nonce:             nonce,
		AttestationReport: data,
		Ca:                c.ca,
		Policies:          c.policies,
	}

	resp, err := verifySocketRequest(c, req)
	if err != nil {
		log.Fatalf("Failed to verify: %v", err)
	}

	err = saveResult(c.ResultFile, c.Publish, resp.VerificationResult)
	if err != nil {
		log.Fatalf("Failed to save result: %v", err)
	}
}

func (a SocketApi) measure(c *config) {

	ctrConfig, err := os.ReadFile(c.CtrConfig)
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}

	configHash, _, _, err := m.GetSpecMeasurement("mycontainer", ctrConfig)
	if err != nil {
		log.Fatalf("Failed to measure config: %v", err)
	}

	rootfsHash, err := m.GetRootfsMeasurement(c.CtrRootfs)
	if err != nil {
		log.Fatalf("Failed to measure rootfs: %v", err)
	}

	req := &api.MeasureRequest{
		Name:         c.CtrName,
		ConfigSha256: configHash,
		RootfsSha256: rootfsHash,
	}

	resp, err := measureSocketRequest(c, req)
	if err != nil {
		log.Fatalf("Failed to measure: %v", err)
	}

	log.Debugf("Recorded measurement. Result: %v", resp.Success)
}

func (a SocketApi) dial(c *config) {
	dialInternal(c, attestedtls.CmcApi_Socket, nil)
}

func (a SocketApi) listen(c *config) {
	listenInternal(c, attestedtls.CmcApi_Socket, nil)
}

func (a SocketApi) request(c *config) {
	requestInternal(c, attestedtls.CmcApi_Socket, nil)
}

func (a SocketApi) serve(c *config) {
	serveInternal(c, attestedtls.CmcApi_Socket, nil)
}

func (a SocketApi) cacerts(c *config) {
	getCaCertsInternal(c)
}

func (a SocketApi) iothub(c *config) {
	log.Fatalf("IoT hub not implemented for sockets API")
}

func verifySocketRequest(c *config, req *api.VerificationRequest,
) (*api.VerificationResponse, error) {

	log.Tracef("Connecting via %v socket to %v", c.Network, c.CmcAddr)

	// Establish connection
	conn, err := net.Dial(c.Network, c.CmcAddr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %v", err)
	}

	// Marshal payload
	payload, err := c.serializer.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Send request
	err = api.Send(conn, payload, api.TypeVerify)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}

	// Read reply
	payload, msgType, err := api.Receive(conn)
	if err != nil {
		log.Fatalf("failed to receive: %v", err)
	}
	checkError(msgType, payload, c.serializer)

	// Unmarshal attestation response
	verifyResp := new(api.VerificationResponse)
	err = c.serializer.Unmarshal(payload, verifyResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response")
	}

	return verifyResp, nil
}

func measureSocketRequest(c *config, req *api.MeasureRequest,
) (*api.MeasureResponse, error) {

	log.Tracef("Connecting via %v socket to %v", c.Network, c.CmcAddr)

	// Establish connection
	conn, err := net.Dial(c.Network, c.CmcAddr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %v", err)
	}

	// Marshal payload
	payload, err := c.serializer.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Send request
	err = api.Send(conn, payload, api.TypeMeasure)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}

	// Read reply
	payload, msgType, err := api.Receive(conn)
	if err != nil {
		log.Fatalf("failed to receive: %v", err)
	}
	checkError(msgType, payload, c.serializer)

	// Unmarshal attestation response
	measureResp := new(api.MeasureResponse)
	err = c.serializer.Unmarshal(payload, measureResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response")
	}

	return measureResp, nil
}

func checkError(t uint32, payload []byte, s ar.Serializer) {
	if t == api.TypeError {
		resp := new(api.SocketError)
		err := s.Unmarshal(payload, resp)
		if err != nil {
			log.Fatal("failed to unmarshal error response")
		} else {
			log.Fatalf("server responded with error: %v", resp.Msg)
		}
	}
}
