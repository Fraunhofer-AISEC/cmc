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
	"crypto/sha256"
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
	payload, err := c.apiSerializer.Marshal(req)
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
	checkError(msgType, payload, c.apiSerializer)

	// Save the attestation response for the verifier
	err = saveReport(c, payload, nonce)
	if err != nil {
		log.Fatalf("failed to save report: %v", err)
	}

}

func (a SocketApi) verify(c *config) {

	report, nonce, err := loadReport(c)
	if err != nil {
		log.Fatalf("Failed to load report: %v", err)
	}

	req := &api.VerificationRequest{
		Nonce:       nonce,
		Report:      report.Report,
		Metadata:    report.Metadata,
		CacheMisses: report.CacheMisses,
		Ca:          c.ca,
		Policies:    c.policies,
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

	if c.CtrConfig == "" {
		log.Fatalf("Mode measure requires OCI runtime config to be specified")
	}
	if c.CtrRootfs == "" {
		log.Fatalf("Mode measure requires container rootfs to be specified")
	}

	ctrConfig, err := os.ReadFile(c.CtrConfig)
	if err != nil {
		log.Fatalf("Failed to read oci runtime config: %v", err)
	}

	configHash, _, _, err := m.GetSpecMeasurement("mycontainer", ctrConfig)
	if err != nil {
		log.Fatalf("Failed to measure config: %v", err)
	}

	rootfsHash, err := m.GetRootfsMeasurement(c.CtrRootfs)
	if err != nil {
		log.Fatalf("Failed to measure rootfs: %v", err)
	}

	// Create template hash
	tbh := []byte(configHash)
	tbh = append(tbh, rootfsHash...)
	hasher := sha256.New()
	hasher.Write(tbh)
	templateHash := hasher.Sum(nil)

	req := &api.MeasureRequest{
		MeasureEvent: ar.MeasureEvent{
			Sha256:    templateHash,
			EventName: c.CtrName,
			CtrData: &ar.CtrData{
				ConfigSha256: configHash,
				RootfsSha256: rootfsHash,
			},
		},
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
	payload, err := c.apiSerializer.Marshal(req)
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
	checkError(msgType, payload, c.apiSerializer)

	// Unmarshal attestation response
	verifyResp := new(api.VerificationResponse)
	err = c.apiSerializer.Unmarshal(payload, verifyResp)
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
	payload, err := c.apiSerializer.Marshal(req)
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
	checkError(msgType, payload, c.apiSerializer)

	// Unmarshal attestation response
	measureResp := new(api.MeasureResponse)
	err = c.apiSerializer.Unmarshal(payload, measureResp)
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
