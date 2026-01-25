// Copyright (c) 2021 - 2024 Fraunhofer AISEC
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
	"crypto/rand"
	"fmt"
	"net"

	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	pub "github.com/Fraunhofer-AISEC/cmc/publish"

	"github.com/Fraunhofer-AISEC/cmc/api"
)

type SocketApi struct{}

func init() {
	apis["socket"] = SocketApi{}
}

func (a SocketApi) generate(c *config) error {

	network, addr, err := internal.GetNetworkAndAddr(c.CmcAddr)
	if err != nil {
		return fmt.Errorf("failed to get network and address: %w", err)
	}

	log.Infof("Sending socket request type 'Attest' to %v", c.CmcAddr)

	// Establish connection
	conn, err := net.Dial(network, addr)
	if err != nil {
		return fmt.Errorf("error dialing: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, 8)
	_, err = rand.Read(nonce)
	if err != nil {
		return fmt.Errorf("failed to read random bytes: %w", err)
	}

	// Generate attestation request
	req := &api.AttestationRequest{
		Version: api.GetVersion(),
		Nonce:   nonce,
	}

	// Marshal payload
	payload, err := c.apiSerializer.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send request
	err = api.Send(conn, payload, api.TypeAttest)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	// Read reply
	payload, msgType, err := api.Receive(conn)
	if err != nil {
		return fmt.Errorf("failed to receive: %w", err)
	}
	checkError(msgType, payload, c.apiSerializer)

	// Save the attestation response for the verifier
	err = pub.SaveReport(c.ReportFile, c.NonceFile, payload, nonce)
	if err != nil {
		return fmt.Errorf("failed to save report: %w", err)
	}

	return nil
}

func (a SocketApi) verify(c *config) error {

	log.Infof("Sending socket request type 'Verify' to %v", c.CmcAddr)

	report, nonce, err := pub.LoadReport(c.ReportFile, c.NonceFile, c.apiSerializer)
	if err != nil {
		return fmt.Errorf("failed to load report: %w", err)
	}

	req := &api.VerificationRequest{
		Version:     api.GetVersion(),
		Nonce:       nonce,
		Report:      report.Report,
		Metadata:    report.Metadata,
		CacheMisses: report.CacheMisses,
		Policies:    c.policies,
	}

	resp, err := verifySocketRequest(c, req)
	if err != nil {
		return fmt.Errorf("failed to verify: %w", err)
	}

	err = pub.PublishResult(c.Publish, c.publishToken, c.ResultFile, &resp.Result)
	if err != nil {
		return fmt.Errorf("failed to save result: %w", err)
	}

	return nil
}

func (a SocketApi) updateCerts(c *config) error {

	network, addr, err := internal.GetNetworkAndAddr(c.CmcAddr)
	if err != nil {
		return fmt.Errorf("failed to get network and address: %w", err)
	}

	log.Infof("Sending socket request type 'UpdateCerts' to %v", c.CmcAddr)

	// Establish connection
	conn, err := net.Dial(network, addr)
	if err != nil {
		return fmt.Errorf("error dialing: %w", err)
	}

	// Generate attestation request
	req := &api.UpdateCertsRequest{
		Version: api.GetVersion(),
	}

	// Marshal payload
	payload, err := c.apiSerializer.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send request
	err = api.Send(conn, payload, api.TypeUpdateCerts)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	// Read reply
	payload, msgType, err := api.Receive(conn)
	if err != nil {
		return fmt.Errorf("failed to receive: %w", err)
	}
	checkError(msgType, payload, c.apiSerializer)

	// Unmarshal attestation response
	resp := new(api.UpdateCertsResponse)
	err = c.apiSerializer.Unmarshal(payload, resp)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Check attestation response
	if err := resp.CheckVersion(); err != nil {
		return fmt.Errorf("failed to update certs: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("update certs response returned success: %v", resp.Success)
	}

	return nil
}

func (a SocketApi) updateMetadata(c *config) error {

	network, addr, err := internal.GetNetworkAndAddr(c.CmcAddr)
	if err != nil {
		return fmt.Errorf("failed to get network and address: %w", err)
	}

	log.Infof("Sending socket request type 'UpdateMetadata' to %v", c.CmcAddr)

	// Establish connection
	conn, err := net.Dial(network, addr)
	if err != nil {
		return fmt.Errorf("error dialing: %w", err)
	}

	// Generate attestation request
	req := &api.UpdateMetadataRequest{
		Version: api.GetVersion(),
	}

	// Marshal payload
	payload, err := c.apiSerializer.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send request
	err = api.Send(conn, payload, api.TypeUpdateMetadata)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	// Read reply
	payload, msgType, err := api.Receive(conn)
	if err != nil {
		return fmt.Errorf("failed to receive: %w", err)
	}
	checkError(msgType, payload, c.apiSerializer)

	// Unmarshal attestation response
	resp := new(api.UpdateMetadataResponse)
	err = c.apiSerializer.Unmarshal(payload, resp)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Check attestation response
	if err := resp.CheckVersion(); err != nil {
		return fmt.Errorf("failed to update metadata: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("update metadata response returned success: %v", resp.Success)
	}

	return nil
}

func verifySocketRequest(c *config, req *api.VerificationRequest,
) (*api.VerificationResponse, error) {

	network, addr, err := internal.GetNetworkAndAddr(c.CmcAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get network and address: %w", err)
	}

	// Establish connection
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, fmt.Errorf("error dialing: %w", err)
	}

	// Marshal payload
	payload, err := c.apiSerializer.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send request
	err = api.Send(conn, payload, api.TypeVerify)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read reply
	payload, msgType, err := api.Receive(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive: %w", err)
	}
	checkError(msgType, payload, c.apiSerializer)

	// Unmarshal attestation response
	verifyResp := new(api.VerificationResponse)
	err = c.apiSerializer.Unmarshal(payload, verifyResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response")
	}

	if err := verifyResp.CheckVersion(); err != nil {
		return nil, err
	}

	return verifyResp, nil
}

func checkError(t uint32, payload []byte, s ar.Serializer) error {
	if t == api.TypeError {
		resp := new(api.SocketError)
		err := s.Unmarshal(payload, resp)
		if err != nil {
			return fmt.Errorf("failed to unmarshal error response: %w", err)
		} else {
			return fmt.Errorf("server responded with error: %v", resp.Msg)
		}
	}
	return nil
}
