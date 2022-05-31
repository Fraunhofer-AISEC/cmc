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

package attestedtls

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	ci "github.com/Fraunhofer-AISEC/cmc/cmcinterface"
)

var id = "0000"
var noncelen = 32

// Checks Attestation report by calling the CMC to Verify and checking its status response
func obtainAR(req *ci.AttestationRequest, cc cmcConfig) (resp *ci.AttestationResponse, err error) {
	// Get backend connection
	cmcClient, cmcconn, cancel := getCMCServiceConn(cc)
	if cmcClient == nil {
		return nil, errors.New("[attestedTLS] Connection failed. No result obtained")
	}
	defer cmcconn.Close()
	defer cancel()
	log.Trace("[attestedTLS] Contacting backend to obtain AR.")

	// Extend Attest request with id
	req.Id = id

	// Call Attest request
	resp, err = cmcClient.Attest(context.Background(), req)
	if err != nil {
		log.Error(err)
		return nil, errors.New("[attestedTLS] Could not obtain attestation report")
	}

	// Return response
	return resp, nil
}

//Checks Attestation report by calling the CMC to Verify and checking its status response
func verifyAR(nonce, report []byte, cc cmcConfig) error {
	// Get backend connection
	cmcClient, conn, cancel := getCMCServiceConn(cc)
	if cmcClient == nil {
		return errors.New("[attestedTLS] Connection failed. No result obtained")
	}
	defer conn.Close()
	defer cancel()
	log.Trace("[attestedTLS] Contacting backend for AR verification")

	// Create Verification request
	req := ci.VerificationRequest{
		Nonce:             nonce,
		AttestationReport: report,
		Ca:                cc.ca,
	}
	// Perform Verify request
	resp, err := cmcClient.Verify(context.Background(), &req)
	if err != nil {
		log.Error(err)
		return errors.New("[attestedTLS] Could not obtain verification result")
	}
	// Check Verify response
	if resp.GetStatus() != ci.Status_OK {
		return errors.New("[attestedTLS] Obtaining verification result failed")
	}

	// parse VerificationResult
	var result ar.VerificationResult
	err = json.Unmarshal(resp.GetVerificationResult(), &result)
	if err != nil {
		log.Error(err)
		return errors.New("[attestedTLS] Could not parse verification result")
	}

	// check results
	if !result.Success {
		log.Tracef("Attestation result: %v", string(resp.GetVerificationResult()))
		return errors.New("[attestedTLS] Verification failed")
	}
	return nil
}

// Attests itself by receiving a nonce, creating an AR and returning it
func attest(conn *tls.Conn, cert []byte, cc cmcConfig) error {
	log.Info("[attestedTLS] Attesting to peer in connection...")

	// Obtain request msg
	data, err := Read(conn)
	if err != nil {
		log.Error(err)
		return errors.New("[attestedTLS] Did not receive attestation request")
	}
	// Parse request msg
	req := &ci.AttestationRequest{}
	err = proto.Unmarshal(data, req)
	if err != nil {
		log.Error(err)
		return errors.New("[attestedTLS] Failed to parse attestation request")
	}

	// Check nonce length
	if len(req.Nonce) != noncelen {
		return errors.New("[attestedTLS] Nonce does not have expected size")
	}

	// include components of tls.Conn to link both protocols: use serverCert
	combinedNonce := sha256.Sum256(append(cert[:], req.Nonce[:]...))
	req.Nonce = combinedNonce[:]

	// Obtain response (AR)
	resp, err := obtainAR(req, cc)
	if err != nil {
		log.Error(err)
		return errors.New("[attestedTLS] Could not obtain response")
	}
	data, err = proto.Marshal(resp)
	if err != nil {
		log.Error(err)
		return errors.New("[attestedTLS] Failed to marshal response")
	}

	// Send response
	err = Write(data, conn)
	if err != nil {
		log.Error(err)
		return errors.New("[attestedTLS] Failed to send AR")
	}
	log.Info("[attestedTLS] Sent AR")

	// Receive Ack to know if verification was successful
	err = receiveAck(conn)
	if err != nil {
		log.Error(err)
		return errors.New("[attestedTLS] Other side failed to verify AR")
	}
	log.Info("[attestedTLS] Attestation to peer succesful")
	return nil
}

// Verifies remote party by sending nonce, receiving an AR and verfying it
func verify(conn *tls.Conn, cert []byte, cc cmcConfig) error {
	log.Info("[attestedTLS] Verifying peer in connection...")

	// Create nonce
	nonce := make([]byte, noncelen)
	_, err := rand.Read(nonce)
	if err != nil {
		log.Error(err)
		_ = sendAck(false, conn)
		return errors.New("[attestedTLS] Failed to generate nonce")
	}

	// Create AR request with nonce
	req := &ci.AttestationRequest{
		Nonce: nonce,
	}
	data, err := proto.Marshal(req)
	if err != nil {
		log.Error(err)
		_ = sendAck(false, conn)
		return errors.New("[attestedTLS] Failed to generate request")
	}

	// Send Request msg
	err = Write(data, conn)
	if err != nil {
		log.Error(err)
		_ = sendAck(false, conn)
		return errors.New("[attestedTLS] Failed to write request")
	}

	// Receive response
	log.Trace("[attestedTLS] Waiting for AR...")
	data, err = Read(conn)
	if err != nil {
		log.Error(err)
		_ = sendAck(false, conn)
		return errors.New("[attestedTLS] Failed to read response")
	}

	// Parse response msg
	resp := &ci.AttestationResponse{}
	err = proto.Unmarshal(data, resp)
	if err != nil {
		log.Error(err)
		_ = sendAck(false, conn)
		return errors.New("[attestedTLS] Failed to parse response")
	}

	// Check response status
	if resp.Status != ci.Status_OK || len(resp.AttestationReport) == 0 {
		_ = sendAck(false, conn)
		return errors.New("[attestedTLS] Did not receive attestation report")
	}

	// include components of tls.Conn to link both protocols
	combinedNonce := sha256.Sum256(append(cert[:], nonce[:]...))

	// Verify AR
	log.Trace("[attestedTLS] Verifying attestation report...")
	err = verifyAR(combinedNonce[:], resp.AttestationReport, cc)
	if err != nil {
		log.Error(err)
		_ = sendAck(false, conn)
		return errors.New("[attestedTLS] Attestation report verification failed")
	}
	err = sendAck(true, conn)
	if err != nil {
		log.Error(err)
		return errors.New("[attestedTLS] Failed to send ACK")
	}
	log.Trace("[attestedTLS] Verified peer")
	return nil
}

// Sends success ACK or failure to peer
func sendAck(success bool, conn *tls.Conn) error {
	log.Trace("[attestedTLS] Sending ACK...")

	data := make([]byte, 1)
	if success {
		data[0] = 0
	} else {
		data[0] = 1
	}
	err := Write(data, conn)
	if err != nil {
		log.Error(err)
		return errors.New("[attestedTLS] Failed to write ACK")
	}
	return nil
}

// Waits for and reads success ACK or failure
// In case of failure, an error is returned
func receiveAck(conn *tls.Conn) error {
	log.Trace("[attestedTLS] Waiting for ACK...")

	data, err := Read(conn)
	if err != nil {
		log.Error(err)
		return errors.New("[attestedTLS] Failed to read ACK")
	}
	if len(data) != 1 || data[0] != 0 {
		return errors.New("[attestedTLS] Did not receive success ACK")
	}
	return nil
}
