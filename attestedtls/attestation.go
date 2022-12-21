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
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
)

var id = "0000"
var noncelen = 32

var log = logrus.WithField("service", "atls")

// Attests itself by receiving a nonce, creating an AR and returning it
func attest(conn *tls.Conn, cert []byte, cc cmcConfig) error {
	log.Info("Attesting to peer in connection...")

	// Obtain request msg
	req, err := Read(conn)
	if err != nil {
		return fmt.Errorf("failed to receive attestation request: %w", err)
	}

	// Obtain response (AR)
	resp, err := cc.cmcApi.obtainAR(req, cc, cert)
	if err != nil {
		return fmt.Errorf("could not obtain response: %w", err)
	}

	// Send response
	err = Write(resp, conn)
	if err != nil {
		return fmt.Errorf("failed to send AR: %w", err)
	}
	log.Info("Sent AR")

	// Receive Ack to know if verification was successful
	err = receiveAck(conn)
	if err != nil {
		return fmt.Errorf("other side failed to verify AR: %w", err)
	}
	log.Info("Attestation to peer successful")
	return nil
}

// Verifies remote party by sending nonce, receiving an AR and verfying it
func verify(conn *tls.Conn, cert []byte, cc cmcConfig) error {
	log.Info("Verifying peer in connection...")

	// Create nonce
	nonce := make([]byte, noncelen)
	_, err := rand.Read(nonce)
	if err != nil {
		_ = sendAck(false, conn)
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	data, err := cc.cmcApi.createARRequest(nonce)
	if err != nil {
		_ = sendAck(false, conn)
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Send Request msg
	err = Write(data, conn)
	if err != nil {
		_ = sendAck(false, conn)
		return fmt.Errorf("failed to write request: %w", err)
	}

	// Receive response
	log.Trace("Waiting for AR...")
	data, err = Read(conn)
	if err != nil {
		_ = sendAck(false, conn)
		return fmt.Errorf("failed to read response: %w", err)
	}

	report, err := cc.cmcApi.parseARResponse(data)
	if err != nil {
		_ = sendAck(false, conn)
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// include components of tls.Conn to link both protocols
	combinedNonce := sha256.Sum256(append(cert[:], nonce[:]...))

	// Verify AR
	log.Trace("Verifying attestation report...")
	err = cc.cmcApi.verifyAR(combinedNonce[:], report, cc)
	if err != nil {
		_ = sendAck(false, conn)
		return err
	}
	err = sendAck(true, conn)
	if err != nil {
		return fmt.Errorf("failed to send ACK: %w", err)
	}
	log.Trace("Verified peer")
	return nil
}

// Sends success ACK or failure to peer
func sendAck(success bool, conn *tls.Conn) error {
	log.Trace("Sending ACK...")

	data := make([]byte, 1)
	if success {
		data[0] = 0
	} else {
		data[0] = 1
	}
	err := Write(data, conn)
	if err != nil {
		return fmt.Errorf("failed to write ACK: %w", err)
	}
	return nil
}

// Waits for and reads success ACK or failure
// In case of failure, an error is returned
func receiveAck(conn *tls.Conn) error {
	log.Trace("Waiting for ACK...")

	data, err := Read(conn)
	if err != nil {
		return fmt.Errorf("failed to read ACK: %w", err)
	}
	if len(data) != 1 || data[0] != 0 {
		return errors.New("did not receive success ACK")
	}
	return nil
}
