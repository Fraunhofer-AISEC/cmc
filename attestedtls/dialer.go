package attestedtls

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	ci "github.com/Fraunhofer-AISEC/cmc/cmcinterface"
	// debug
	"encoding/hex"
)

var noncelen = 32

/* Checks Attestation report by calling the CMC to Verify and checking its status response
 */
func verifyAR(nonce, report []byte) error {
	var req ci.VerificationRequest
	var resp *ci.VerificationResponse
	var result ar.VerificationResult
	var err error
	// Get backend connection
	cmcClient, conn, cancel := getCMCServiceConn()
	if cmcClient == nil {
		return errors.New("[Dialer] Connection failed. No result obtained.")
	}
	defer conn.Close()
	defer cancel()
	log.Trace("[Dialer] Contacting backend for AR verification.")
	// Create Verification request
	req = ci.VerificationRequest{
		Nonce:             nonce,
		AttestationReport: report,
	}
	// Perform Verify request
	resp, err = cmcClient.Verify(context.Background(), &req)
	if err != nil {
		log.Error(err)
		return errors.New("[Dialer] Could not obtain verification result")
	}
	// Check Verify response
	if resp.GetStatus() != ci.Status_OK {
		return errors.New("[Dialer] Obtaining verification result failed")
	}

	// parse VerificationResult
	err = json.Unmarshal(resp.GetVerificationResult(), &result)
	if err != nil {
		log.Error(err)
		return errors.New("[Dialer] Could not parse verification result")
	}
	// check results
	if !result.Success {
		log.Error("Verification failed")
		return errors.New("[Dialer] Verification failed.")
	}
	return nil
}

/***********************************************************
 * tls.Dial Wrapper -> attestedtls.Dial
 * Additionally requests and then verifies the obtained Attestation Report
 * before returning the established connection.
 */
func Dial(network, addr string, config *tls.Config) (*tls.Conn, error) {
	var nonce []byte
	var err error
	var conn *tls.Conn
	// Create TLS connection
	conn, err = tls.Dial(network, addr, config)
	if err != nil {
		log.Error(err)
		return nil, errors.New("[Dialer] TLS establishment failed.")
	}
	log.Trace("[Dialer] TLS established. Obtaining attestation report.....")

	// Create nonce
	nonce = make([]byte, noncelen)
	_, err = rand.Read(nonce)
	if err != nil {
		log.Error(err)
		conn.Close()
		return nil, errors.New("[Dialer] Failed to generate nonce.")
	}

	// Create AR request with nonce
	req := &ci.AttestationRequest{
		Nonce: nonce,
	}
	data, err := proto.Marshal(req)
	if err != nil {
		log.Error(err)
		conn.Close()
		return nil, errors.New("[Dialer] Failed to generate request.")
	}

	// Send Request msg
	log.Trace("[Dialer] writing: ", hex.EncodeToString(data))
	err = Write(data, conn)
	if err != nil {
		log.Error(err)
		conn.Close()
		return nil, errors.New("[Dialer] Failed to write request.")
	}

	// Receive response
	log.Trace("[Dialer] Waiting for AR.....")
	data, err = Read(conn)
	if err != nil {
		log.Error(err)
		conn.Close()
		return nil, errors.New("[Dialer] Failed to read response.")
	}

	// Parse response msg
	resp := &ci.AttestationResponse{}
	err = proto.Unmarshal(data, resp)
	if err != nil {
		log.Error(err)
		conn.Close()
		return nil, errors.New("[Dialer] Failed to parse response.")
	}

	// Check response status
	if resp.Status != ci.Status_OK || len(resp.AttestationReport) == 0 {
		conn.Close()
		return nil, errors.New("[Dialer] Did not receive attestation report.")
	}

	// Verify AR
	log.Trace("[Dialer] Verifying attestation report.....")
	err = verifyAR(nonce, resp.AttestationReport)
	if err != nil {
		log.Error(err)
		conn.Close()
		return nil, errors.New("[Dialer] Attestation report verification failed.")
	}
	// FUTURE: check for mTLS here and then receive nonce, obtain local AR and send to other connector
	// FUTURE: Send some sort of Ack (or receive if mTLS)

	log.Info("[Dialer] Attestation successful. Connection Establishment complete.")

	// finished
	return conn, nil
}
