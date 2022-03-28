package attestedtls

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/golang/protobuf/proto"
	"net"
	"time"
	// local modules
	ci "github.com/Fraunhofer-AISEC/cmc/cmcinterface"
	log "github.com/sirupsen/logrus"
	// debug
	"encoding/hex"
)

var id = "0000"
var timeout = 10 * time.Second

/* Checks Attestation report by calling the CMC to Verify and checking its status response
 */
func obtainAR(req *ci.AttestationRequest) (resp *ci.AttestationResponse, err error) {
	// Get backend connection
	cmcClient, cmcconn, cancel := getCMCServiceConn()
	if cmcClient == nil {
		return nil, errors.New("[Listener] Connection failed. No result obtained")
	}
	defer cmcconn.Close()
	defer cancel()

	// Extend Attest request with id
	req.Id = id

	// Call Attest request
	resp, err = cmcClient.Attest(context.Background(), req)
	if err != nil {
		log.Error(err)
		return nil, errors.New("[Listener] Could not obtain attestation report")
	}

	// Return response
	return resp, nil
}

/***********************************************************
* net.Listener Wrapper -> attestedtls.Listener
 */

/* Struct to implement Listener interface
 * holds net.Listener and adds additional functionality to its functions */
type Listener struct {
	Ln net.Listener
}

/* Implementation of Accept() in net.Listener iface
 * Additionally creates AR with obtained nonce and returns it
 */
func (ln Listener) Accept() (net.Conn, error) {
	var err error
	var conn net.Conn
	var data []byte
	var resp *ci.AttestationResponse

	// Accept TLS connection
	conn, err = ln.Ln.Accept()
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	log.Trace("TLS established. Providing attestation report....")

	// Obtain request msg
	data, err = Read(conn)
	if err != nil {
		log.Error(err)
		conn.Close()
		return nil, errors.New("[Listener] Did not receive (right sized) nonce")
	}
	log.Trace("[Listener] Received: ", hex.EncodeToString(data))

	// Parse request msg
	req := &ci.AttestationRequest{}
	err = proto.Unmarshal(data, req)
	if err != nil {
		log.Error(err)
		conn.Close()
		return nil, errors.New("[Dialer] Failed to parse attestation request.")
	}

	// Check nonce length
	if len(req.Nonce) != noncelen {
		conn.Close()
		return nil, errors.New("[Dialer] Nonce does not have expected size")
	}

	// Obtain response
	log.Info("[Listener] Contacting backend for AR verification")
	resp, err = obtainAR(req)
	if err != nil {
		log.Error(err)
		conn.Close()
		return nil, errors.New("[Listener] Could not obtain response")
	}
	data, err = proto.Marshal(resp)
	if err != nil {
		log.Error(err)
		conn.Close()
		return nil, errors.New("[Dialer] Failed to marshal response.")
	}

	// Send response
	log.Info("[Listener] Sending AR to client")
	err = Write(data, conn)
	if err != nil {
		log.Error(err)
		conn.Close()
		return nil, errors.New("[Listener] Failed to write AR")
	}
	log.Info("[Listener] Sent AR")

	// FUTURE: Receive some sort of Ack (or send if mTLS)
	// FUTURE: check for mTLS here: if enabled, create and send nonce to connector, receive and verify its AR

	log.Info("[Listener] Server-side connection complete")
	// finished
	return conn, nil
}

/* Implementation of Close in net.Listener iface
 * Only calls original Close(), since no new functionality required
 */
func (ln Listener) Close() error {
	return ln.Ln.Close()
}

/* Implementation of Addr in net.Listener iface
 * Only calls original Addr(), since no new functionality required
 */
func (ln Listener) Addr() net.Addr {
	return ln.Ln.Addr()
}

/***********************************************************
* Public function
 */

/* Wrapper for tls.Listen
 * Returns custom Listener that will perform steps to send the AR right after connection establishment
 */
func Listen(network, laddr string, config *tls.Config) (net.Listener, error) {
	var listener Listener
	ln, err := tls.Listen(network, laddr, config)
	if err != nil {
		log.Error(err)
		return listener, errors.New("[Listener] Failed")
	}
	listener = Listener{ln}
	return net.Listener(listener), nil
}
