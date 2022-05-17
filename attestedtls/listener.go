package attestedtls

import (
	"crypto/tls"
	"errors"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

var timeout = 10 * time.Second

/* Struct to implement Listener interface
 * holds net.Listener and adds additional functionality to it */
type Listener struct {
	Ln     net.Listener
	Config *tls.Config
}

// Implementation of Accept() in net.Listener iface
// Calls Accept of the net.Listnener and additionally performs remote attestation
// after connection establishment before returning the connection
func (ln Listener) Accept() (net.Conn, error) {
	// Accept TLS connection
	conn, err := ln.Ln.Accept()
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	log.Trace("[Listener] TLS established. Providing attestation report....")
	tlsConn := conn.(*tls.Conn)

	// Perform remote attestation
	// include components of tls.Conn to link both protocols: use own cert
	err = attest(tlsConn, ln.Config.Certificates[0].Certificate[0])
	if err != nil {
		log.Error(err)
		return nil, errors.New("[Listener] Failed to attest listener")
	}

	// if client provides its cert: mTLS
	// IMPORTANT: This info can only be obtained, once connection is established
	// Connection will only be established when used (read/write operations)
	mTLS := len(tlsConn.ConnectionState().PeerCertificates) != 0

	if mTLS {
		log.Info("[Listener] Performing mTLS: verifying dialer...")
		// include components of tls.Conn to link both protocols: use dialer cert
		// FUTURE: certificate can be obtained differently as well
		//         (function GetClientCertificate, func GetCertificate or func GetConfigForClient)
		err = verify(tlsConn, tlsConn.ConnectionState().PeerCertificates[0].Raw[:])
		if err != nil {
			log.Error(err)
			return nil, errors.New("[Listener] Failed to verify dialer")
		}
	} else {
		log.Info("[Listener] No mTLS performed")
	}

	log.Info("[Listener] Server-side aTLS connection complete")
	// finished
	return conn, nil
}

// Implementation of Close in net.Listener iface
// Only calls original Close(), since no new functionality required
func (ln Listener) Close() error {
	return ln.Ln.Close()
}

// Implementation of Addr in net.Listener iface
// Only calls original Addr(), since no new functionality required
func (ln Listener) Addr() net.Addr {
	return ln.Ln.Addr()
}

// Wrapper for tls.Listen
// Returns custom Listener that will perform additional remote attestation
// operations right after successful TLS connection establishment
func Listen(network, laddr string, config *tls.Config) (net.Listener, error) {
	var listener Listener
	ln, err := tls.Listen(network, laddr, config)
	if err != nil {
		log.Error(err)
		return listener, errors.New("[Listener] Failed")
	}
	listener = Listener{ln, config}
	return net.Listener(listener), nil
}
