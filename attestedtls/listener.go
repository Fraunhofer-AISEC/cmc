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
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"
)

const timeout = 10 * time.Second

/* Struct to implement Listener interface
 * holds net.Listener and adds additional functionality to it */
type Listener struct {
	net.Listener // embedded interface
	*CmcConfig   // embedded struct
	*tls.Config  // embedded struct
}

// Implementation of Accept() in net.Listener iface
// Calls Accept of the net.Listnener and additionally performs remote attestation
// after connection establishment before returning the connection
func (ln Listener) Accept() (net.Conn, error) {

	// Accept TLS connection
	conn, err := ln.Listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("failed to accept connection: %w", err)
	}
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}
	err = conn.SetWriteDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, fmt.Errorf("failed to set write deadline: %w", err)
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("internal error: failed to convert to tlsconn")
	}

	// Usually, not required, as the the first Read or Write will call it
	// automatically. We run it here to export the keying material for
	// channel binding before sending the first message
	log.Debug("Connection established. Performing TLS handshake..")
	err = tlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	log.Debug("Connection established, getting connection state")
	cs := tlsConn.ConnectionState()
	if !cs.HandshakeComplete {
		return nil, errors.New("internal error: handshake not complete")
	}

	log.Debug("TLS handshake complete, generating channel bindings")
	chbindings, err := cs.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to export keying material for channel binding: %w", err)
	}

	// Retrieve peer's TLS leaf certificate fingerprint to be used as peer ID for peer cache
	log.Debug("Retrieving TLS certificate fingerprint as peer ID")
	var fingerprint string
	if len(cs.PeerCertificates) > 0 {
		f := sha256.Sum256(cs.PeerCertificates[0].Raw)
		fingerprint = hex.EncodeToString(f[:])
	}
	log.Debugf("Successfully retrieved peer TLS fingerprint: %v", fingerprint)

	// Perform remote attestation with unique channel binding as specified in RFC5056,
	// RFC5705, and RFC9266
	err = atlsHandshakeStart(tlsConn, chbindings, fingerprint, ln.CmcConfig, Endpoint_Server)
	if err != nil {
		// Only log the error, still send handshake complete message to inform peer
		log.Warnf("atls handshake failed: %v", err)
	}
	err = aTlsHandshakeComplete(tlsConn, ln.CmcConfig.ApiSerializer, err)
	if err != nil {
		return nil, fmt.Errorf("atls handshake failed: %w", err)
	}

	log.Info("Server-side aTLS connection complete")

	return conn, nil
}

// Implementation of Close in net.Listener iface
// Only calls original Close(), since no new functionality required
func (ln Listener) Close() error {
	return ln.Listener.Close()
}

// Implementation of Addr in net.Listener iface
// Only calls original Addr(), since no new functionality required
func (ln Listener) Addr() net.Addr {
	return ln.Listener.Addr()
}

// Wrapper for tls.Listen
// Returns custom Listener that will perform additional remote attestation
// operations right after successful TLS connection establishment
func Listen(network, laddr string, config *tls.Config, moreConfigs ...ConnectionOption[CmcConfig]) (net.Listener, error) {

	cc, err := NewCmcConfig(moreConfigs...)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve CMC config: %w", err)
	}

	listener := Listener{
		CmcConfig: cc,
	}

	// Listen
	ln, err := tls.Listen(network, laddr, config)
	if err != nil {
		return listener, fmt.Errorf("failed to listen: %w", err)
	}
	listener.Listener = ln
	listener.Config = config

	return net.Listener(listener), nil
}
