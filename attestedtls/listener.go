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
	"crypto/tls"
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
	cmcConfig    // embedded struct
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

	log.Trace("TLS established. Providing attestation report..")
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("internal error: failed to convert to tlsconn")
	}

	// Usually, not required, as the the first Read or Write will call it
	// automatically. We run it here to export the keying material for
	// channel binding before sending the first message
	err = tlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	cs := tlsConn.ConnectionState()
	log.Tracef("TLS Handshake Complete: %v, generating channel bindings", cs.HandshakeComplete)
	chbindings, err := cs.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to export keying material for channel binding: %w", err)
	}

	// Perform remote attestation with unique channel binding as specified in RFC5056,
	// RFC5705, and RFC9266
	err = attestListener(tlsConn, chbindings, ln.cmcConfig)
	if err != nil {
		return nil, fmt.Errorf("remote attestation failed: %w", err)
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
func Listen(network, laddr string, config *tls.Config, moreConfigs ...ConnectionOption[cmcConfig]) (net.Listener, error) {

	// Default listener
	listener := Listener{
		cmcConfig: cmcConfig{
			cmcAddr: cmcAddrDefault,
			cmcApi:  cmcApis[cmcApiSelectDefault],
		},
	}

	// Apply all additional (CMC) configs
	for _, c := range moreConfigs {
		c(&listener.cmcConfig)
	}

	// Check that selected API is implemented
	if listener.cmcConfig.cmcApi == nil {
		return listener, fmt.Errorf("selected CMC API is not implemented")
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
