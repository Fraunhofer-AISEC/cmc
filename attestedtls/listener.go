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
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

var timeout = 10 * time.Second

/* Struct to implement Listener interface
 * holds net.Listener and adds additional functionality to it */
type Listener struct {
	net.Listener // embedded interface
	cmcConfig    // embedded struct
	*tls.Config  // embedded struct
}

type ConnectionOption[T any] func(*T)

// WithCmcPort sets the port on which to contact the CMC.
// If not specified, default is "9955"
func WithCmcPort(port string) ConnectionOption[cmcConfig] {
	return func(c *cmcConfig) {
		c.cmcPort = port
	}
}

// WithCmcAddress sets the address with which to contact the CMC.
// If not specified, default is "localhost"
func WithCmcAddress(address string) ConnectionOption[cmcConfig] {
	return func(c *cmcConfig) {
		c.cmcAddress = address
	}
}

// WithCmcCa specifies the CA the attestation report should be verified against
// in PEM format
func WithCmcCa(pem []byte) ConnectionOption[cmcConfig] {
	return func(c *cmcConfig) {
		c.ca = pem
	}
}

// WithCmcPolicies specified optional custom policies the attestation report should
// be verified against
func WithCmcPolicies(policies []byte) ConnectionOption[cmcConfig] {
	return func(c *cmcConfig) {
		c.policies = policies
	}
}

// Implementation of Accept() in net.Listener iface
// Calls Accept of the net.Listnener and additionally performs remote attestation
// after connection establishment before returning the connection
func (ln Listener) Accept() (net.Conn, error) {
	// Accept TLS connection
	conn, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	log.Trace("[Listener] TLS established. Providing attestation report....")
	tlsConn := conn.(*tls.Conn)

	// Perform remote attestation
	// include components of tls.Conn to link both protocols: use own cert
	err = attest(tlsConn, ln.Certificates[0].Certificate[0], ln.cmcConfig)
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
		err = verify(tlsConn, tlsConn.ConnectionState().PeerCertificates[0].Raw[:], ln.cmcConfig)
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
			cmcAddress: cmcAddressDefault,
			cmcPort:    cmcPortDefault,
		},
	}
	// Listen
	ln, err := tls.Listen(network, laddr, config)
	if err != nil {
		log.Error(err)
		return listener, errors.New("[Listener] Failed")
	}
	// Apply all additional (CMC) configs
	listener.Listener = ln
	listener.Config = config
	for _, c := range moreConfigs {
		c(&listener.cmcConfig)
	}
	return net.Listener(listener), nil
}
