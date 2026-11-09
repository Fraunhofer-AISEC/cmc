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
	"sync"
	"time"
)

const timeout = 10 * time.Second

// atlsTimeout returns the effective aTLS handshake deadline duration.
// If c.AtlsTimeout is set it takes precedence; otherwise the package default
// (10 s) is used. This is the single authoritative source for the timeout
// value, shared by both Listener (via handshake) and Dial.
func atlsTimeout(c *CmcConfig) time.Duration {
	if c != nil && c.AtlsTimeout != nil {
		return *c.AtlsTimeout
	}
	return timeout
}

// Listener wraps a TLS listener and performs the aTLS handshake on accepted connections.
// Handshakes run concurrently in the background, so slow or silent peers do not block other
// connections. Accept only returns connections that completed the handshake.
type Listener struct {
	net.Listener
	cc        *CmcConfig
	config    *tls.Config
	conns     chan net.Conn
	errs      chan error
	done      chan struct{}
	closeOnce sync.Once
}

// NewListener wraps a listener that returns *tls.Conn connections. The TLS config is only used
// for diagnostics on handshake errors and may be nil.
func NewListener(inner net.Listener, config *tls.Config, cc *CmcConfig) *Listener {
	ln := &Listener{
		Listener: inner,
		cc:       cc,
		config:   config,
		conns:    make(chan net.Conn),
		errs:     make(chan error),
		done:     make(chan struct{}),
	}
	go ln.serve()
	return ln
}

// Accept returns the next connection that completed the aTLS handshake. Errors of the
// underlying listener are returned unwrapped so that callers can inspect them.
func (ln *Listener) Accept() (net.Conn, error) {
	select {
	case conn := <-ln.conns:
		return conn, nil
	case err := <-ln.errs:
		return nil, err
	case <-ln.done:
		return nil, net.ErrClosed
	}
}

// Close stops accepting connections and closes the underlying listener
func (ln *Listener) Close() error {
	ln.closeOnce.Do(func() { close(ln.done) })
	return ln.Listener.Close()
}

func (ln *Listener) serve() {
	for {
		conn, err := ln.Listener.Accept()
		if errors.Is(err, net.ErrClosed) {
			ln.closeOnce.Do(func() { close(ln.done) })
			return
		}
		if err != nil {
			// Hand the error to the caller, which decides whether to retry
			select {
			case ln.errs <- err:
				continue
			case <-ln.done:
				return
			}
		}
		go ln.handle(conn)
	}
}

func (ln *Listener) handle(conn net.Conn) {
	if err := ln.handshake(conn); err != nil {
		log.Warnf("%v", err)
		conn.Close()
		return
	}
	select {
	case ln.conns <- conn:
	case <-ln.done:
		conn.Close()
	}
}

func (ln *Listener) handshake(conn net.Conn) error {

	err := conn.SetDeadline(time.Now().Add(atlsTimeout(ln.cc)))
	if err != nil {
		return fmt.Errorf("failed to set deadline: %w", err)
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return errors.New("internal error: failed to convert to tlsconn")
	}

	peer := conn.RemoteAddr().String()

	// Usually, not required, as the the first Read or Write will call it
	// automatically. We run it here to export the keying material for
	// channel binding before sending the first message
	log.Debugf("Connection from %v established. Performing TLS handshake..", peer)
	err = tlsConn.Handshake()
	if err != nil {
		return tlsHandshakeError(err, ln.config, peer, "")
	}

	log.Debug("Connection established, getting connection state")
	cs := tlsConn.ConnectionState()
	if !cs.HandshakeComplete {
		return errors.New("internal error: handshake not complete")
	}
	log.Debug("TLS handshake complete")

	// Retrieve peer's TLS leaf certificate fingerprint to be used as peer ID for peer cache
	log.Debug("Retrieving TLS certificate fingerprint as peer ID")
	var fingerprint string
	if len(cs.PeerCertificates) > 0 {
		f := sha256.Sum256(cs.PeerCertificates[0].Raw)
		fingerprint = hex.EncodeToString(f[:])
	}
	log.Debugf("Successfully retrieved peer TLS fingerprint: %v", fingerprint)

	// Perform remote attestation
	err = atlsHandshakeStart(tlsConn, fingerprint, ln.cc, Endpoint_Server)
	if err != nil {
		// Only log the error, still send handshake complete message to inform peer
		log.Warnf("atls handshake failed: %v", err)
	}
	err = aTlsHandshakeComplete(tlsConn, ln.cc.Serializer, err)
	if err != nil {
		return fmt.Errorf("atls handshake failed: %w", err)
	}

	// Remove the handshake deadline, the application manages its own timeouts
	err = conn.SetDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("failed to reset deadline: %w", err)
	}

	log.Info("Server-side aTLS connection complete")

	return nil
}

// Listen wraps tls.Listen and returns a Listener that performs the aTLS handshake on
// accepted connections
func Listen(network, laddr string, config *tls.Config, moreConfigs ...ConnectionOption[CmcConfig]) (net.Listener, error) {

	cc, err := NewCmcConfig(moreConfigs...)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve CMC config: %w", err)
	}

	ln, err := tls.Listen(network, laddr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}

	return NewListener(ln, config, cc), nil
}
