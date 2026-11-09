// Copyright (c) 2026 Fraunhofer AISEC
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

func testTlsConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	server := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
	}
	client := &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13}
	return server, client
}

// TestListenerSilentPeers checks that silent peers neither block other handshakes nor surface
// as Accept errors, and that the handshake deadline is removed from established connections.
func TestListenerSilentPeers(t *testing.T) {

	const handshakeTimeout = 500 * time.Millisecond

	serverConf, clientConf := testTlsConfigs(t)

	ln, err := Listen("tcp", "127.0.0.1:0", serverConf,
		WithAttest(Attest_None), WithAtlsTimeout(handshakeTimeout))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Silent peers that never start the TLS handshake
	for range 5 {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	clientErr := make(chan error, 1)
	start := time.Now()
	go func() {
		conn, err := Dial("tcp", ln.Addr().String(), clientConf, WithAttest(Attest_None))
		if err != nil {
			clientErr <- err
			return
		}
		defer conn.Close()
		// Wait beyond the handshake deadline before exchanging data
		time.Sleep(2 * handshakeTimeout)
		if _, err := conn.Write([]byte("ping")); err != nil {
			clientErr <- err
			return
		}
		buf := make([]byte, 4)
		_, err = conn.Read(buf)
		clientErr <- err
	}()

	var conn net.Conn
	select {
	case conn = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("accept failed: %v", err)
	case err := <-clientErr:
		t.Fatalf("client failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("accept timed out")
	}
	defer conn.Close()
	if d := time.Since(start); d >= handshakeTimeout {
		t.Fatalf("handshake was blocked by silent peers for %v", d)
	}

	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("server read failed: %v", err)
	}
	if _, err := conn.Write(buf); err != nil {
		t.Fatalf("server write failed: %v", err)
	}
	if err := <-clientErr; err != nil {
		t.Fatalf("client failed: %v", err)
	}

	// The silent peers time out in the background without returning Accept errors
	ln.Close()
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed after close, got %v", err)
	}
}
