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
	"math/big"
	"strings"
	"testing"
	"time"
)

// createTestCert creates a certificate signed by parent, or a self-signed certificate if no
// parent is given
func createTestCert(t *testing.T, cn string, parent *x509.Certificate,
	parentKey *ecdsa.PrivateKey, isCa bool, dnsNames []string,
) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCa,
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}
	if isCa {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	signer, signerKey := parent, parentKey
	if signer == nil {
		signer, signerKey = tmpl, key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert, key
}

// dialTestServer starts a TLS server presenting chain and returns the enriched error of a
// client connecting to it with clientConf
func dialTestServer(t *testing.T, chain [][]byte, key *ecdsa.PrivateKey,
	clientConf *tls.Config,
) error {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}},
	})
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// The handshake is expected to fail, the error is reported on the client side
		_ = conn.(*tls.Conn).Handshake()
		conn.Close()
	}()

	addr := ln.Addr().String()
	conn, err := tls.Dial("tcp", addr, clientConf)
	if err == nil {
		conn.Close()
		t.Fatal("TLS handshake succeeded, but was expected to fail")
	}

	return tlsHandshakeError(err, clientConf, addr, serverName(clientConf, addr))
}

func TestTlsHandshakeError(t *testing.T) {

	root, rootKey := createTestCert(t, "Test Root CA", nil, nil, true, nil)
	inter, interKey := createTestCert(t, "Test Intermediate CA", root, rootKey, true, nil)
	leaf, leafKey := createTestCert(t, "server.example.com", inter, interKey, false,
		[]string{"server.example.com"})
	selfSigned, selfSignedKey := createTestCert(t, "selfsigned.example.com", nil, nil, false,
		[]string{"selfsigned.example.com"})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(root)

	tests := []struct {
		name       string
		chain      [][]byte
		key        *ecdsa.PrivateKey
		clientConf *tls.Config
		want       []string
	}{
		{
			name:  "missing intermediate",
			chain: [][]byte{leaf.Raw},
			key:   leafKey,
			clientConf: &tls.Config{
				RootCAs:    rootPool,
				ServerName: "server.example.com",
			},
			want: []string{
				"peer presented 1 certificate(s)",
				`subject "CN=server.example.com,O=Test"`,
				`issuer "CN=Test Intermediate CA,O=Test"`,
				"the peer sent only its leaf certificate",
			},
		},
		{
			name:  "untrusted root",
			chain: [][]byte{leaf.Raw, inter.Raw, root.Raw},
			key:   leafKey,
			clientConf: &tls.Config{
				RootCAs:    x509.NewCertPool(),
				ServerName: "server.example.com",
			},
			want: []string{
				"peer presented 3 certificate(s)",
				`the chain ends at the self-signed root CA "CN=Test Root CA,O=Test"`,
			},
		},
		{
			name:  "self-signed peer certificate",
			chain: [][]byte{selfSigned.Raw},
			key:   selfSignedKey,
			clientConf: &tls.Config{
				RootCAs:    rootPool,
				ServerName: "selfsigned.example.com",
			},
			want: []string{
				"the peer presented a self-signed certificate",
				"attestation-only trust",
			},
		},
		{
			name:  "host name mismatch",
			chain: [][]byte{leaf.Raw, inter.Raw},
			key:   leafKey,
			clientConf: &tls.Config{
				RootCAs:    x509.NewCertPool(),
				ServerName: "wrong.example.com",
			},
			want: []string{
				`the leaf certificate is not valid for "wrong.example.com"`,
			},
		},
		{
			name:  "no peer chain reports own certificates",
			chain: [][]byte{leaf.Raw, inter.Raw, root.Raw},
			key:   leafKey,
			clientConf: &tls.Config{
				RootCAs:    rootPool,
				ServerName: "server.example.com",
				Certificates: []tls.Certificate{
					{Certificate: [][]byte{leaf.Raw}, PrivateKey: leafKey, Leaf: leaf},
				},
				// Force a failure that does not involve the peer certificates
				MaxVersion: tls.VersionTLS10,
			},
			want: []string{
				"presented 1 own certificate chain(s)",
				`subject "CN=server.example.com,O=Test"`,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := dialTestServer(t, test.chain, test.key, test.clientConf)
			got := err.Error()
			for _, want := range test.want {
				if !strings.Contains(got, want) {
					t.Errorf("error does not contain %q:\n%v", want, got)
				}
			}
		})
	}
}
