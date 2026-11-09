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

package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func createTestCa(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert, key
}

func TestHttpClientTlsErrorDetails(t *testing.T) {

	// The server and the client use different root CAs with the same name
	serverCa, serverCaKey := createTestCa(t, "Test Root CA")
	clientCa, _ := createTestCa(t, "Test Root CA")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, serverCa, &key.PublicKey, serverCaKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
	server.StartTLS()
	defer server.Close()

	client, err := NewHttpClient([]*x509.Certificate{clientCa}, false, nil)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = client.Get(server.URL)
	if err == nil {
		t.Fatal("request succeeded, but was expected to fail")
	}

	got := err.Error()
	for _, want := range []string{
		"peer presented 1 certificate(s)",
		"configured 1 root CA(s)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("error does not contain %q:\n%v", want, got)
		}
	}
	if strings.Contains(got, "the peer sent only its leaf certificate") {
		t.Errorf("error contains misleading chain hint:\n%v", got)
	}
	for _, want := range []string{
		"sha256 " + fingerprint(clientCa),
		`the configured root CA "CN=Test Root CA" (sha256 ` + fingerprint(clientCa) +
			") has the name of the issuer, but did not sign the chain",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("error does not contain %q:\n%v", want, got)
		}
	}
}
