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

package main

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
	"net/http"
	"net/http/httptest"
	"testing"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision/est"
)

func TestAuthorize(t *testing.T) {

	const endpoint = "/test"

	result := &ar.AttestationResult{}
	attestOk := func() (*ar.AttestationResult, error) { return result, nil }
	attestFail := func() (*ar.AttestationResult, error) { return nil, errors.New("invalid report") }

	withCert := httptest.NewRequest("POST", endpoint, nil)
	withCert.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}

	for _, tt := range []struct {
		name       string
		configured bool
		methods    internal.AuthMethod
		cert       bool
		attest     attestFunc
		wantErr    bool
		wantResult bool
	}{
		{"not configured", false, 0, false, nil, true, false},
		{"none", true, internal.AuthNone, false, nil, false, false},
		{"none with report", true, internal.AuthNone, false, attestOk, true, false},
		{"attestation", true, internal.AuthAttestation, false, attestOk, false, true},
		{"attestation fails", true, internal.AuthAttestation, false, attestFail, true, false},
		{"attestation without report", true, internal.AuthAttestation, false, nil, true, false},
		{"certificate", true, internal.AuthCertificate, true, nil, false, false},
		{"certificate missing", true, internal.AuthCertificate, false, nil, true, false},
		{"certificate with report", true, internal.AuthCertificate, true, attestOk, true, false},
		{"token missing", true, internal.AuthToken, false, nil, true, false},
		{"certificate fallback without report", true,
			internal.AuthAttestation | internal.AuthCertificate, true, nil, false, false},
		{"no fallback on failed attestation", true,
			internal.AuthAttestation | internal.AuthCertificate, true, attestFail, true, false},
		{"all fail", true, internal.AuthAttestation | internal.AuthCertificate | internal.AuthToken,
			false, nil, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{auth: map[string]internal.AuthMethod{}, tokenPath: t.TempDir()}
			if tt.configured {
				s.auth[endpoint] = tt.methods
			}
			req := httptest.NewRequest("POST", endpoint, nil)
			if tt.cert {
				req = withCert
			}

			r, err := s.authorize(endpoint, req, tt.attest)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, want error %v", err, tt.wantErr)
			}
			if (r != nil) != tt.wantResult {
				t.Errorf("result = %v, want result %v", r, tt.wantResult)
			}
		})
	}
}

func TestAuthorizeReenroll(t *testing.T) {

	result := &ar.AttestationResult{}
	attestOk := func() (*ar.AttestationResult, error) { return result, nil }
	attestFail := func() (*ar.AttestationResult, error) { return nil, errors.New("invalid report") }

	for _, tt := range []struct {
		name       string
		configured bool
		methods    internal.AuthMethod
		cert       bool
		attest     attestFunc
		wantErr    bool
		wantResult bool
	}{
		{"not configured", false, 0, true, nil, true, false},
		{"certificate", true, internal.AuthCertificate, true, nil, false, false},
		{"certificate missing", true, internal.AuthCertificate, false, nil, true, false},
		{"certificate with report", true, internal.AuthCertificate, true, attestOk, true, false},
		{"certificate and attestation", true, internal.AuthCertificate | internal.AuthAttestation,
			true, attestOk, false, true},
		{"attestation without certificate", true,
			internal.AuthCertificate | internal.AuthAttestation, false, attestOk, true, false},
		{"certificate without report", true, internal.AuthCertificate | internal.AuthAttestation,
			true, nil, true, false},
		{"attestation fails", true, internal.AuthCertificate | internal.AuthAttestation, true,
			attestFail, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{auth: map[string]internal.AuthMethod{}}
			if tt.configured {
				s.auth[est.ReenrollEndpoint] = tt.methods
			}
			req := httptest.NewRequest("POST", est.ReenrollEndpoint, nil)
			if tt.cert {
				req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}
			}

			r, err := s.authorizeReenroll(req, tt.attest)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, want error %v", err, tt.wantErr)
			}
			if (r != nil) != tt.wantResult {
				t.Errorf("result = %v, want result %v", r, tt.wantResult)
			}
		})
	}
}

// TestClientCertificateCas checks that client certificates are only accepted if they chain to
// est.client_cas, but not to the metadata CAs in trust.root_cas
func TestClientCertificateCas(t *testing.T) {

	const endpoint = "/test"

	clientCa, clientCaKey := newTestCa(t, "Client CA")
	metadataCa, metadataCaKey := newTestCa(t, "Metadata CA")
	serverCa, serverCaKey := newTestCa(t, "Server CA")

	serverKey := newTestKey(t)
	serverCert := createTestCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "EST Server"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, serverCa, serverCaKey, serverKey)

	c := &Config{
		tlsKey:     serverKey,
		tlsCaChain: []*x509.Certificate{serverCert, serverCa},
		rootCas:    []*x509.Certificate{metadataCa},
		clientCas:  []*x509.Certificate{clientCa},
		auth:       map[string]internal.AuthMethod{endpoint: internal.AuthCertificate},
	}
	c.Trust.AllowSystemCerts = true

	s := &Server{auth: c.auth}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.authorize(endpoint, r, nil); err != nil {
			s.writeAuthError(w, endpoint, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = newTlsConfig(c)
	server.StartTLS()
	defer server.Close()

	for _, tt := range []struct {
		name       string
		ca         *x509.Certificate
		caKey      *ecdsa.PrivateKey
		wantStatus int
		wantErr    bool
	}{
		{"client CA", clientCa, clientCaKey, http.StatusOK, false},
		{"metadata CA", metadataCa, metadataCaKey, 0, true},
		{"no certificate", nil, nil, http.StatusForbidden, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			roots := x509.NewCertPool()
			roots.AddCert(serverCa)
			tlsCfg := &tls.Config{RootCAs: roots}
			if tt.ca != nil {
				key := newTestKey(t)
				cert := createTestCert(t, &x509.Certificate{
					SerialNumber: big.NewInt(3),
					Subject:      pkix.Name{CommonName: "Client"},
					KeyUsage:     x509.KeyUsageDigitalSignature,
					ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				}, tt.ca, tt.caKey, key)
				// Always send the certificate, the client would otherwise omit certificates not
				// issued by one of the CAs the server requests
				tlsCfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}, nil
				}
			}
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}

			resp, err := client.Post(server.URL+endpoint, "", nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, want error %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			resp.Body.Close()
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %v, want %v", resp.StatusCode, tt.wantStatus)
			}
		})
	}
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return key
}

func newTestCa(t *testing.T, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := newTestKey(t)
	ca := createTestCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, nil, nil, key)
	return ca, key
}
