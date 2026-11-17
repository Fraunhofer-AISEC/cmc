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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/certpolicy"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision/est"
)

func TestEnrollCertProfiles(t *testing.T) {
	tree, err := certpolicy.New(certpolicy.DefaultArc)
	if err != nil {
		t.Fatal(err)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDer, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDer)
	if err != nil {
		t.Fatal(err)
	}

	hw, _ := tree.Level(ar.LevelHardware)
	tdx, _ := tree.Tee("tdx")
	tpm, _ := tree.Tee("tpm")

	tests := []struct {
		name         string
		profile      certProfile
		wantAk       bool
		wantPolicies []x509.OID
	}{
		{"simpleenroll without attestation", tlsProfile(nil), false, nil},
		{"tpmactivateenroll", akProfile, true, nil},
		{"simpleenroll azure tdx", tlsProfile(tree.FromResult(&ar.AttestationResult{
			AttestLevel:  ar.LevelHardware,
			Measurements: []ar.MeasurementResult{{Type: ar.TYPE_RESULT_TDX}, {Type: ar.TYPE_RESULT_TPM}},
		})), false, []x509.OID{hw, tpm, tdx}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csr := makeCSR(t, pkix.Name{CommonName: "leaf"}, nil, nil, nil)
			cert, err := enrollCert(csr, caKey, ca, CsrPassthrough{}, nil, 0, tt.profile)
			if err != nil {
				t.Fatalf("enrollCert() error = %v", err)
			}
			if !slices.Equal(cert.ExtKeyUsage, tt.profile.ekus) {
				t.Errorf("ExtKeyUsage = %v, want %v", cert.ExtKeyUsage, tt.profile.ekus)
			}
			if !slices.EqualFunc(cert.UnknownExtKeyUsage, tt.profile.unknownEkus,
				asn1.ObjectIdentifier.Equal) {
				t.Errorf("UnknownExtKeyUsage = %v, want %v", cert.UnknownExtKeyUsage,
					tt.profile.unknownEkus)
			}
			if isAk := internal.HasUnknownExtKeyUsage(cert, internal.OidAkCertificate); isAk != tt.wantAk {
				t.Errorf("AK EKU present = %v, want %v", isAk, tt.wantAk)
			}
			if !slices.EqualFunc(cert.Policies, tt.wantPolicies, x509.OID.Equal) {
				t.Errorf("Policies = %v, want %v", cert.Policies, tt.wantPolicies)
			}
		})
	}
}

func TestCsrattrs(t *testing.T) {
	for _, tt := range []struct {
		name     string
		auth     internal.AuthMethod
		want     int
		wantAttr bool
	}{
		{"attestation", internal.AuthAttestation | internal.AuthToken, http.StatusOK, true},
		{"token", internal.AuthToken, http.StatusNoContent, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{auth: map[string]internal.AuthMethod{est.EnrollEndpoint: tt.auth}}
			req := httptest.NewRequest(http.MethodGet, est.EndpointPrefix+est.CsrattrsEndpoint, nil)
			rec := httptest.NewRecorder()

			s.handleCsrattrs(rec, req)

			if rec.Code != tt.want {
				t.Fatalf("status = %v, want %v", rec.Code, tt.want)
			}
			if !tt.wantAttr {
				return
			}
			der, err := est.DecodeBase64(rec.Body.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			var attrs []asn1.ObjectIdentifier
			if rest, err := asn1.Unmarshal(der, &attrs); err != nil || len(rest) > 0 {
				t.Fatalf("failed to parse CSR attributes: %v", err)
			}
			if len(attrs) != 1 || !attrs[0].Equal(est.OidAttestation) {
				t.Errorf("CSR attributes = %v, want %v", attrs, est.OidAttestation)
			}
		})
	}
}

// TestSimplereenroll checks that /simplereenroll requires a client certificate and a CSR with
// the subject and SANs of that certificate
func TestSimplereenroll(t *testing.T) {
	tree, err := certpolicy.New(certpolicy.DefaultArc)
	if err != nil {
		t.Fatal(err)
	}
	ca, caKey := newTestCa(t, "EST CA")
	s := &Server{
		estCaKey:     caKey,
		estCaChain:   []*x509.Certificate{ca},
		certPolicies: tree,
		namingPolicy: CsrPassthrough{},
		auth:         map[string]internal.AuthMethod{est.ReenrollEndpoint: internal.AuthCertificate},
	}

	subject := pkix.Name{CommonName: "device"}
	dnsNames := []string{"device.example.com"}
	client := createTestCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      subject,
		DNSNames:     dnsNames,
		ExtKeyUsage:  internal.TlsExtKeyUsage,
	}, ca, caKey, newTestKey(t))

	for _, tt := range []struct {
		name     string
		cert     bool
		subject  pkix.Name
		dnsNames []string
		want     int
	}{
		{"matching", true, subject, dnsNames, http.StatusOK},
		{"no client certificate", false, subject, dnsNames, http.StatusUnauthorized},
		{"subject mismatch", true, pkix.Name{CommonName: "other"}, dnsNames, http.StatusBadRequest},
		{"SAN mismatch", true, subject, []string{"other.example.com"}, http.StatusBadRequest},
		{"SAN missing", true, subject, nil, http.StatusBadRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			csr := makeCSR(t, tt.subject, tt.dnsNames, nil, nil)
			req := httptest.NewRequest(http.MethodPost, est.EndpointPrefix+est.ReenrollEndpoint,
				bytes.NewReader(est.EncodeBase64(csr.Raw)))
			req.Header.Set(internal.HttpContentTypeHeader, est.MimeTypePKCS10)
			if tt.cert {
				req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{client, ca}}}
			}
			rec := httptest.NewRecorder()

			s.handleSimplereenroll(rec, req)

			if rec.Code != tt.want {
				t.Fatalf("status = %v, want %v: %v", rec.Code, tt.want, rec.Body.String())
			}
			if tt.want != http.StatusOK {
				return
			}
			certs, err := est.ParseSimplePkiResponse(rec.Body.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if err := matchCertNames(csr, certs[0]); err != nil {
				t.Errorf("renewed certificate names differ: %v", err)
			}
		})
	}
}
