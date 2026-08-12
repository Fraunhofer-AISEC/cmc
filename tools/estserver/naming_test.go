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
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"testing"

	"github.com/Fraunhofer-AISEC/cmc/internal"
)

func makeCSR(t *testing.T, subject pkix.Name, dnsNames []string, ips []net.IP, uris []*url.URL) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:     subject,
		DNSNames:    dnsNames,
		IPAddresses: ips,
		URIs:        uris,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	return csr
}

func TestCsrPassthrough_CopiesAllFields(t *testing.T) {
	uri, _ := url.Parse("https://example.com/workload")
	ip := net.ParseIP("192.0.2.1")
	subject := pkix.Name{CommonName: "test.example.com", Organization: []string{"Acme"}}
	csr := makeCSR(t, subject, []string{"test.example.com"}, []net.IP{ip}, []*url.URL{uri})

	fields, err := CsrPassthrough{}.Assign(csr, internal.DefaultCertValidity, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// RawSubject must be byte-identical to the CSR's to preserve the original
	// DER encoding (string types, OID ordering, non-standard attributes).
	if !bytes.Equal(fields.RawSubject, csr.RawSubject) {
		t.Errorf("RawSubject mismatch: passthrough must copy DER bytes verbatim")
	}
	if len(fields.DNSNames) != 1 || fields.DNSNames[0] != "test.example.com" {
		t.Errorf("DNSNames: got %v, want [test.example.com]", fields.DNSNames)
	}
	if len(fields.IPAddresses) != 1 || !fields.IPAddresses[0].Equal(ip) {
		t.Errorf("IPAddresses: got %v, want [%v]", fields.IPAddresses, ip)
	}
	if len(fields.URIs) != 1 || fields.URIs[0].String() != uri.String() {
		t.Errorf("URIs: got %v, want [%v]", fields.URIs, uri)
	}
}

func TestCsrPassthrough_EmptyCSR(t *testing.T) {
	csr := makeCSR(t, pkix.Name{}, nil, nil, nil)
	fields, err := CsrPassthrough{}.Assign(csr, internal.DefaultCertValidity, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fields.DNSNames) != 0 || len(fields.IPAddresses) != 0 || len(fields.URIs) != 0 {
		t.Errorf("expected empty SANs, got dns=%v ip=%v uri=%v", fields.DNSNames, fields.IPAddresses, fields.URIs)
	}
}

func TestCsrPassthrough_IgnoresAttestationResult(t *testing.T) {
	csr := makeCSR(t, pkix.Name{CommonName: "node"}, nil, nil, nil)
	// nil result must not cause a panic
	fields, err := CsrPassthrough{}.Assign(csr, internal.DefaultCertValidity, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(fields.RawSubject, csr.RawSubject) {
		t.Errorf("RawSubject mismatch")
	}
}
