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

package est

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-attestation/attest"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// opaqueSigner hides the concrete key type like TPM keys do, so that only Public and Sign are
// available
type opaqueSigner struct {
	s crypto.Signer
}

func (o opaqueSigner) Public() crypto.PublicKey { return o.s.Public() }

func (o opaqueSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return o.s.Sign(r, digest, opts)
}

var (
	testTpmCertify = &attest.CertificationParameters{
		Public:            []byte("tpmt-public"),
		CreateAttestation: []byte("tpms-attest"),
		CreateSignature:   []byte("tpmt-signature"),
	}
	testReportJson = []byte(`{"type":"Attestation Report"}`)
	testReportCbor = []byte{0xa1, 0x64, 't', 'y', 'p', 'e', 0x01}
)

func testCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestCreateCsrRoundTrip(t *testing.T) {
	ecP256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecP521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	signers := []struct {
		name   string
		signer crypto.Signer
	}{
		{"ecdsa-p256", ecP256},
		{"ecdsa-p384", ecP384},
		{"ecdsa-p521", ecP521},
		{"rsa", rsaKey},
		{"ed25519", edKey},
		{"tpm-style-ecdsa", opaqueSigner{ecP256}},
		{"tpm-style-rsa", opaqueSigner{rsaKey}},
	}

	akCert := testCert(t, "AK")
	caCert := testCert(t, "CA")

	attestations := []struct {
		name string
		att  *CsrAttestation
	}{
		{"none", nil},
		{"tpm", &CsrAttestation{TpmCertify: testTpmCertify, Certs: []*x509.Certificate{akCert, caCert}}},
		{"report-json", &CsrAttestation{Report: testReportJson}},
		{"report-cbor", &CsrAttestation{Report: testReportCbor}},
		{"both", &CsrAttestation{TpmCertify: testTpmCertify, Report: testReportJson,
			Certs: []*x509.Certificate{akCert}}},
	}

	subject := pkix.Name{CommonName: "device", Organization: []string{"org"}}
	dnsNames := []string{"localhost", "device.example"}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

	for _, s := range signers {
		for _, a := range attestations {
			t.Run(s.name+"/"+a.name, func(t *testing.T) {
				csr, err := CreateCsr(s.signer, subject, dnsNames, ips, a.att)
				if err != nil {
					t.Fatalf("CreateCsr: %v", err)
				}

				// Parse from DER as the server does
				csr, err = x509.ParseCertificateRequest(csr.Raw)
				if err != nil {
					t.Fatalf("ParseCertificateRequest: %v", err)
				}
				if err := csr.CheckSignature(); err != nil {
					t.Fatalf("CheckSignature: %v", err)
				}
				if csr.Subject.CommonName != "device" || len(csr.Subject.Organization) != 1 {
					t.Fatalf("unexpected subject %v", csr.Subject)
				}
				if len(csr.DNSNames) != 2 || csr.DNSNames[1] != "device.example" {
					t.Fatalf("unexpected DNS names %v", csr.DNSNames)
				}
				if len(csr.IPAddresses) != 2 || !csr.IPAddresses[0].Equal(ips[0]) ||
					!csr.IPAddresses[1].Equal(ips[1]) {
					t.Fatalf("unexpected IPs %v", csr.IPAddresses)
				}

				got, err := ParseCsrAttestation(csr)
				if err != nil {
					t.Fatalf("ParseCsrAttestation: %v", err)
				}
				checkAttestation(t, a.att, got)
			})
		}
	}
}

func TestCreateCsrNoSans(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := CreateCsr(key, pkix.Name{CommonName: "x"}, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateCsr: %v", err)
	}
	if len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 || len(csr.Extensions) != 0 {
		t.Fatal("unexpected SANs")
	}
	att, err := ParseCsrAttestation(csr)
	if err != nil || att != nil {
		t.Fatalf("expected no attestation, got %v, %v", att, err)
	}
}

func TestCreateCsrEmptyAttestation(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := CreateCsr(key, pkix.Name{CommonName: "x"}, nil, nil,
		&CsrAttestation{Certs: []*x509.Certificate{testCert(t, "AK")}})
	if err == nil {
		t.Fatal("expected error for attestation without statements")
	}
}

func TestParseCsrAttestationGoCsr(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "x"},
		DNSNames: []string{"localhost"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	att, err := ParseCsrAttestation(csr)
	if err != nil || att != nil {
		t.Fatalf("expected no attestation, got %v, %v", att, err)
	}
}

func checkAttestation(t *testing.T, want, got *CsrAttestation) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Fatalf("expected no attestation, got %v", got)
		}
		return
	}
	if got == nil {
		t.Fatal("expected attestation")
	}
	if (want.TpmCertify == nil) != (got.TpmCertify == nil) {
		t.Fatalf("TPM certify presence mismatch")
	}
	if want.TpmCertify != nil {
		if !bytes.Equal(want.TpmCertify.Public, got.TpmCertify.Public) ||
			!bytes.Equal(want.TpmCertify.CreateAttestation, got.TpmCertify.CreateAttestation) ||
			!bytes.Equal(want.TpmCertify.CreateSignature, got.TpmCertify.CreateSignature) {
			t.Fatalf("TPM certify mismatch")
		}
	}
	if !bytes.Equal(want.Report, got.Report) {
		t.Fatalf("report mismatch: %x != %x", got.Report, want.Report)
	}
	if len(want.Certs) != len(got.Certs) {
		t.Fatalf("got %v certs, want %v", len(got.Certs), len(want.Certs))
	}
	for i := range want.Certs {
		if !want.Certs[i].Equal(got.Certs[i]) {
			t.Fatalf("cert %v mismatch", i)
		}
	}
}

// Helpers to build malformed or unusual attributes

func der(t *testing.T, f func(b *cryptobyte.Builder)) []byte {
	t.Helper()
	b := cryptobyte.NewBuilder(nil)
	f(b)
	out, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func seq(t *testing.T, elems ...[]byte) []byte {
	return der(t, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			for _, e := range elems {
				b.AddBytes(e)
			}
		})
	})
}

func oid(t *testing.T, o asn1.ObjectIdentifier) []byte {
	return der(t, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(o) })
}

func octets(t *testing.T, data []byte) []byte {
	return der(t, func(b *cryptobyte.Builder) { b.AddASN1OctetString(data) })
}

func utf8(t *testing.T, s string) []byte {
	return der(t, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.UTF8String, func(b *cryptobyte.Builder) { b.AddBytes([]byte(s)) })
	})
}

func tpmStmt(t *testing.T) []byte {
	return seq(t, oid(t, OidTpmCertify), seq(t, octets(t, []byte("a")), octets(t, []byte("s")),
		octets(t, []byte("p"))))
}

func cborCmw(t *testing.T, record any) []byte {
	data, err := cbor.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return octets(t, data)
}

func csrWithAttrs(t *testing.T, attrs ...[]byte) *x509.CertificateRequest {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(key.Public())
	tbs, err := marshalTbsCsr(seq(t), spki, attrs)
	if err != nil {
		t.Fatal(err)
	}
	return &x509.CertificateRequest{RawTBSCertificateRequest: tbs}
}

func attestationAttr(t *testing.T, bundles ...[]byte) []byte {
	attr, err := marshalAttribute(OidAttestation, bundles...)
	if err != nil {
		t.Fatal(err)
	}
	return attr
}

func TestParseCsrAttestation(t *testing.T) {
	cert := testCert(t, "AK")
	otherCert := der(t, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.Tag(3).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddBytes(oid(t, asn1.ObjectIdentifier{1, 2, 3}))
			b.AddBytes(octets(t, []byte("x")))
		})
	})
	jsonReport := `["` + MediaTypeCmcReportJson + `","eyJhIjoxfQ"]`
	otherStmt := seq(t, oid(t, asn1.ObjectIdentifier{1, 2, 3, 4}), octets(t, []byte("x")))
	otherCmw := seq(t, oid(t, OidCmw), utf8(t, `["application/eat+jwt","eHg"]`))
	cmwCollection := seq(t, oid(t, OidCmw), utf8(t, `{"a":["application/eat+jwt","eHg"]}`))
	cmwContentFormat := seq(t, oid(t, OidCmw), cborCmw(t, []any{10000, []byte("x")}))

	tests := []struct {
		name      string
		attrs     [][]byte
		wantErr   bool
		wantNil   bool
		wantTpm   bool
		wantRep   []byte
		wantCerts int
	}{
		{name: "no attributes", wantNil: true},
		{name: "other attribute", attrs: [][]byte{
			seq(t, oid(t, asn1.ObjectIdentifier{1, 2, 3}), der(t, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { b.AddBytes(octets(t, nil)) })
			}))}, wantNil: true},
		{name: "tpm", attrs: [][]byte{attestationAttr(t, seq(t, seq(t, tpmStmt(t))))},
			wantTpm: true},
		{name: "json report with parameter", attrs: [][]byte{attestationAttr(t, seq(t, seq(t,
			seq(t, oid(t, OidCmw), utf8(t, `["`+MediaTypeCmcReportJson+`; v=1","eyJhIjoxfQ",4]`)))))},
			wantRep: []byte(`{"a":1}`)},
		{name: "cbor report", attrs: [][]byte{attestationAttr(t, seq(t, seq(t,
			seq(t, oid(t, OidCmw), cborCmw(t, []any{MediaTypeCmcReportCbor, []byte{0xa0}})))))},
			wantRep: []byte{0xa0}},
		{name: "unknown statements ignored", attrs: [][]byte{attestationAttr(t, seq(t, seq(t,
			otherStmt, otherCmw, cmwCollection, cmwContentFormat, tpmStmt(t))))}, wantTpm: true},
		{name: "certs", attrs: [][]byte{attestationAttr(t, seq(t, seq(t, tpmStmt(t)),
			seq(t, cert.Raw, otherCert, cert.Raw)))}, wantTpm: true, wantCerts: 2},
		{name: "duplicate attribute", attrs: [][]byte{
			attestationAttr(t, seq(t, seq(t, tpmStmt(t)))),
			attestationAttr(t, seq(t, seq(t, tpmStmt(t)))),
		}, wantErr: true},
		{name: "two bundles", attrs: [][]byte{
			attestationAttr(t, seq(t, seq(t, tpmStmt(t))), seq(t, seq(t, tpmStmt(t)))),
		}, wantErr: true},
		{name: "no bundle", attrs: [][]byte{attestationAttr(t)}, wantErr: true},
		{name: "no statements", attrs: [][]byte{attestationAttr(t, seq(t, seq(t)))}, wantErr: true},
		{name: "empty certs", attrs: [][]byte{attestationAttr(t, seq(t, seq(t, tpmStmt(t)), seq(t)))},
			wantErr: true},
		{name: "trailing data in bundle", attrs: [][]byte{attestationAttr(t, seq(t,
			seq(t, tpmStmt(t)), seq(t, cert.Raw), octets(t, nil)))}, wantErr: true},
		{name: "invalid cert", attrs: [][]byte{attestationAttr(t, seq(t, seq(t, tpmStmt(t)),
			seq(t, seq(t, octets(t, nil)))))}, wantErr: true},
		{name: "invalid cert choice", attrs: [][]byte{attestationAttr(t, seq(t, seq(t, tpmStmt(t)),
			seq(t, octets(t, nil))))}, wantErr: true},
		{name: "duplicate tpm", attrs: [][]byte{attestationAttr(t, seq(t,
			seq(t, tpmStmt(t), tpmStmt(t))))}, wantErr: true},
		{name: "tpm missing signature", attrs: [][]byte{attestationAttr(t, seq(t, seq(t,
			seq(t, oid(t, OidTpmCertify), seq(t, octets(t, []byte("a"))))))),
		}, wantErr: true},
		{name: "tpm missing public", attrs: [][]byte{attestationAttr(t, seq(t, seq(t,
			seq(t, oid(t, OidTpmCertify), seq(t, octets(t, []byte("a")), octets(t, []byte("s"))))))),
		}, wantErr: true},
		{name: "statement trailing data", attrs: [][]byte{attestationAttr(t, seq(t, seq(t,
			seq(t, oid(t, OidTpmCertify), seq(t, octets(t, []byte("a")), octets(t, []byte("s")),
				octets(t, []byte("p"))), octets(t, nil)))))}, wantErr: true},
		{name: "duplicate report", attrs: [][]byte{attestationAttr(t, seq(t, seq(t,
			seq(t, oid(t, OidCmw), utf8(t, jsonReport)),
			seq(t, oid(t, OidCmw), utf8(t, jsonReport)))))}, wantErr: true},
		{name: "empty report", attrs: [][]byte{attestationAttr(t, seq(t, seq(t,
			seq(t, oid(t, OidCmw), utf8(t, `["`+MediaTypeCmcReportJson+`",""]`)))))}, wantErr: true},
		{name: "malformed json cmw", attrs: [][]byte{attestationAttr(t, seq(t, seq(t,
			seq(t, oid(t, OidCmw), utf8(t, `["`+MediaTypeCmcReportJson+`"`)))))}, wantErr: true},
		{name: "invalid json cmw length", attrs: [][]byte{attestationAttr(t, seq(t, seq(t,
			seq(t, oid(t, OidCmw), utf8(t, `["`+MediaTypeCmcReportJson+`"]`)))))}, wantErr: true},
		{name: "invalid base64url", attrs: [][]byte{attestationAttr(t, seq(t, seq(t,
			seq(t, oid(t, OidCmw), utf8(t, `["`+MediaTypeCmcReportJson+`","e+/="]`)))))},
			wantErr: true},
		{name: "invalid cbor cmw value", attrs: [][]byte{attestationAttr(t, seq(t, seq(t,
			seq(t, oid(t, OidCmw), cborCmw(t, []any{MediaTypeCmcReportCbor, "text"})))))},
			wantErr: true},
		{name: "invalid cmw choice", attrs: [][]byte{attestationAttr(t, seq(t, seq(t,
			seq(t, oid(t, OidCmw), seq(t)))))}, wantErr: true},
		{name: "empty cmw", attrs: [][]byte{attestationAttr(t, seq(t, seq(t,
			seq(t, oid(t, OidCmw), utf8(t, "")))))}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			att, err := ParseCsrAttestation(csrWithAttrs(t, tc.attrs...))
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCsrAttestation: %v", err)
			}
			if tc.wantNil {
				if att != nil {
					t.Fatalf("expected no attestation, got %v", att)
				}
				return
			}
			if att == nil {
				t.Fatal("expected attestation")
			}
			if (att.TpmCertify != nil) != tc.wantTpm {
				t.Fatalf("TPM certify present %v, want %v", att.TpmCertify != nil, tc.wantTpm)
			}
			if !bytes.Equal(att.Report, tc.wantRep) {
				t.Fatalf("report %q, want %q", att.Report, tc.wantRep)
			}
			if len(att.Certs) != tc.wantCerts {
				t.Fatalf("got %v certs, want %v", len(att.Certs), tc.wantCerts)
			}
		})
	}
}

func TestParseCsrAttestationMalformedTbs(t *testing.T) {
	_, err := ParseCsrAttestation(&x509.CertificateRequest{RawTBSCertificateRequest: []byte{0x30, 0x01}})
	if err == nil {
		t.Fatal("expected error")
	}
}
