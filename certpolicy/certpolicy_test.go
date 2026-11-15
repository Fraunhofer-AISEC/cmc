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

package certpolicy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"testing"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

func mustTree(t *testing.T) *Tree {
	t.Helper()
	tree, err := New(DefaultArc)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return tree
}

func TestNew(t *testing.T) {
	for _, arc := range []string{DefaultArc, "1.3.6.1.4.1.32473.1"} {
		if _, err := New(arc); err != nil {
			t.Errorf("New(%q) error = %v", arc, err)
		}
	}
	for _, arc := range []string{"", "1", "1.3.foo", "1.3."} {
		if _, err := New(arc); err == nil {
			t.Errorf("New(%q) expected error", arc)
		}
	}
}

func TestFromResult(t *testing.T) {
	tree := mustTree(t)
	sw, _ := tree.Level(ar.LevelSoftware)
	hw, _ := tree.Level(ar.LevelHardware)
	tpm, _ := tree.Tee("tpm")
	snp, _ := tree.Tee("snp")

	tests := []struct {
		name   string
		result *ar.AttestationResult
		want   []x509.OID
	}{
		{"no attestation", nil, nil},
		{"level none", &ar.AttestationResult{AttestLevel: ar.LevelNone}, nil},
		{"software", &ar.AttestationResult{AttestLevel: ar.LevelSoftware,
			Measurements: []ar.MeasurementResult{{Type: ar.TYPE_RESULT_SW}}}, []x509.OID{sw}},
		{"tpm", &ar.AttestationResult{AttestLevel: ar.LevelHardware,
			Measurements: []ar.MeasurementResult{{Type: ar.TYPE_RESULT_TPM}, {Type: ar.TYPE_RESULT_IMA}}},
			[]x509.OID{hw, tpm}},
		{"azure snp", &ar.AttestationResult{AttestLevel: ar.LevelHardware,
			Measurements: []ar.MeasurementResult{{Type: ar.TYPE_RESULT_SNP}, {Type: ar.TYPE_RESULT_TPM}}},
			[]x509.OID{hw, tpm, snp}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tree.FromResult(tt.result)
			if !slices.EqualFunc(got, tt.want, x509.OID.Equal) {
				t.Errorf("FromResult() = %v, want %v", got, tt.want)
			}
		})
	}
}

type testCa struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func issue(t *testing.T, parent *testCa, isCa bool, policies []x509.OID) *testCa {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCa,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		Policies:              policies,
	}
	signerCert, signerKey := tmpl, crypto.Signer(key)
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, key.Public(), signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCa{cert: cert, key: key}
}

func TestCheck(t *testing.T) {
	tree := mustTree(t)
	hw, _ := tree.Level(ar.LevelHardware)
	sw, _ := tree.Level(ar.LevelSoftware)
	snp, _ := tree.Tee("snp")

	root := issue(t, nil, true, nil)
	hwLeaf := issue(t, root, false, []x509.OID{hw, snp}).cert
	swLeaf := issue(t, root, false, []x509.OID{sw}).cert
	noLeaf := issue(t, root, false, nil).cert
	otherLeaf := issue(t, root, false, []x509.OID{mustOid(t, "1.3.6.1.4.1.32473.1.1.2")}).cert

	tests := []struct {
		name    string
		cert    *x509.Certificate
		level   ar.AttestLevel
		wantErr bool
	}{
		{"level none", noLeaf, ar.LevelNone, false},
		{"hardware ok", hwLeaf, ar.LevelHardware, false},
		{"hardware satisfies software", hwLeaf, ar.LevelSoftware, false},
		{"software ok", swLeaf, ar.LevelSoftware, false},
		{"software is not hardware", swLeaf, ar.LevelHardware, true},
		{"no policies", noLeaf, ar.LevelSoftware, true},
		{"other arc", otherLeaf, ar.LevelSoftware, true},
		{"unknown level", hwLeaf, 3, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tree.Check(tt.cert, tt.level)
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyConnection(t *testing.T) {
	tree := mustTree(t)
	hw, _ := tree.Level(ar.LevelHardware)
	root := issue(t, nil, true, nil)
	leaf := issue(t, root, false, []x509.OID{hw}).cert

	if _, err := tree.VerifyConnection(-1); err == nil {
		t.Error("VerifyConnection() expected error for unknown level")
	}

	verify, err := tree.VerifyConnection(ar.LevelHardware)
	if err != nil {
		t.Fatalf("VerifyConnection() error = %v", err)
	}
	if err := verify(tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{leaf, root.cert}},
	}); err != nil {
		t.Errorf("verify() error = %v", err)
	}
	// Unverified peer certificates, e.g. with InsecureSkipVerify, must be rejected
	if err := verify(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}); err == nil {
		t.Error("verify() expected error for unverified chain")
	}
}

func mustOid(t *testing.T, s string) x509.OID {
	t.Helper()
	oid, err := x509.ParseOID(s)
	if err != nil {
		t.Fatal(err)
	}
	return oid
}
