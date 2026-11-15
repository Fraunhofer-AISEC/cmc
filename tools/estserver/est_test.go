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
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"testing"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/certpolicy"
	"github.com/Fraunhofer-AISEC/cmc/internal"
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
		ekus         []x509.ExtKeyUsage
		policies     []x509.OID
		wantPolicies []x509.OID
	}{
		{"simpleenroll", internal.TlsExtKeyUsage, nil, nil},
		{"tpmactivateenroll", nil, nil, nil},
		{"attestenroll azure tdx", internal.TlsExtKeyUsage, tree.FromResult(&ar.AttestationResult{
			AttestLevel:  ar.LevelHardware,
			Measurements: []ar.MeasurementResult{{Type: ar.TYPE_RESULT_TDX}, {Type: ar.TYPE_RESULT_TPM}},
		}), []x509.OID{hw, tpm, tdx}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csr := makeCSR(t, pkix.Name{CommonName: "leaf"}, nil, nil, nil)
			cert, err := enrollCert(csr, caKey, ca, CsrPassthrough{}, nil, 0, tt.ekus, tt.policies)
			if err != nil {
				t.Fatalf("enrollCert() error = %v", err)
			}
			if !slices.Equal(cert.ExtKeyUsage, tt.ekus) {
				t.Errorf("ExtKeyUsage = %v, want %v", cert.ExtKeyUsage, tt.ekus)
			}
			if !slices.EqualFunc(cert.Policies, tt.wantPolicies, x509.OID.Equal) {
				t.Errorf("Policies = %v, want %v", cert.Policies, tt.wantPolicies)
			}
		})
	}
}
