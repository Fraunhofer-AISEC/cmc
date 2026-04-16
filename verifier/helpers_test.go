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

package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

func TestVerifyNonce(t *testing.T) {
	tests := []struct {
		name       string
		measured   []byte
		expected   []byte
		wantStatus ar.Status
	}{
		{
			"matching nonces",
			[]byte{1, 2, 3, 4},
			[]byte{1, 2, 3, 4},
			ar.StatusSuccess,
		},
		{
			"mismatched nonces",
			[]byte{1, 2, 3, 4},
			[]byte{5, 6, 7, 8},
			ar.StatusFail,
		},
		{
			"both empty",
			[]byte{},
			[]byte{},
			ar.StatusSuccess,
		},
		{
			"both nil",
			nil,
			nil,
			ar.StatusSuccess,
		},
		{
			"different lengths",
			[]byte{1, 2, 3},
			[]byte{1, 2, 3, 4},
			ar.StatusFail,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifyNonce(tt.measured, tt.expected)
			if result.Status != tt.wantStatus {
				t.Errorf("verifyNonce() Status = %v, want %v", result.Status, tt.wantStatus)
			}
			if tt.wantStatus == ar.StatusFail {
				if result.Expected == "" || result.Got == "" {
					t.Error("on failure, Expected and Got should be populated")
				}
				if result.Expected != hex.EncodeToString(tt.expected) {
					t.Errorf("Expected = %q, want %q", result.Expected, hex.EncodeToString(tt.expected))
				}
				if result.Got != hex.EncodeToString(tt.measured) {
					t.Errorf("Got = %q, want %q", result.Got, hex.EncodeToString(tt.measured))
				}
			}
			if tt.wantStatus == ar.StatusSuccess {
				if result.Got != hex.EncodeToString(tt.expected) {
					t.Errorf("on success, Got = %q, want %q", result.Got, hex.EncodeToString(tt.expected))
				}
			}
		})
	}
}

// generateSelfSignedCert creates a self-signed certificate for testing.
func generateSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDer, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

func TestVerifyCaFingerprint(t *testing.T) {
	cert := generateSelfSignedCert(t)
	fingerprint := sha256.Sum256(cert.Raw)
	correctFp := hex.EncodeToString(fingerprint[:])
	wrongFp := hex.EncodeToString(make([]byte, 32))

	tests := []struct {
		name         string
		fingerprints []string
		wantStatus   ar.Status
	}{
		{
			name:         "matching fingerprint",
			fingerprints: []string{correctFp},
			wantStatus:   ar.StatusSuccess,
		},
		{
			name:         "match on second fingerprint",
			fingerprints: []string{wrongFp, correctFp},
			wantStatus:   ar.StatusSuccess,
		},
		{
			name:         "no matching fingerprint",
			fingerprints: []string{wrongFp},
			wantStatus:   ar.StatusFail,
		},
		{
			name:         "empty fingerprint list",
			fingerprints: []string{},
			wantStatus:   ar.StatusFail,
		},
		{
			name:         "invalid hex fingerprint",
			fingerprints: []string{"not-valid-hex"},
			wantStatus:   ar.StatusFail,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifyCaFingerprint(cert, tt.fingerprints)
			if result.Status != tt.wantStatus {
				t.Errorf("verifyCaFingerprint() Status = %v, want %v", result.Status, tt.wantStatus)
			}
		})
	}
}
