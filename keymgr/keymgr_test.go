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

package keymgr

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"path"
	"testing"

	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision/est"
)

// fakeDriver provides empty evidence, which suffices to generate a report
type fakeDriver struct{}

func (fakeDriver) Init(*drivers.DriverConfig) error          { return nil }
func (fakeDriver) GetEvidence([]byte) ([]ar.Evidence, error) { return nil, nil }
func (fakeDriver) GetCollateral() ([]ar.Collateral, error)   { return nil, nil }
func (fakeDriver) Name() string                              { return "fake" }
func (fakeDriver) UpdateCerts() error                        { return nil }

// fakeEnroller creates the CSR with its nonce and returns a fixed chain
type fakeEnroller struct {
	nonce []byte
	csr   *x509.CertificateRequest
	chain []*x509.Certificate
}

func (e *fakeEnroller) Enroll(createCsr CsrFunc) ([]*x509.Certificate, error) {
	csr, err := createCsr(e.nonce)
	if err != nil {
		return nil, err
	}
	e.csr = csr
	return e.chain, nil
}

func TestEnrollKey(t *testing.T) {

	s, err := ar.NewJsonSerializer()
	if err != nil {
		t.Fatalf("failed to create serializer: %v", err)
	}

	for _, tt := range []struct {
		name        string
		attestation bool
		nonce       []byte
	}{
		{"no attestation", false, nil},
		{"attestation without nonce", true, nil},
		{"attestation with nonce", true, []byte("enroller nonce")},
	} {
		t.Run(tt.name, func(t *testing.T) {

			chain := []*x509.Certificate{{Raw: []byte("leaf")}, {Raw: []byte("ca")}}
			enroller := &fakeEnroller{nonce: tt.nonce, chain: chain}

			dir := t.TempDir()
			mgr, err := NewKeyMgr(dir, nil, enroller, false)
			if err != nil {
				t.Fatalf("failed to create key manager: %v", err)
			}

			keyId, err := mgr.EnrollKey(&KeyEnrollmentParams{
				KeyConfig: api.TLSKeyConfig{
					Type: "sw", Alg: "ec256", Cn: "test", DNSNames: []string{"localhost"},
				},
				Attest:     tt.attestation,
				Drivers:    []drivers.Driver{fakeDriver{}},
				Serializer: s,
				ArHashAlg:  crypto.SHA256,
			})
			if err != nil {
				t.Fatalf("failed to enroll key: %v", err)
			}

			att, err := est.ParseCsrAttestation(enroller.csr)
			if err != nil {
				t.Fatalf("failed to parse CSR attestation: %v", err)
			}

			if !tt.attestation {
				if att != nil && att.Report != nil {
					t.Fatalf("CSR contains a report without attestation")
				}
			} else {
				if att == nil || att.Report == nil {
					t.Fatalf("CSR contains no report")
				}
				var report ar.AttestationReport
				if err := s.Unmarshal(att.Report, &report); err != nil {
					t.Fatalf("failed to unmarshal report: %v", err)
				}
				spki, err := x509.MarshalPKIXPublicKey(enroller.csr.PublicKey)
				if err != nil {
					t.Fatalf("failed to marshal public key: %v", err)
				}
				want := sha256.Sum256(append(spki, tt.nonce...))
				if !bytes.Equal(report.Context.Nonce, want[:]) {
					t.Errorf("report nonce %x, want %x", report.Context.Nonce, want)
				}
			}

			// The returned chain is kept in memory and stored persistently
			got, err := mgr.GetCertChain(keyId)
			if err != nil {
				t.Fatalf("failed to get cert chain: %v", err)
			}
			if len(got) != len(chain) || !bytes.Equal(got[0].Raw, chain[0].Raw) {
				t.Errorf("cert chain not stored in memory")
			}
			stored, err := os.ReadFile(path.Join(dir, "certs", keyId))
			if err != nil {
				t.Fatalf("failed to read stored certs: %v", err)
			}
			if !bytes.Equal(stored, internal.WriteCertsPemBlob(chain)) {
				t.Errorf("stored cert chain does not match")
			}
		})
	}
}
