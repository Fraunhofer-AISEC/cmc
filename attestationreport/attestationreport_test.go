// Copyright (c) 2021 Fraunhofer AISEC
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

package attestationreport

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
)

var (
	vers = []ReferenceValue{
		{Type: "TPM Reference Value", Name: "TPM1"},
		{Type: "TPM Reference Value", Name: "TPM2"},
		{Type: "SNP Reference Value", Name: "SNP1"},
		{Type: "SW Reference Value", Name: "SW1"},
		{Type: "SW Reference Value", Name: "SW2"},
	}

	verMap = map[string][]ReferenceValue{
		"TPM Reference Value": vers[:2],
		"SNP Reference Value": {vers[2]},
		"SW Reference Value":  vers[3:],
	}

	rtmManifest = RtmManifest{
		ReferenceValues: []ReferenceValue{
			vers[0],
			vers[2],
		},
	}

	osManifest = OsManifest{
		ReferenceValues: []ReferenceValue{
			vers[1],
		},
	}

	appManifests = []AppManifest{
		{ReferenceValues: []ReferenceValue{vers[3]}},
		{ReferenceValues: []ReferenceValue{vers[4]}},
	}
)

type SwSigner struct {
	certChain []*x509.Certificate
	priv      crypto.PrivateKey
}

func (s *SwSigner) Init(c *DriverConfig) error {
	return nil
}

func (s *SwSigner) Measure(nonce []byte) (Measurement, error) {
	return nil, nil
}

func (s *SwSigner) Lock() error {
	return nil
}

func (s *SwSigner) Unlock() error {
	return nil
}

func (s *SwSigner) GetSigningKeys() (crypto.PrivateKey, crypto.PublicKey, error) {
	return s.priv, &s.priv.(*ecdsa.PrivateKey).PublicKey, nil
}

func (s *SwSigner) GetCertChain() ([]*x509.Certificate, error) {
	return s.certChain, nil
}

func createCertsAndKeys() (*ecdsa.PrivateKey, []*x509.Certificate, error) {

	// Generate private key and public key for test CA
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	caTmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA Cert",
			Country:      []string{"DE"},
			Province:     []string{"BY"},
			Locality:     []string{"Munich"},
			Organization: []string{"Test Company"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &caTmpl, &caTmpl, &caPriv.PublicKey, caPriv)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create certificate: %w", err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse certificate: %w", err)
	}

	// Generate private key and certificate for test prover, signed by test CA
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Key Cert",
			Country:      []string{"DE"},
			Province:     []string{"BY"},
			Locality:     []string{"Munich"},
			Organization: []string{"Test Company"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err = x509.CreateCertificate(rand.Reader, &tmpl, &caTmpl, &priv.PublicKey, caPriv)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse certificate: %w", err)
	}

	return priv, []*x509.Certificate{leaf, ca}, nil
}

func TestVerify(t *testing.T) {
	type args struct {
		serializer Serializer
	}
	tests := []struct {
		name string
		args args
		want VerificationResult
	}{
		{
			name: "Empty Attestation Report JSON",
			args: args{
				serializer: JsonSerializer{},
			},
			want: VerificationResult{Success: false},
		},
		{
			name: "Empty Attestation Report CBOR",
			args: args{
				serializer: CborSerializer{},
			},
			want: VerificationResult{Success: false},
		},
	}

	// Setup logger
	logrus.SetLevel(logrus.TraceLevel)

	// Setup Test Keys and Certificates
	log.Trace("Creating Keys and Certificates")
	key, certchain, err := createCertsAndKeys()
	if err != nil {
		log.Errorf("Internal Error: Failed to create testing certs and keys: %v", err)
		return
	}

	swSigner := &SwSigner{
		priv:      key,
		certChain: certchain,
	}

	// Perform unit tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Preparation: Create nonce
			nonce := make([]byte, 8)
			rand.Read(nonce)

			// Preparation: Generate and sign attestation report
			var metadata [][]byte
			a, err := Generate(nonce, metadata, []Driver{}, tt.args.serializer)
			if err != nil {
				t.Errorf("Preparation failed: %v", err)
			}
			ar, err := Sign(a, swSigner, tt.args.serializer)
			if err != nil {
				t.Errorf("Internal Error: Failed to sign Attestion Report: %v", err)
			}

			// Run FUT
			got := Verify(
				ar, nonce,
				internal.WriteCertPem(certchain[len(certchain)-1]),
				nil, 0)
			if got.Success != tt.want.Success {
				t.Errorf("Result.Success = %v, want %v", got.Success, tt.want.Success)
			}
		})
	}
}

func Test_collectReferenceValues(t *testing.T) {
	type args struct {
		ar *ArPlain
	}
	tests := []struct {
		name    string
		args    args
		want    map[string][]ReferenceValue
		wantErr bool
	}{
		{
			name: "Success",
			args: args{
				ar: &ArPlain{
					RtmManifest:  rtmManifest,
					OsManifest:   osManifest,
					AppManifests: appManifests,
				},
			},
			want:    verMap,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := collectReferenceValues(tt.args.ar)
			if (err != nil) != tt.wantErr {
				t.Errorf("collectReferenceValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("collectReferenceValues() = %v, want %v", got, tt.want)
			}
		})
	}
}
