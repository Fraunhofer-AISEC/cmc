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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	testCA   []byte
	testCert []byte
	testKey  *ecdsa.PrivateKey
	nonce    []byte
)

type SwSigner struct {
	certChain CertChain
	priv      crypto.PrivateKey
}

func (s *SwSigner) Lock() {}

func (s *SwSigner) Unlock() {}

func (s *SwSigner) GetSigningKeys() (crypto.PrivateKey, crypto.PublicKey, error) {
	return s.priv, &s.priv.(*ecdsa.PrivateKey).PublicKey, nil
}

func (s *SwSigner) GetCertChain() CertChain {
	return s.certChain
}

func createCertsAndKeys() error {

	// Generate private key and public key for test CA
	caPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

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
		return fmt.Errorf("Failed to create certificate: %v", err)
	}
	tmp := &bytes.Buffer{}
	pem.Encode(tmp, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	testCA = tmp.Bytes()

	// Generate private key and certificate for test prover, signed by test CA
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	testKey = priv

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
		return fmt.Errorf("Failed to create certificate: %v", err)
	}
	tmp = &bytes.Buffer{}
	pem.Encode(tmp, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	testCert = tmp.Bytes()

	// Create Nonce
	nonce = make([]byte, 8)
	rand.Read(nonce)

	return nil
}

func TestVerify(t *testing.T) {
	type args struct {
		nonce      *[]byte
		caCertPem  *[]byte
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
				nonce:      &nonce,
				caCertPem:  &testCA,
				serializer: JsonSerializer{},
			},
			want: VerificationResult{Success: false},
		},
		{
			name: "Empty Attestation Report CBOR",
			args: args{
				nonce:      &nonce,
				caCertPem:  &testCA,
				serializer: CborSerializer{},
			},
			want: VerificationResult{Success: false},
		},
	}

	// Setup logger
	log.SetLevel(log.TraceLevel)

	// Setup Test Keys and Certificates
	log.Trace("Creating Keys and Certificates")
	if err := createCertsAndKeys(); err != nil {
		log.Errorf("Internal Error: Failed to create testing certs and keys: %v", err)
		return
	}

	swSigner := &SwSigner{
		priv: testKey,
		certChain: CertChain{
			Leaf: testCert,
			Ca:   testCA,
		},
	}

	// Perform unit tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Generate and sign attestation report to test Verify() function
			var metadata [][]byte
			a, err := Generate(nonce, metadata, []Measurement{}, tt.args.serializer)
			if err != nil {
				t.Errorf("Preparation failed: %v", err)
			}
			ok, ar := Sign(a, swSigner, tt.args.serializer)
			if !ok {
				t.Error("Internal Error: Failed to sign Attestion Report")
				return
			}

			got := Verify(string(ar), *tt.args.nonce, *tt.args.caCertPem, nil, tt.args.serializer)
			if got.Success != tt.want.Success {
				t.Errorf("Result.Success = %v, want %v", got.Success, tt.want.Success)
			}
		})
	}
}

var (
	vers = []Verification{
		{Type: "TPM Verification", Name: "TPM1"},
		{Type: "TPM Verification", Name: "TPM2"},
		{Type: "SNP Verification", Name: "SNP1"},
		{Type: "SW Verification", Name: "SW1"},
		{Type: "SW Verification", Name: "SW2"},
	}

	verMap = map[string][]Verification{
		"TPM Verification": vers[:2],
		"SNP Verification": {vers[2]},
		"SW Verification":  vers[3:],
	}

	rtmManifest = RtmManifest{
		Verifications: []Verification{
			vers[0],
			vers[2],
		},
	}

	osManifest = OsManifest{
		Verifications: []Verification{
			vers[1],
		},
	}

	appManifests = []AppManifest{
		{Verifications: []Verification{vers[3]}},
		{Verifications: []Verification{vers[4]}},
	}
)

func Test_collectVerifications(t *testing.T) {
	type args struct {
		ar *ArPlain
	}
	tests := []struct {
		name    string
		args    args
		want    map[string][]Verification
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
			got, err := collectVerifications(tt.args.ar)
			if (err != nil) != tt.wantErr {
				t.Errorf("collectVerifications() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("collectVerifications() = %v, want %v", got, tt.want)
			}
		})
	}
}
