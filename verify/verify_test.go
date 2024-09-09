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

package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/generate"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
)

// variables for Test_collectReferenceValues
var (
	vers = []ar.ReferenceValue{
		{Type: "TPM Reference Value", Name: "TPM1"},
		{Type: "TPM Reference Value", Name: "TPM2"},
		{Type: "SNP Reference Value", Name: "SNP1"},
		{Type: "SW Reference Value", Name: "SW1"},
		{Type: "SW Reference Value", Name: "SW2"},
	}

	verMap = map[string][]ar.ReferenceValue{
		"TPM Reference Value": vers[:2],
		"SNP Reference Value": {vers[2]},
		"SW Reference Value":  vers[3:],
	}

	rtmManifest = ar.RtmManifest{
		ReferenceValues: []ar.ReferenceValue{
			vers[0],
			vers[2],
		},
	}

	osManifest = ar.OsManifest{
		ReferenceValues: []ar.ReferenceValue{
			vers[1],
		},
	}

	appManifests = []ar.AppManifest{
		{ReferenceValues: []ar.ReferenceValue{vers[3]}},
		{ReferenceValues: []ar.ReferenceValue{vers[4]}},
	}
)

// variables for TestVerify
var (
	validRtmManifest = ar.RtmManifest{
		MetaInfo: ar.MetaInfo{
			Type:    "RTM Manifest",
			Name:    "de.test.rtm",
			Version: "2023-04-10T20:00:00Z",
		},
		DevCommonName: "Test Developer",
		Validity: ar.Validity{
			NotBefore: "2023-04-10T20:00:00Z",
			NotAfter:  "2030-04-10T20:00:00Z",
		},
		Description:        "de.test.rtm",
		CertificationLevel: 1,
	}

	validOsManifest = ar.OsManifest{
		MetaInfo: ar.MetaInfo{
			Type:    "OS Manifest",
			Name:    "de.test.os",
			Version: "2023-04-10T20:00:00Z",
		},
		DevCommonName: "Test Developer",
		Validity: ar.Validity{
			NotBefore: "2023-04-10T20:00:00Z",
			NotAfter:  "2030-04-10T20:00:00Z",
		},
		Description:        "PoC Fraunhofer AISEC Sample Report",
		CertificationLevel: 1,
		Rtms: []string{
			"de.test.rtm",
		},
	}

	incompatibleOsManifest = ar.OsManifest{
		MetaInfo: ar.MetaInfo{
			Type:    "OS Manifest",
			Name:    "de.test.os",
			Version: "2023-04-10T20:00:00Z",
		},
		DevCommonName: "Test Developer",
		Validity: ar.Validity{
			NotBefore: "2023-04-10T20:00:00Z",
			NotAfter:  "2030-04-10T20:00:00Z",
		},
		Description:        "PoC Fraunhofer AISEC Sample Report",
		CertificationLevel: 1,
		Rtms: []string{
			"INVALID",
		},
	}

	validDeviceDescription = ar.DeviceDescription{
		MetaInfo: ar.MetaInfo{
			Type:    "Device Description",
			Name:    "test-device.test.de",
			Version: "2023-04-10T20:00:00Z",
		},
		Location:    "Munich, Germany",
		RtmManifest: "de.test.rtm",
		OsManifest:  "de.test.os",
	}

	invalidDeviceDescription = ar.DeviceDescription{
		MetaInfo: ar.MetaInfo{
			Type:    "Device Description",
			Name:    "test-device.test.de",
			Version: "2023-04-10T20:00:00Z",
		},
		Location:    "Munich, Germany",
		RtmManifest: "INVALID",
		OsManifest:  "INVALID",
	}

	nonce = []byte{0x01, 0x02, 0x03}
)

type SwSigner struct {
	certChain []*x509.Certificate
	priv      crypto.PrivateKey
}

func (s *SwSigner) Init(c *ar.DriverConfig) error {
	return nil
}

func (s *SwSigner) Measure(nonce []byte) (ar.Measurement, error) {
	return ar.Measurement{}, nil
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

func Test_collectReferenceValues(t *testing.T) {
	type args struct {
		metadata *ar.Metadata
	}
	tests := []struct {
		name    string
		args    args
		want    map[string][]ar.ReferenceValue
		wantErr bool
	}{
		{
			name: "Success",
			args: args{
				metadata: &ar.Metadata{
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
			got, err := collectReferenceValues(tt.args.metadata)
			if (err != nil) != tt.wantErr {
				t.Errorf("collectReferenceValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for wantedkey, wantedrefvals := range tt.want {
				for _, wantedrefval := range wantedrefvals {
					found := false
					for _, gotrefval := range got[wantedkey] {
						if gotrefval.Name == wantedrefval.Name {
							found = true
						}
					}
					if !found {
						t.Errorf("collectReferenceValues() failed to find %v", wantedrefval.Name)
					}
				}
			}
		})
	}
}

func TestVerify(t *testing.T) {
	logrus.SetLevel(logrus.TraceLevel)

	type args struct {
		serializer        ar.Serializer
		rtmManifest       ar.RtmManifest
		osManifest        ar.OsManifest
		deviceDescription ar.DeviceDescription
		nonce             []byte
	}
	tests := []struct {
		name string
		args args
		want ar.VerificationResult
	}{
		{
			name: "Valid Report JSON",
			args: args{
				serializer:        ar.JsonSerializer{},
				rtmManifest:       validRtmManifest,
				osManifest:        validOsManifest,
				deviceDescription: validDeviceDescription,
				nonce:             nonce,
			},
			want: ar.VerificationResult{Success: true},
		},
		{
			name: "Valid Report CBOR",
			args: args{
				serializer:        ar.CborSerializer{},
				rtmManifest:       validRtmManifest,
				osManifest:        validOsManifest,
				deviceDescription: validDeviceDescription,
				nonce:             nonce,
			},
			want: ar.VerificationResult{Success: true},
		},
		{
			// expected aggregated CertificationLevel in Manifests for
			// empty measurement is max. 1 (here CertificationLevel = 3)
			name: "Invalid Certification Level",
			args: args{
				serializer: ar.JsonSerializer{},
				rtmManifest: ar.RtmManifest{
					MetaInfo: ar.MetaInfo{
						Type:    "RTM Manifest",
						Name:    "de.test.rtm",
						Version: "2023-04-10T20:00:00Z",
					},
					DevCommonName: "Test Developer",
					Validity: ar.Validity{
						NotBefore: "2023-04-10T20:00:00Z",
						NotAfter:  "2026-04-10T20:00:00Z",
					},
					Description:        "de.test.rtm",
					CertificationLevel: 3,
					ReferenceValues:    []ar.ReferenceValue{},
				},
				osManifest: ar.OsManifest{
					MetaInfo: ar.MetaInfo{
						Type:    "OS Manifest",
						Name:    "de.test.os",
						Version: "2023-04-10T20:00:00Z",
					},
					DevCommonName: "Test Developer",
					Validity: ar.Validity{
						NotBefore: "2023-04-10T20:00:00Z",
						NotAfter:  "2026-04-10T20:00:00Z",
					},
					Description:        "PoC Fraunhofer AISEC Sample Report",
					CertificationLevel: 3,
					Rtms: []string{
						"de.test.rtm",
					},
				},
				deviceDescription: validDeviceDescription,
				nonce:             nonce,
			},
			want: ar.VerificationResult{Success: false},
		},
		{
			name: "Invalid Device Description",
			args: args{
				serializer:        ar.JsonSerializer{},
				rtmManifest:       validRtmManifest,
				osManifest:        validOsManifest,
				deviceDescription: invalidDeviceDescription,
				nonce:             nonce,
			},
			want: ar.VerificationResult{Success: false},
		},
		{
			name: "Incompatible RTM/OS Manifests",
			args: args{
				serializer:        ar.JsonSerializer{},
				rtmManifest:       validRtmManifest,
				osManifest:        incompatibleOsManifest,
				deviceDescription: validDeviceDescription,
				nonce:             nonce,
			},
			want: ar.VerificationResult{Success: false},
		},
	}

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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.args.serializer

			// Preparation: Generate a Sample Report
			log.Trace("Generating a Sample Report")

			ar := ar.AttestationReport{
				Type: "Attestation Report",
			}

			// Preparation: create signed manifests and deviceDescription
			rtmManifest, err := s.Marshal(tt.args.rtmManifest)
			if err != nil {
				t.Errorf("failed to marshal the RtmManifest: %v", err)
			}
			osManifest, err := s.Marshal(tt.args.osManifest)
			if err != nil {
				t.Errorf("failed to marshal the OsManifest: %v", err)
			}
			deviceDescription, err := s.Marshal(tt.args.deviceDescription)
			if err != nil {
				t.Errorf("failed to marshal the DeviceDescription: %v", err)
			}
			ar.RtmManifest, err = generate.Sign(rtmManifest, swSigner, s)
			if err != nil {
				t.Errorf("failed to sign the RtmManifest: %v", err)
			}
			ar.OsManifest, err = generate.Sign(osManifest, swSigner, s)
			if err != nil {
				t.Errorf("failed to sign the OsManifest: %v", err)
			}
			ar.DeviceDescription, err = generate.Sign(deviceDescription, swSigner, s)
			if err != nil {
				t.Errorf("failed to sign the DeviceDescription: %v", err)
			}

			report, err := s.Marshal(ar)
			if err != nil {
				t.Errorf("failed to marshal the Attestation Report: %v", err)
			}

			// Preparation: Sign the report
			arSigned, err := generate.Sign(report, swSigner, s)
			if err != nil {
				t.Errorf("Internal Error: Failed to sign Attestion Report: %v", err)
			}

			// Run FUT
			got := Verify(
				arSigned, nonce,
				internal.WriteCertPem(certchain[len(certchain)-1]),
				nil, 0, "")
			if got.Success != tt.want.Success {
				t.Errorf("Result.Success = %v, want %v", got.Success, tt.want.Success)
			}
			fmt.Println(got)
		})
	}
}
