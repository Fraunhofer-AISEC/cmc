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

package verifier

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/prover"
	"github.com/sirupsen/logrus"
)

// variables for Test_collectReferenceValues
var (
	refs = []ar.ReferenceValue{
		{Type: "TPM Reference Value", Name: "TPM1"},
		{Type: "TPM Reference Value", Name: "TPM2"},
		{Type: "SNP Reference Value", Name: "SNP1"},
		{Type: "SW Reference Value", Name: "SW1"},
		{Type: "SW Reference Value", Name: "SW2"},
	}

	refMap = map[string][]ar.ReferenceValue{
		"TPM Reference Value": refs[:2],
		"SNP Reference Value": {refs[2]},
		"SW Reference Value":  refs[3:],
	}

	rtmManifest = ar.MetadataResult{
		Metadata: ar.Metadata{
			Manifest: ar.Manifest{
				ReferenceValues: []ar.ReferenceValue{
					refs[0],
					refs[2],
				},
			},
		},
	}

	osManifest = ar.MetadataResult{
		Metadata: ar.Metadata{
			Manifest: ar.Manifest{
				ReferenceValues: []ar.ReferenceValue{
					refs[1],
				},
			},
		},
	}

	appManifest1 = ar.MetadataResult{
		Metadata: ar.Metadata{
			Manifest: ar.Manifest{
				ReferenceValues: []ar.ReferenceValue{refs[3]},
			},
		},
	}

	appManifest2 = ar.MetadataResult{
		Metadata: ar.Metadata{
			Manifest: ar.Manifest{
				ReferenceValues: []ar.ReferenceValue{refs[4]},
			},
		},
	}
)

// variables for TestVerify & Test_checkMetadataCompatibility
var (
	validCompanyDescription = ar.Metadata{
		MetaInfo: ar.MetaInfo{
			Type: "Company Description",
			Name: "Test Company Description",
		},
	}

	validRtmManifestDescription = ar.ManifestDescription{
		Type:     "Manifest Description",
		Name:     " Test RTM Manifest Description",
		Manifest: "de.test.rtm",
	}

	validOsManifestDescription = ar.ManifestDescription{
		Type:     "Manifest Description",
		Name:     " Test OS Manifest Description",
		Manifest: "de.test.os",
	}

	validAppManifestDescription = ar.ManifestDescription{
		Type:     "Manifest Description",
		Name:     " Test App Manifest Description 1",
		Manifest: "de.test.app",
	}

	successCompatibilityResult = &ar.CompatibilityResult{
		Summary: ar.Result{
			Success: true,
		},
	}

	failedCompatibilityResult = &ar.CompatibilityResult{
		Summary: ar.Result{
			Success: false,
		},
	}

	validRtmManifest = ar.Metadata{
		MetaInfo: ar.MetaInfo{
			Type:    "Manifest",
			Name:    "de.test.rtm",
			Version: "2023-04-10T20:00:00Z",
			Validity: ar.Validity{
				NotBefore: "2023-04-10T20:00:00Z",
				NotAfter:  "2030-04-10T20:00:00Z",
			},
			Description: "de.test.rtm",
		},
		Manifest: ar.Manifest{
			DevCommonName: "Test Developer",
			CertLevel:     1,
			BaseLayers:    []string{"de.test.rtm"},
		},
	}

	validOsManifest = ar.Metadata{
		MetaInfo: ar.MetaInfo{
			Type:    "Manifest",
			Name:    "de.test.os",
			Version: "2023-04-10T20:00:00Z",
			Validity: ar.Validity{
				NotBefore: "2023-04-10T20:00:00Z",
				NotAfter:  "2030-04-10T20:00:00Z",
			},
			Description: "PoC Fraunhofer AISEC Sample Report",
		},
		Manifest: ar.Manifest{
			DevCommonName: "Test Developer",
			BaseLayers: []string{
				"de.test.rtm",
			},
			CertLevel: 1,
		},
	}

	validAppManifest = ar.Metadata{
		MetaInfo: ar.MetaInfo{
			Type:    "Manifest",
			Name:    "de.test.app",
			Version: "2023-04-10T20:00:00Z",
			Validity: ar.Validity{
				NotBefore: "2023-04-10T20:00:00Z",
				NotAfter:  "2030-04-10T20:00:00Z",
			},
			Description: "PoC Fraunhofer AISEC Sample Report",
		},
		Manifest: ar.Manifest{
			DevCommonName: "Test Developer",
			BaseLayers: []string{
				"de.test.os",
			},
			CertLevel: 1,
		},
	}

	incompatibleOsManifest = ar.Metadata{
		MetaInfo: ar.MetaInfo{
			Type:    "Manifest",
			Name:    "de.test.os",
			Version: "2023-04-10T20:00:00Z",
			Validity: ar.Validity{
				NotBefore: "2023-04-10T20:00:00Z",
				NotAfter:  "2030-04-10T20:00:00Z",
			},
			Description: "PoC Fraunhofer AISEC Sample Report",
		},
		Manifest: ar.Manifest{
			DevCommonName: "Test Developer",
			BaseLayers: []string{
				"INVALID",
			},
			CertLevel: 1,
		},
	}

	validMetaInfo = ar.MetaInfo{
		Type:    "Device Description",
		Name:    "test-device.test.de",
		Version: "2023-04-10T20:00:00Z",
		Validity: ar.Validity{
			NotBefore: "2023-04-10T20:00:00Z",
			NotAfter:  "2030-04-10T20:00:00Z",
		},
	}

	validDeviceDescription = ar.Metadata{
		MetaInfo: validMetaInfo,
		DeviceDescription: ar.DeviceDescription{
			Location: "Munich, Germany",
			Descriptions: []ar.ManifestDescription{
				validRtmManifestDescription,
				validOsManifestDescription,
				validAppManifestDescription,
			},
		},
	}

	incompleteDeviceDescription = ar.Metadata{
		MetaInfo: validMetaInfo,
		DeviceDescription: ar.DeviceDescription{
			Location: "Munich, Germany",
			Descriptions: []ar.ManifestDescription{
				validRtmManifestDescription,
				validOsManifestDescription,
			},
		},
	}

	invalidDeviceDescription = ar.Metadata{
		MetaInfo: ar.MetaInfo{
			Type:    "Device Description",
			Name:    "test-device.test.de",
			Version: "2023-04-10T20:00:00Z",
		},
		DeviceDescription: ar.DeviceDescription{
			Location: "Munich, Germany",
			Descriptions: []ar.ManifestDescription{
				validRtmManifestDescription,
				validOsManifestDescription,
				validAppManifestDescription,
			},
		},
	}
)

// Variables for TestVerify
var (
	nonce = []byte{0x01, 0x02, 0x03}
)

// Variables for Test_checkMetadataCompatibility
var (
	validDevDescResult = ar.MetadataResult{
		Metadata: validDeviceDescription,
	}

	incompleteDevDescResult = ar.MetadataResult{
		Metadata: incompleteDeviceDescription,
	}

	validCompDescResult = &ar.MetadataResult{
		Metadata: validCompanyDescription,
	}

	validRtmResult = ar.MetadataResult{
		Metadata: validRtmManifest,
	}

	validOsResult = ar.MetadataResult{
		Metadata: validOsManifest,
	}

	validAppResult = ar.MetadataResult{
		Metadata: validAppManifest,
	}

	validMetadata = &ar.MetadataSummary{
		DevDescResult:  validDevDescResult,
		CompDescResult: validCompDescResult,
		ManifestResults: []ar.MetadataResult{
			validRtmResult,
			validOsResult,
			validAppResult,
		},
	}

	noRootManifestMetadata = &ar.MetadataSummary{
		DevDescResult:  validDevDescResult,
		CompDescResult: validCompDescResult,
		ManifestResults: []ar.MetadataResult{
			validOsResult,
			validAppResult,
		},
	}

	multipleRootManifestMetadata = &ar.MetadataSummary{
		DevDescResult:  validDevDescResult,
		CompDescResult: validCompDescResult,
		ManifestResults: []ar.MetadataResult{
			validRtmResult,
			validRtmResult,
			validOsResult,
			validAppResult,
		},
	}

	missingManifestMetadata = &ar.MetadataSummary{
		DevDescResult:  validDevDescResult,
		CompDescResult: validCompDescResult,
		ManifestResults: []ar.MetadataResult{
			validRtmResult,
			validOsResult,
		},
	}

	missingDescriptionMetadata = &ar.MetadataSummary{
		DevDescResult:  incompleteDevDescResult,
		CompDescResult: validCompDescResult,
		ManifestResults: []ar.MetadataResult{
			validRtmResult,
			validOsResult,
			validAppResult,
		},
	}
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

func (s *SwSigner) GetKeyHandles(sel ar.KeySelection) (crypto.PrivateKey, crypto.PublicKey, error) {
	return s.priv, &s.priv.(*ecdsa.PrivateKey).PublicKey, nil
}

func (s *SwSigner) GetCertChain(sel ar.KeySelection) ([]*x509.Certificate, error) {
	return s.certChain, nil
}

func (s *SwSigner) Name() string {
	return "SW Driver"
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
		metadata []ar.MetadataResult
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
				metadata: []ar.MetadataResult{
					rtmManifest,
					osManifest,
					appManifest1,
					appManifest2,
				},
			},
			want:    refMap,
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
		rtmManifest       ar.Metadata
		osManifest        ar.Metadata
		appManifest       ar.Metadata
		deviceDescription ar.Metadata
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
				appManifest:       validAppManifest,
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
				appManifest:       validAppManifest,
				deviceDescription: validDeviceDescription,
				nonce:             nonce,
			},
			want: ar.VerificationResult{Success: true},
		},
		{
			// expected aggregated certification level in Manifests for
			// empty measurement is max. 1 (here certification level = 3)
			name: "Invalid Certification Level",
			args: args{
				serializer: ar.JsonSerializer{},
				rtmManifest: ar.Metadata{
					MetaInfo: ar.MetaInfo{
						Type:    "Manifest",
						Name:    "de.test.rtm",
						Version: "2023-04-10T20:00:00Z",
						Validity: ar.Validity{
							NotBefore: "2023-04-10T20:00:00Z",
							NotAfter:  "2026-04-10T20:00:00Z",
						},
						Description: "de.test.rtm",
					},
					Manifest: ar.Manifest{
						DevCommonName:   "Test Developer",
						ReferenceValues: []ar.ReferenceValue{},
						CertLevel:       3,
					},
				},
				osManifest: ar.Metadata{
					MetaInfo: ar.MetaInfo{
						Type:    "Manifest",
						Name:    "de.test.os",
						Version: "2023-04-10T20:00:00Z",
						Validity: ar.Validity{
							NotBefore: "2023-04-10T20:00:00Z",
							NotAfter:  "2026-04-10T20:00:00Z",
						},
						Description: "PoC Fraunhofer AISEC Sample Report",
					},
					Manifest: ar.Manifest{
						DevCommonName: "Test Developer",
						BaseLayers: []string{
							"de.test.rtm",
						},
						CertLevel: 3,
					},
				},
				appManifest:       validAppManifest,
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
				appManifest:       validAppManifest,
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
				appManifest:       validAppManifest,
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

			// Preparation: create signed manifests and deviceDescription
			rtmManifest, err := s.Marshal(tt.args.rtmManifest)
			if err != nil {
				t.Errorf("failed to marshal the RTM Manifest: %v", err)
			}
			osManifest, err := s.Marshal(tt.args.osManifest)
			if err != nil {
				t.Errorf("failed to marshal the OS Manifest: %v", err)
			}
			appManifest, err := s.Marshal(tt.args.appManifest)
			if err != nil {
				t.Errorf("failed to marshal the App Manifest: %v", err)
			}
			deviceDescription, err := s.Marshal(tt.args.deviceDescription)
			if err != nil {
				t.Errorf("failed to marshal the DeviceDescription: %v", err)
			}

			rtmManifest, err = prover.Sign(rtmManifest, swSigner, s, ar.IK)
			if err != nil {
				t.Errorf("failed to sign the RTM Manifest: %v", err)
			}
			osManifest, err = prover.Sign(osManifest, swSigner, s, ar.IK)
			if err != nil {
				t.Errorf("failed to sign the OS Manifest: %v", err)
			}
			appManifest, err = prover.Sign(appManifest, swSigner, s, ar.IK)
			if err != nil {
				t.Errorf("failed to sign the App Manifest: %v", err)
			}
			deviceDescription, err = prover.Sign(deviceDescription, swSigner, s, ar.IK)
			if err != nil {
				t.Errorf("failed to sign the DeviceDescription: %v", err)
			}

			rtmDigest := sha256.Sum256(rtmManifest)
			rtmManifestDigest := ar.MetadataDigest{
				Type:   "Manifest",
				Digest: rtmDigest[:],
			}

			osDigest := sha256.Sum256(osManifest)
			osManifestDigest := ar.MetadataDigest{
				Type:   "Manifest",
				Digest: osDigest[:],
			}

			appDigest := sha256.Sum256(appManifest)
			appManifestDigest := ar.MetadataDigest{
				Type:   "Manifest",
				Digest: appDigest[:],
			}

			deviceDigest := sha256.Sum256(deviceDescription)
			deviceDescriptionDigest := ar.MetadataDigest{
				Type:   "Manifest",
				Digest: deviceDigest[:],
			}

			report := ar.AttestationReport{
				Type:    "Attestation Report",
				Version: "1.0.0",
				Metadata: []ar.MetadataDigest{
					rtmManifestDigest, osManifestDigest, appManifestDigest, deviceDescriptionDigest,
				},
			}

			metadata := map[string][]byte{
				hex.EncodeToString(rtmDigest[:]):    rtmManifest,
				hex.EncodeToString(osDigest[:]):     osManifest,
				hex.EncodeToString(appDigest[:]):    appManifest,
				hex.EncodeToString(deviceDigest[:]): deviceDescription,
			}

			data, err := s.Marshal(report)
			if err != nil {
				t.Errorf("failed to marshal the Attestation Report: %v", err)
			}

			// Preparation: Sign the report
			arSigned, err := prover.Sign(data, swSigner, s, ar.IK)
			if err != nil {
				t.Errorf("Internal Error: Failed to sign Attestion Report: %v", err)
			}

			// Run FUT
			log.Info("Running FUT")
			got := Verify(
				arSigned, nonce, internal.WriteCertPem(certchain[len(certchain)-1]), nil,
				"",
				PolicyEngineSelect_None,
				metadata,
				"")
			log.Info("Finished FUT")
			if got.Success != tt.want.Success {
				log.Warnf("Printing Summary")
				got.PrintErr()
				t.Errorf("Result.Success = %v, want %v", got.Success, tt.want.Success)
			}
		})
	}
}

func Test_checkMetadataCompatibility(t *testing.T) {
	logrus.SetLevel(logrus.TraceLevel)
	type args struct {
		metadata *ar.MetadataSummary
	}
	tests := []struct {
		name  string
		args  args
		want  *ar.CompatibilityResult
		want1 ar.ErrorCode
		want2 bool
	}{
		{
			name:  "Valid Metadata",
			want:  successCompatibilityResult,
			want1: ar.NotSet,
			want2: true,
			args: args{
				metadata: validMetadata,
			},
		},
		{
			name:  "No Root Manifest",
			want:  failedCompatibilityResult,
			want1: ar.NoRootManifest,
			want2: false,
			args: args{
				metadata: noRootManifestMetadata,
			},
		},
		{
			name:  "Multiple Root Manifests",
			want:  failedCompatibilityResult,
			want1: ar.MultipleRootManifests,
			want2: false,
			args: args{
				metadata: multipleRootManifestMetadata,
			},
		},
		{
			name:  "Missing Manifests",
			want:  failedCompatibilityResult,
			want1: ar.NotSet,
			want2: false,
			args: args{
				metadata: missingManifestMetadata,
			},
		},
		{
			name:  "Missing Manifest Description",
			want:  failedCompatibilityResult,
			want1: ar.NotSet,
			want2: false,
			args: args{
				metadata: missingDescriptionMetadata,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2 := checkMetadataCompatibility(tt.args.metadata)
			if got.Summary.Success != tt.want.Summary.Success {
				t.Errorf("checkMetadataCompatibility() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("checkMetadataCompatibility() got1 = %v, want %v", got1, tt.want1)
			}
			if got2 != tt.want2 {
				t.Errorf("checkMetadataCompatibility() got2 = %v, want %v", got2, tt.want2)
			}
		})
	}
}
