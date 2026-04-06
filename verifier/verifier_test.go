// Copyright (c) 2021 - 2025 Fraunhofer AISEC
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
	"testing"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
)

func Test_collectComponents(t *testing.T) {
	type args struct {
		metadata []ar.MetadataResult
	}
	tests := []struct {
		name    string
		args    args
		want    map[string][]ar.Component
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
			got, err := collectComponents(tt.args.metadata)
			if (err != nil) != tt.wantErr {
				t.Errorf("collectComponents() error = %v, wantErr %v", err, tt.wantErr)
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
						t.Errorf("collectComponents() failed to find %v", wantedrefval.Name)
					}
				}
			}
		})
	}
}

func TestVerify(t *testing.T) {
	logrus.SetLevel(logrus.TraceLevel)

	type args struct {
		serializer       ar.Serializer
		rtmManifest      ar.Metadata
		osManifest       ar.Metadata
		appManifest      ar.Metadata
		imageDescription ar.Metadata
		proverNonce      []byte
		verifierNonce    []byte
		encoding         string
		alg              string
	}
	tests := []struct {
		name string
		args args
		want ar.Status
	}{
		{
			name: "Valid Report JSON",
			args: args{
				serializer:       getJsonSerializer(),
				rtmManifest:      validRtmManifest,
				osManifest:       validOsManifest,
				appManifest:      validAppManifest,
				imageDescription: validImageDescription,
				proverNonce:      validUserNonce,
				verifierNonce:    validUserNonce,
				encoding:         ar.TYPE_ENCODING_B64,
				alg:              "SHA-256",
			},
			want: ar.StatusSuccess,
		},
		{
			name: "Valid Report CBOR",
			args: args{
				serializer:       getCborSerializer(),
				rtmManifest:      validRtmManifest,
				osManifest:       validOsManifest,
				appManifest:      validAppManifest,
				imageDescription: validImageDescription,
				proverNonce:      validUserNonce,
				verifierNonce:    validUserNonce,
				encoding:         ar.TYPE_ENCODING_CBOR,
				alg:              "SHA-256",
			},
			want: ar.StatusSuccess,
		},
		{
			// expected aggregated certification level in Manifests for
			// empty measurement is max. 1 (here certification level = 3)
			name: "Invalid Certification Level",
			args: args{
				serializer: getJsonSerializer(),
				rtmManifest: ar.Metadata{
					MetaInfo: ar.MetaInfo{
						Type:    ar.TYPE_MANIFEST,
						Name:    "de.test.rtm",
						Version: "2023-04-10T20:00:00Z",
						Validity: ar.Validity{
							NotBefore: "2023-04-10T20:00:00Z",
							NotAfter:  "2026-04-10T20:00:00Z",
						},
						Description: "de.test.rtm",
					},
					Manifest: ar.Manifest{
						DevCommonName: "Test Developer",
						Sbom: &ar.Sbom{
							Components: []ar.Component{},
						},
						CertLevel: 3,
					},
				},
				osManifest: ar.Metadata{
					MetaInfo: ar.MetaInfo{
						Type:    ar.TYPE_MANIFEST,
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
				appManifest:      validAppManifest,
				imageDescription: validImageDescription,
				proverNonce:      validUserNonce,
				verifierNonce:    validUserNonce,
				encoding:         ar.TYPE_ENCODING_B64,
				alg:              "SHA-256",
			},
			want: ar.StatusFail,
		},
		{
			name: "Invalid Image Description",
			args: args{
				serializer:       getJsonSerializer(),
				rtmManifest:      validRtmManifest,
				osManifest:       validOsManifest,
				appManifest:      validAppManifest,
				imageDescription: invalidImageDescription,
				proverNonce:      validUserNonce,
				verifierNonce:    validUserNonce,
				encoding:         ar.TYPE_ENCODING_B64,
				alg:              "SHA-256",
			},
			want: ar.StatusFail,
		},
		{
			name: "Incompatible RTM/OS Manifests",
			args: args{
				serializer:       getJsonSerializer(),
				rtmManifest:      validRtmManifest,
				osManifest:       incompatibleOsManifest,
				appManifest:      validAppManifest,
				imageDescription: validImageDescription,
				proverNonce:      validUserNonce,
				verifierNonce:    validUserNonce,
				encoding:         ar.TYPE_ENCODING_B64,
				alg:              "SHA-256",
			},
			want: ar.StatusFail,
		},
		{
			name: "Invalid user nonce",
			args: args{
				serializer:       getJsonSerializer(),
				rtmManifest:      validRtmManifest,
				osManifest:       validOsManifest,
				appManifest:      validAppManifest,
				imageDescription: validImageDescription,
				proverNonce:      invalidUserNonce,
				verifierNonce:    validUserNonce,
				encoding:         ar.TYPE_ENCODING_B64,
				alg:              "SHA-256",
			},
			want: ar.StatusFail,
		},
	}

	// Setup Test Keys and Certificates
	log.Trace("Creating Keys and Certificates")
	key, certchain, err := createCertsAndKeys()
	if err != nil {
		log.Errorf("Internal Error: Failed to create testing certs and keys: %v", err)
		return
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.args.serializer

			// Preparation: Generate a Sample Report
			log.Trace("Generating a Sample Report")

			// Preparation: create signed manifests and imageDescription
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
			imageDescription, err := s.Marshal(tt.args.imageDescription)
			if err != nil {
				t.Errorf("failed to marshal the ImageDescription: %v", err)
			}

			rtmManifest, err = internal.Sign(rtmManifest, key, key.PublicKey, s.String(), certchain)
			if err != nil {
				t.Errorf("failed to sign the RTM Manifest: %v", err)
			}
			osManifest, err = internal.Sign(osManifest, key, key.PublicKey, s.String(), certchain)
			if err != nil {
				t.Errorf("failed to sign the OS Manifest: %v", err)
			}
			appManifest, err = internal.Sign(appManifest, key, key.PublicKey, s.String(), certchain)
			if err != nil {
				t.Errorf("failed to sign the App Manifest: %v", err)
			}
			imageDescription, err = internal.Sign(imageDescription, key, key.PublicKey, s.String(), certchain)
			if err != nil {
				t.Errorf("failed to sign the ImageDescription: %v", err)
			}

			rtmDigest := sha256.Sum256(rtmManifest)
			osDigest := sha256.Sum256(osManifest)
			appDigest := sha256.Sum256(appManifest)
			imageDigest := sha256.Sum256(imageDescription)

			metadata := map[string][]byte{
				hex.EncodeToString(rtmDigest[:]):   rtmManifest,
				hex.EncodeToString(osDigest[:]):    osManifest,
				hex.EncodeToString(appDigest[:]):   appManifest,
				hex.EncodeToString(imageDigest[:]): imageDescription,
			}

			report := ar.AttestationReport{
				Type:     ar.TYPE_ATTESTATION_REPORT,
				Version:  ar.GetReportVersion(),
				Encoding: tt.args.encoding,
				Context: ar.Context{
					Type:  ar.TYPE_CONTEXT,
					Alg:   tt.args.alg,
					Nonce: tt.args.proverNonce,
					Digests: []string{
						hex.EncodeToString(rtmDigest[:]),
						hex.EncodeToString(osDigest[:]),
						hex.EncodeToString(appDigest[:]),
						hex.EncodeToString(imageDigest[:]),
					},
					Metadata: metadata,
				},
			}

			_, err = report.PrepareContext(tt.args.serializer, crypto.SHA256)
			if err != nil {
				t.Errorf("failed to prepare report context: %v", err)
			}

			data, err := s.Marshal(report)
			if err != nil {
				t.Errorf("failed to marshal the Attestation Report: %v", err)
			}

			// Run FUT
			log.Info("Running FUT")
			got := Verify(
				data, tt.args.verifierNonce,
				[]*x509.Certificate{certchain[len(certchain)-1]},
				nil,
				PolicyEngineSelect_None,
				false,
				[]*x509.Certificate{certchain[len(certchain)-1]},
				nil, "",
			)
			log.Info("Finished FUT")
			if got.Summary.Status != tt.want {
				log.Warnf("Printing Summary")
				got.PrintErr()
				t.Errorf("Result.Success = %v, want %v", got.Summary.Status, tt.want)
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
		want  ar.Status
		want1 []ar.ErrorCode
	}{
		{
			name:  "Valid Metadata",
			want:  ar.StatusSuccess,
			want1: []ar.ErrorCode{},
			args: args{
				metadata: validMetadata,
			},
		},
		{
			name:  "No Root Manifest",
			want:  ar.StatusFail,
			want1: []ar.ErrorCode{ar.NoRootManifest},
			args: args{
				metadata: noRootManifestMetadata,
			},
		},
		{
			name:  "Multiple Root Manifests",
			want:  ar.StatusFail,
			want1: []ar.ErrorCode{ar.MultipleRootManifests},
			args: args{
				metadata: multipleRootManifestMetadata,
			},
		},
		{
			name:  "Missing Manifests",
			want:  ar.StatusFail,
			want1: []ar.ErrorCode{},
			args: args{
				metadata: missingManifestMetadata,
			},
		},
		{
			name:  "Missing Manifest Description",
			want:  ar.StatusFail,
			want1: []ar.ErrorCode{},
			args: args{
				metadata: missingDescriptionMetadata,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkMetadataCompatibility(tt.args.metadata)
			if got.Summary.Status != tt.want {
				t.Errorf("checkMetadataCompatibility() got = %v, want %v", got, tt.want)
			}
			if len(got.Summary.ErrorCodes) != len(tt.want1) {
				t.Errorf("checkMetadataCompatibility() got1 = %v, want %v", got.Summary.ErrorCodes, tt.want1)
			}
			for _, ec1 := range got.Summary.ErrorCodes {
				found := false
				for _, ec2 := range tt.want1 {
					if ec1 == ec2 {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("checkMetadataCompatibility() got1 = %v, want %v", got.Summary.ErrorCodes, tt.want1)
				}
			}
		})
	}
}

// variables for Test_collectComponents
var (
	refs = []ar.Component{
		{Type: ar.TYPE_REFVAL_TPM, Name: "TPM1"},
		{Type: ar.TYPE_REFVAL_TPM, Name: "TPM2"},
		{Type: ar.TYPE_REFVAL_SNP, Name: "SNP1"},
		{Type: ar.TYPE_REFVAL_SW, Name: "SW1"},
		{Type: ar.TYPE_REFVAL_SW, Name: "SW2"},
	}

	refMap = map[string][]ar.Component{
		ar.TYPE_REFVAL_TPM: refs[:2],
		ar.TYPE_REFVAL_SNP: {refs[2]},
		ar.TYPE_REFVAL_SW:  refs[3:],
	}

	rtmManifest = ar.MetadataResult{
		Metadata: ar.Metadata{
			Manifest: ar.Manifest{
				Sbom: &ar.Sbom{
					Components: []ar.Component{
						refs[0],
						refs[2],
					},
				},
			},
		},
	}

	osManifest = ar.MetadataResult{
		Metadata: ar.Metadata{
			Manifest: ar.Manifest{
				Sbom: &ar.Sbom{
					Components: []ar.Component{
						refs[1],
					},
				},
			},
		},
	}

	appManifest1 = ar.MetadataResult{
		Metadata: ar.Metadata{
			Manifest: ar.Manifest{
				Sbom: &ar.Sbom{
					Components: []ar.Component{refs[3]},
				},
			},
		},
	}

	appManifest2 = ar.MetadataResult{
		Metadata: ar.Metadata{
			Manifest: ar.Manifest{
				Sbom: &ar.Sbom{
					Components: []ar.Component{refs[4]},
				},
			},
		},
	}
)

// variables for TestVerify & Test_checkMetadataCompatibility
var (
	validCompanyDescription = ar.Metadata{
		MetaInfo: ar.MetaInfo{
			Type: ar.TYPE_COMPANY_DESCRIPTION,
			Name: "Test Company Description",
		},
	}

	validRtmManifestDescription = ar.ManifestDescription{
		Type:     ar.TYPE_MANIFEST_DESCRIPTION,
		Name:     " Test RTM Manifest Description",
		Manifest: "de.test.rtm",
	}

	validOsManifestDescription = ar.ManifestDescription{
		Type:     ar.TYPE_MANIFEST_DESCRIPTION,
		Name:     " Test OS Manifest Description",
		Manifest: "de.test.os",
	}

	validAppManifestDescription = ar.ManifestDescription{
		Type:     ar.TYPE_MANIFEST_DESCRIPTION,
		Name:     " Test App Manifest Description 1",
		Manifest: "de.test.app",
	}

	validRtmManifest = ar.Metadata{
		MetaInfo: ar.MetaInfo{
			Type:    ar.TYPE_MANIFEST,
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
			Type:    ar.TYPE_MANIFEST,
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
			Type:    ar.TYPE_MANIFEST,
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
			Type:    ar.TYPE_MANIFEST,
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
		Type:    ar.TYPE_IMAGE_DESCRIPTION,
		Name:    "test-device.test.de",
		Version: "2023-04-10T20:00:00Z",
		Validity: ar.Validity{
			NotBefore: "2023-04-10T20:00:00Z",
			NotAfter:  "2030-04-10T20:00:00Z",
		},
	}

	validImageDescription = ar.Metadata{
		MetaInfo: validMetaInfo,
		ImageDescription: ar.ImageDescription{
			Location: "Munich, Germany",
			Descriptions: []ar.ManifestDescription{
				validRtmManifestDescription,
				validOsManifestDescription,
				validAppManifestDescription,
			},
		},
	}

	incompleteImageDescription = ar.Metadata{
		MetaInfo: validMetaInfo,
		ImageDescription: ar.ImageDescription{
			Location: "Munich, Germany",
			Descriptions: []ar.ManifestDescription{
				validRtmManifestDescription,
				validOsManifestDescription,
			},
		},
	}

	invalidImageDescription = ar.Metadata{
		MetaInfo: ar.MetaInfo{
			Type:    ar.TYPE_IMAGE_DESCRIPTION,
			Name:    "test-device.test.de",
			Version: "2023-04-10T20:00:00Z",
		},
		ImageDescription: ar.ImageDescription{
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
	validUserNonce = []byte{0x01, 0x02, 0x03}

	invalidUserNonce = []byte{0x04, 0x05, 0x06}
)

// Variables for Test_checkMetadataCompatibility
var (
	validImageDescriptionResult = ar.MetadataResult{
		Metadata: validImageDescription,
	}

	incompleteImageDescriptionResult = ar.MetadataResult{
		Metadata: incompleteImageDescription,
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
		ImageDescriptionResult:   validImageDescriptionResult,
		CompanyDescriptionResult: validCompDescResult,
		ManifestResults: []ar.MetadataResult{
			validRtmResult,
			validOsResult,
			validAppResult,
		},
	}

	noRootManifestMetadata = &ar.MetadataSummary{
		ImageDescriptionResult:   validImageDescriptionResult,
		CompanyDescriptionResult: validCompDescResult,
		ManifestResults: []ar.MetadataResult{
			validOsResult,
			validAppResult,
		},
	}

	multipleRootManifestMetadata = &ar.MetadataSummary{
		ImageDescriptionResult:   validImageDescriptionResult,
		CompanyDescriptionResult: validCompDescResult,
		ManifestResults: []ar.MetadataResult{
			validRtmResult,
			validRtmResult,
			validOsResult,
			validAppResult,
		},
	}

	missingManifestMetadata = &ar.MetadataSummary{
		ImageDescriptionResult:   validImageDescriptionResult,
		CompanyDescriptionResult: validCompDescResult,
		ManifestResults: []ar.MetadataResult{
			validRtmResult,
			validOsResult,
		},
	}

	missingDescriptionMetadata = &ar.MetadataSummary{
		ImageDescriptionResult:   incompleteImageDescriptionResult,
		CompanyDescriptionResult: validCompDescResult,
		ManifestResults: []ar.MetadataResult{
			validRtmResult,
			validOsResult,
			validAppResult,
		},
	}
)

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

func getCborSerializer() ar.Serializer {
	s, err := ar.NewCborSerializer()
	if err != nil {
		log.Fatalf("test: failed to initialize cbor serializer: %v", err)
	}
	return s
}

func getJsonSerializer() ar.Serializer {
	s, err := ar.NewJsonSerializer()
	if err != nil {
		log.Fatalf("test: failed to initialize json serializer: %v", err)
	}
	return s
}
