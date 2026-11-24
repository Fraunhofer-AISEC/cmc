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

package attestationreport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
)

func Test_parseAndVerifyMetadataDuplicates(t *testing.T) {
	logrus.SetLevel(logrus.TraceLevel)

	key, chain := createTestCertChain(t)
	s := getJsonSerializer()

	sign := func(m any) (string, []byte) {
		data, err := s.Marshal(m)
		if err != nil {
			t.Fatalf("failed to marshal metadata: %v", err)
		}
		signed, err := internal.Sign(data, key, s.String(), chain)
		if err != nil {
			t.Fatalf("failed to sign metadata: %v", err)
		}
		digest := sha256.Sum256(signed)
		return hex.EncodeToString(digest[:]), signed
	}

	// Variants differ in their version only, resulting in different digests
	withVersion := func(m Metadata, version string) Metadata {
		m.Version = version
		return m
	}

	companyDescription := Metadata{
		MetaInfo: MetaInfo{
			Type:     TYPE_COMPANY_DESCRIPTION,
			Name:     "Test Company Description",
			Version:  "2023-04-10T20:00:00Z",
			Validity: validMetaInfo.Validity,
		},
	}

	rtmDigest, rtm := sign(validRtmManifest)
	omspResponse := func(producedAt string) Metadata {
		return Metadata{
			MetaInfo: MetaInfo{Type: TYPE_OMSP_RESPONSE},
			OmspResponse: OmspResponse{
				Server:     validRtmManifest.OmspServer,
				ProducedAt: producedAt,
				Responses: []SingleOmspResponse{{
					ManifestHash: rtmDigest,
					Status:       OmspStatusGood,
					ThisUpdate:   "2025-04-01T20:00:00Z",
				}},
			},
		}
	}

	base := func(extra ...any) map[string][]byte {
		items := map[string][]byte{rtmDigest: rtm}
		for _, m := range append([]any{validOsManifest, validAppManifest}, extra...) {
			digest, signed := sign(m)
			items[digest] = signed
		}
		return items
	}

	tests := []struct {
		name      string
		items     map[string][]byte
		checkOmsp bool
		want      Status
		wantCode  ErrorCode
		check     func(t *testing.T, got MetadataSummary)
	}{
		{
			name: "Unique Items",
			items: base(validImageDescription, companyDescription,
				omspResponse("2025-04-01T20:00:00Z")),
			checkOmsp: true,
			want:      StatusSuccess,
			check: func(t *testing.T, got MetadataSummary) {
				if got.ImageDescriptionResult.Name != validImageDescription.Name {
					t.Errorf("image description %q, want %q",
						got.ImageDescriptionResult.Name, validImageDescription.Name)
				}
				if got.CompanyDescriptionResult == nil {
					t.Errorf("company description missing")
				}
				if len(got.OmspResults) != 1 {
					t.Errorf("got %v OMSP results, want 1", len(got.OmspResults))
				}
				for _, m := range got.ManifestResults {
					if m.Digest == "" {
						t.Errorf("manifest %v has no digest", m.Name)
					}
				}
			},
		},
		{
			name: "Multiple Image Descriptions",
			items: base(validImageDescription,
				withVersion(validImageDescription, "2024-01-01T00:00:00Z")),
			want:     StatusFail,
			wantCode: MultipleImageDescriptions,
			check: func(t *testing.T, got MetadataSummary) {
				if got.ImageDescriptionResult.Name != "" {
					t.Errorf("image description %q selected despite duplicates",
						got.ImageDescriptionResult.Name)
				}
			},
		},
		{
			name: "Multiple Company Descriptions",
			items: base(validImageDescription, companyDescription,
				withVersion(companyDescription, "2024-01-01T00:00:00Z")),
			want:     StatusFail,
			wantCode: MultipleCompanyDescriptions,
			check: func(t *testing.T, got MetadataSummary) {
				if got.CompanyDescriptionResult != nil {
					t.Errorf("company description selected despite duplicates")
				}
			},
		},
		{
			name: "Multiple OMSP Responses",
			items: base(validImageDescription, omspResponse("2025-04-01T20:00:00Z"),
				omspResponse("2025-04-02T20:00:00Z")),
			checkOmsp: true,
			want:      StatusFail,
			wantCode:  MultipleOmspResponses,
			check: func(t *testing.T, got MetadataSummary) {
				if len(got.OmspResults) != 0 {
					t.Errorf("got %v OMSP results despite duplicates", len(got.OmspResults))
				}
				rtmResult := RootManifest(got.ManifestResults)
				if rtmResult.OmspStatus == nil ||
					!slices.Contains(rtmResult.OmspStatus.ErrorCodes, ManifestRevocationUnknown) {
					t.Errorf("RTM revocation status %v, want %v",
						rtmResult.OmspStatus, ManifestRevocationUnknown)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, status := ParseAndVerifyMetadata([]*x509.Certificate{chain[len(chain)-1]},
				tt.items, tt.checkOmsp)
			if status != tt.want {
				t.Errorf("status = %v, want %v", status, tt.want)
			}
			if tt.wantCode != NotSpecified {
				if len(got.UnknownResults) != 2 {
					t.Fatalf("got %v unknown results, want 2", len(got.UnknownResults))
				}
				for _, r := range got.UnknownResults {
					if !slices.Contains(r.Summary.ErrorCodes, tt.wantCode) {
						t.Errorf("unknown result %v error codes %v, want %v",
							r.Name, r.Summary.ErrorCodes, tt.wantCode)
					}
					if r.Digest == "" {
						t.Errorf("unknown result %v has no digest", r.Name)
					}
				}
			} else if len(got.UnknownResults) != 0 {
				t.Errorf("got %v unknown results, want 0", len(got.UnknownResults))
			}
			tt.check(t, got)
		})
	}
}

func Test_checkMetadataCompatibility(t *testing.T) {
	logrus.SetLevel(logrus.TraceLevel)
	type args struct {
		metadata *MetadataSummary
	}
	tests := []struct {
		name  string
		args  args
		want  Status
		want1 []ErrorCode
	}{
		{
			name:  "Valid Metadata",
			want:  StatusSuccess,
			want1: []ErrorCode{},
			args: args{
				metadata: validMetadata,
			},
		},
		{
			name:  "No Root Manifest",
			want:  StatusFail,
			want1: []ErrorCode{NoRootManifest},
			args: args{
				metadata: noRootManifestMetadata,
			},
		},
		{
			name:  "Multiple Root Manifests",
			want:  StatusFail,
			want1: []ErrorCode{MultipleRootManifests},
			args: args{
				metadata: multipleRootManifestMetadata,
			},
		},
		{
			name:  "Missing Manifests",
			want:  StatusFail,
			want1: []ErrorCode{},
			args: args{
				metadata: missingManifestMetadata,
			},
		},
		{
			name:  "Missing Manifest Description",
			want:  StatusFail,
			want1: []ErrorCode{},
			args: args{
				metadata: missingDescriptionMetadata,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckMetadataCompatibility(tt.args.metadata)
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

func Test_rootManifest(t *testing.T) {
	tests := []struct {
		name      string
		manifests []MetadataResult
		want      string
	}{
		{
			name:      "Root First",
			manifests: []MetadataResult{validRtmResult, validOsResult, validAppResult},
			want:      validRtmResult.Name,
		},
		{
			name:      "Root Last",
			manifests: []MetadataResult{validAppResult, validOsResult, validRtmResult},
			want:      validRtmResult.Name,
		},
		{
			name:      "No Root",
			manifests: []MetadataResult{validOsResult, validAppResult},
			want:      "",
		},
		{
			name:      "No Manifests",
			manifests: nil,
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RootManifest(tt.manifests); got.Name != tt.want {
				t.Errorf("rootManifest() --GOT-- %q, --WANT-- %q", got.Name, tt.want)
			}
		})
	}
}

func Test_collectComponents(t *testing.T) {
	type args struct {
		metadata []MetadataResult
	}
	tests := []struct {
		name    string
		args    args
		want    map[string][]Component
		wantErr bool
	}{
		{
			name: "Success",
			args: args{
				metadata: []MetadataResult{
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
			got, err := CollectComponents(tt.args.metadata, nil)
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

var (
	validMetaInfo = MetaInfo{
		Type:    TYPE_IMAGE_DESCRIPTION,
		Name:    "test-device.test.de",
		Version: "2023-04-10T20:00:00Z",
		Validity: &Validity{
			NotBefore: "2023-04-10T20:00:00Z",
			NotAfter:  "2030-04-10T20:00:00Z",
		},
	}

	validImageDescription = Metadata{
		MetaInfo: validMetaInfo,
		ImageDescription: ImageDescription{
			Location: "Munich, Germany",
			Descriptions: []ManifestDescription{
				validRtmManifestDescription,
				validOsManifestDescription,
				validAppManifestDescription,
			},
		},
	}

	incompleteImageDescription = Metadata{
		MetaInfo: validMetaInfo,
		ImageDescription: ImageDescription{
			Location: "Munich, Germany",
			Descriptions: []ManifestDescription{
				validRtmManifestDescription,
				validOsManifestDescription,
			},
		},
	}

	validRtmManifestDescription = ManifestDescription{
		Type:     TYPE_MANIFEST_DESCRIPTION,
		Name:     " Test RTM Manifest Description",
		Manifest: "de.test.rtm",
	}

	validOsManifestDescription = ManifestDescription{
		Type:     TYPE_MANIFEST_DESCRIPTION,
		Name:     " Test OS Manifest Description",
		Manifest: "de.test.os",
	}

	validAppManifestDescription = ManifestDescription{
		Type:     TYPE_MANIFEST_DESCRIPTION,
		Name:     " Test App Manifest Description 1",
		Manifest: "de.test.app",
	}

	validRtmManifest = Metadata{
		MetaInfo: MetaInfo{
			Type:    TYPE_MANIFEST,
			Name:    "de.test.rtm",
			Version: "2023-04-10T20:00:00Z",
			Validity: &Validity{
				NotBefore: "2023-04-10T20:00:00Z",
				NotAfter:  "2030-04-10T20:00:00Z",
			},
			Description: "de.test.rtm",
		},
		Manifest: Manifest{
			DevCommonName: "Test Developer",
			BaseLayers:    []string{"de.test.rtm"},
			OmspServer:    "https://10.0.2.2:9000/",
		},
	}

	validOsManifest = Metadata{
		MetaInfo: MetaInfo{
			Type:    TYPE_MANIFEST,
			Name:    "de.test.os",
			Version: "2023-04-10T20:00:00Z",
			Validity: &Validity{
				NotBefore: "2023-04-10T20:00:00Z",
				NotAfter:  "2030-04-10T20:00:00Z",
			},
			Description: "PoC Fraunhofer AISEC Sample Report",
		},
		Manifest: Manifest{
			DevCommonName: "Test Developer",
			BaseLayers: []string{
				"de.test.rtm",
			},
		},
	}

	validAppManifest = Metadata{
		MetaInfo: MetaInfo{
			Type:    TYPE_MANIFEST,
			Name:    "de.test.app",
			Version: "2023-04-10T20:00:00Z",
			Validity: &Validity{
				NotBefore: "2023-04-10T20:00:00Z",
				NotAfter:  "2030-04-10T20:00:00Z",
			},
			Description: "PoC Fraunhofer AISEC Sample Report",
		},
		Manifest: Manifest{
			DevCommonName: "Test Developer",
			BaseLayers: []string{
				"de.test.os",
			},
		},
	}

	validCompanyDescription = Metadata{
		MetaInfo: MetaInfo{
			Type: TYPE_COMPANY_DESCRIPTION,
			Name: "Test Company Description",
		},
	}

	validImageDescriptionResult = MetadataResult{
		Metadata: validImageDescription,
	}

	incompleteImageDescriptionResult = MetadataResult{
		Metadata: incompleteImageDescription,
	}

	validCompDescResult = &MetadataResult{
		Metadata: validCompanyDescription,
	}

	validRtmResult = MetadataResult{
		Metadata: validRtmManifest,
	}

	validOsResult = MetadataResult{
		Metadata: validOsManifest,
	}

	validAppResult = MetadataResult{
		Metadata: validAppManifest,
	}

	validMetadata = &MetadataSummary{
		ImageDescriptionResult:   validImageDescriptionResult,
		CompanyDescriptionResult: validCompDescResult,
		ManifestResults: []MetadataResult{
			validRtmResult,
			validOsResult,
			validAppResult,
		},
	}

	noRootManifestMetadata = &MetadataSummary{
		ImageDescriptionResult:   validImageDescriptionResult,
		CompanyDescriptionResult: validCompDescResult,
		ManifestResults: []MetadataResult{
			validOsResult,
			validAppResult,
		},
	}

	multipleRootManifestMetadata = &MetadataSummary{
		ImageDescriptionResult:   validImageDescriptionResult,
		CompanyDescriptionResult: validCompDescResult,
		ManifestResults: []MetadataResult{
			validRtmResult,
			validRtmResult,
			validOsResult,
			validAppResult,
		},
	}

	missingManifestMetadata = &MetadataSummary{
		ImageDescriptionResult:   validImageDescriptionResult,
		CompanyDescriptionResult: validCompDescResult,
		ManifestResults: []MetadataResult{
			validRtmResult,
			validOsResult,
		},
	}

	missingDescriptionMetadata = &MetadataSummary{
		ImageDescriptionResult:   incompleteImageDescriptionResult,
		CompanyDescriptionResult: validCompDescResult,
		ManifestResults: []MetadataResult{
			validRtmResult,
			validOsResult,
			validAppResult,
		},
	}
)

// variables for Test_collectComponents
var (
	refs = []Component{
		{
			Type: TYPE_FIRMWARE,
			Name: "TPM1",
			Properties: []Property{
				{Name: PROPERTY_TRUST_ANCHOR, Value: TRUST_ANCHOR_TPM},
			},
		},
		{
			Type: TYPE_FIRMWARE,
			Name: "TPM2",
			Properties: []Property{
				{Name: PROPERTY_TRUST_ANCHOR, Value: TRUST_ANCHOR_TPM},
			},
		},
		{
			Type: TYPE_FIRMWARE,
			Name: "SNP1",
			Properties: []Property{
				{Name: PROPERTY_TRUST_ANCHOR, Value: TRUST_ANCHOR_SNP},
			},
		},
		{
			Type: TYPE_APP,
			Name: "SW1",
			Properties: []Property{
				{Name: PROPERTY_TRUST_ANCHOR, Value: TRUST_ANCHOR_SW},
			},
		},
		{
			Type: TYPE_APP,
			Name: "SW2",
			Properties: []Property{
				{Name: PROPERTY_TRUST_ANCHOR, Value: TRUST_ANCHOR_SW},
			},
		},
	}

	refMap = map[string][]Component{
		TRUST_ANCHOR_TPM: refs[:2],
		TRUST_ANCHOR_SNP: {refs[2]},
		TRUST_ANCHOR_SW:  refs[3:],
	}

	rtmManifest = MetadataResult{
		Metadata: Metadata{
			Manifest: Manifest{
				Sbom: &Sbom{
					Components: []Component{
						refs[0],
						refs[2],
					},
				},
			},
		},
	}

	osManifest = MetadataResult{
		Metadata: Metadata{
			Manifest: Manifest{
				Sbom: &Sbom{
					Components: []Component{
						refs[1],
					},
				},
			},
		},
	}

	appManifest1 = MetadataResult{
		Metadata: Metadata{
			Manifest: Manifest{
				Sbom: &Sbom{
					Components: []Component{refs[3]},
				},
			},
		},
	}

	appManifest2 = MetadataResult{
		Metadata: Metadata{
			Manifest: Manifest{
				Sbom: &Sbom{
					Components: []Component{refs[4]},
				},
			},
		},
	}
)

func createTestCertChain(t *testing.T) (*ecdsa.PrivateKey, []*x509.Certificate) {
	t.Helper()

	create := func(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey,
	) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatalf("failed to create certificate: %v", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("failed to parse certificate: %v", err)
		}
		return cert
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	ca := create(caTmpl, caTmpl, &caKey.PublicKey, caKey)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	leaf := create(&x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Signer"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}, ca, &key.PublicKey, caKey)

	return key, []*x509.Certificate{leaf, ca}
}
