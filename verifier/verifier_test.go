// Copyright (c) 2021 - 2026 Fraunhofer AISEC
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
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"testing"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
)

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
		omspResponse     ar.Metadata
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
				omspResponse:     validOmspResponse,
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
				omspResponse:     validOmspResponse,
			},
			want: ar.StatusSuccess,
		},
		// The report contains no evidence, so metadata requiring evidence must fail
		{
			name: "Missing TDX Evidence",
			args: args{
				serializer:       getJsonSerializer(),
				rtmManifest:      rtmManifestWith(tdxComponent(false), nil),
				osManifest:       validOsManifest,
				appManifest:      validAppManifest,
				imageDescription: validImageDescription,
				proverNonce:      validUserNonce,
				verifierNonce:    validUserNonce,
				encoding:         ar.TYPE_ENCODING_B64,
				alg:              "SHA-256",
				omspResponse:     validOmspResponse,
			},
			want: ar.StatusFail,
		},
		{
			name: "Optional TDX Reference Value",
			args: args{
				serializer:       getJsonSerializer(),
				rtmManifest:      rtmManifestWith(tdxComponent(true), nil),
				osManifest:       validOsManifest,
				appManifest:      validAppManifest,
				imageDescription: validImageDescription,
				proverNonce:      validUserNonce,
				verifierNonce:    validUserNonce,
				encoding:         ar.TYPE_ENCODING_B64,
				alg:              "SHA-256",
				omspResponse:     validOmspResponse,
			},
			want: ar.StatusSuccess,
		},
		{
			name: "Missing SNP Evidence For Policy",
			args: args{
				serializer:       getJsonSerializer(),
				rtmManifest:      rtmManifestWith(nil, &ar.SnpPolicy{}),
				osManifest:       validOsManifest,
				appManifest:      validAppManifest,
				imageDescription: validImageDescription,
				proverNonce:      validUserNonce,
				verifierNonce:    validUserNonce,
				encoding:         ar.TYPE_ENCODING_B64,
				alg:              "SHA-256",
				omspResponse:     validOmspResponse,
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
				omspResponse:     validOmspResponse,
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
				omspResponse:     validOmspResponse,
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
				omspResponse:     validOmspResponse,
			},
			want: ar.StatusFail,
		},
		// Test cases for manifest revocation (OMSP Response)
		{
			name: "RTM manifest revocation status unknown",
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
				omspResponse: ar.Metadata{
					MetaInfo: ar.MetaInfo{
						Type: ar.TYPE_OMSP_RESPONSE,
					},
					OmspResponse: ar.OmspResponse{
						Server:     "https://10.0.2.2:9000/",
						ProducedAt: "2026-04-16T20:00:00Z",
						Responses: []ar.SingleOmspResponse{
							{
								ManifestHash: "rtmhash", //is replaced with hash of signed artefact in the test function
								Status:       ar.OmspStatusUnknown,
								ThisUpdate:   "2026-04-01T20:00:00Z",
								NextUpdate:   "2030-04-01T20:00:00Z",
							},
						},
					},
				},
			},
			want: ar.StatusFail,
		},
		{
			name: "RTM manifest revocation status outdated",
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
				omspResponse: ar.Metadata{
					MetaInfo: ar.MetaInfo{
						Type: ar.TYPE_OMSP_RESPONSE,
					},
					OmspResponse: ar.OmspResponse{
						Server:     "https://10.0.2.2:9000/",
						ProducedAt: "2026-04-16T20:00:00Z",
						Responses: []ar.SingleOmspResponse{
							{
								ManifestHash: "rtmhash", //is replaced with hash of signed artefact in the test function
								Status:       ar.OmspStatusOutdated,
								ThisUpdate:   "2026-04-01T20:00:00Z",
								NextUpdate:   "2030-04-01T20:00:00Z",
							},
						},
					},
				},
			},
			want: ar.StatusWarn,
		},
		{
			name: "RTM manifest revocation status revoked",
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
				omspResponse: ar.Metadata{
					MetaInfo: ar.MetaInfo{
						Type: ar.TYPE_OMSP_RESPONSE,
					},
					OmspResponse: ar.OmspResponse{
						Server:     "https://10.0.2.2:9000/",
						ProducedAt: "2026-04-16T20:00:00Z",
						Responses: []ar.SingleOmspResponse{
							{
								ManifestHash: "rtmhash", //is replaced with hash of signed artefact in the test function
								Status:       ar.OmspStatusRevoked,
								ThisUpdate:   "2026-04-01T20:00:00Z",
								NextUpdate:   "2030-04-01T20:00:00Z",
							},
						},
					},
				},
			},
			want: ar.StatusFail,
		},
		{
			name: "Invalid OMSP response because of ProducedAt",
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
				omspResponse: ar.Metadata{
					MetaInfo: ar.MetaInfo{
						Type: ar.TYPE_OMSP_RESPONSE,
					},
					OmspResponse: ar.OmspResponse{
						Server:     "https://10.0.2.2:9000/",
						ProducedAt: "2030-04-16T20:00:00Z",
						Responses: []ar.SingleOmspResponse{
							{
								ManifestHash: "rtmhash", //is replaced with hash of signed artefact in the test function
								Status:       ar.OmspStatusGood,
								ThisUpdate:   "2026-04-01T20:00:00Z",
								NextUpdate:   "2030-04-01T20:00:00Z",
							},
						},
					},
				},
			},
			want: ar.StatusFail,
		},
		{
			name: "Invalid OMSP response because of NextUpdate for RTM",
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
				omspResponse: ar.Metadata{
					MetaInfo: ar.MetaInfo{
						Type: ar.TYPE_OMSP_RESPONSE,
					},
					OmspResponse: ar.OmspResponse{
						Server:     "https://10.0.2.2:9000/",
						ProducedAt: "2026-04-16T20:00:00Z",
						Responses: []ar.SingleOmspResponse{
							{
								ManifestHash: "rtmhash", //is replaced with hash of signed artefact in the test function
								Status:       ar.OmspStatusGood,
								ThisUpdate:   "2025-04-01T20:00:00Z",
								NextUpdate:   "2026-01-01T20:00:00Z",
							},
						},
					},
				},
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

			rtmManifest, err = internal.Sign(rtmManifest, key, s.String(), certchain)
			if err != nil {
				t.Errorf("failed to sign the RTM Manifest: %v", err)
			}
			osManifest, err = internal.Sign(osManifest, key, s.String(), certchain)
			if err != nil {
				t.Errorf("failed to sign the OS Manifest: %v", err)
			}
			appManifest, err = internal.Sign(appManifest, key, s.String(), certchain)
			if err != nil {
				t.Errorf("failed to sign the App Manifest: %v", err)
			}
			imageDescription, err = internal.Sign(imageDescription, key, s.String(), certchain)
			if err != nil {
				t.Errorf("failed to sign the ImageDescription: %v", err)
			}

			rtmDigest := sha256.Sum256(rtmManifest)
			osDigest := sha256.Sum256(osManifest)
			appDigest := sha256.Sum256(appManifest)
			imageDigest := sha256.Sum256(imageDescription)

			// add RTM hashes to OMSP response
			tt.args.omspResponse.Responses[0].ManifestHash = hex.EncodeToString(rtmDigest[:])

			omspResponse, err := s.Marshal(tt.args.omspResponse)
			if err != nil {
				t.Errorf("failed to marshall OMSP response: %v", err)
			}
			omspResponseSigned, err := internal.Sign(omspResponse, key, s.String(), certchain)
			if err != nil {
				t.Errorf("failed to sign the OMSP response: %v", err)
			}
			omspDigest := sha256.Sum256(omspResponseSigned)

			metadata := map[string][]byte{
				hex.EncodeToString(rtmDigest[:]):   rtmManifest,
				hex.EncodeToString(osDigest[:]):    osManifest,
				hex.EncodeToString(appDigest[:]):   appManifest,
				hex.EncodeToString(imageDigest[:]): imageDescription,
				hex.EncodeToString(omspDigest[:]):  omspResponseSigned,
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
						hex.EncodeToString(omspDigest[:]),
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
			got := Verify(data, tt.args.verifierNonce, VerifyOptions{
				MetadataCas: []*x509.Certificate{certchain[len(certchain)-1]},
				CheckOmsp:   true,
			})
			log.Info("Finished FUT")
			if got.Summary.Status != tt.want {
				log.Warnf("Printing Summary")
				got.PrintErr()
				t.Errorf("Result.Success = %v, want %v", got.Summary.Status, tt.want)
			}
			if got.Name != validMetaInfo.Name {
				t.Errorf("Name = %q, want %q", got.Name, validMetaInfo.Name)
			}
		})
	}
}

func TestAttestLevel(t *testing.T) {
	tests := []struct {
		name      string
		evidences []string
		want      ar.AttestLevel
		covers    []string
	}{
		{"no evidence", nil, ar.LevelNone, nil},
		{"sw", []string{ar.TYPE_EVIDENCE_SW}, ar.LevelSoftware, []string{ar.TRUST_ANCHOR_SW}},
		{"tpm and sw", []string{ar.TYPE_EVIDENCE_TPM, ar.TYPE_EVIDENCE_SW}, ar.LevelHardware,
			[]string{ar.TRUST_ANCHOR_TPM, ar.TRUST_ANCHOR_SW}},
		{"azure tdx", []string{ar.TYPE_EVIDENCE_AZURE_TDX, ar.TYPE_EVIDENCE_AZURE_TPM},
			ar.LevelHardware, []string{ar.TRUST_ANCHOR_TDX, ar.TRUST_ANCHOR_TPM}},
		{"nvidia", []string{ar.TYPE_EVIDENCE_NVIDIA}, ar.LevelSoftware,
			[]string{ar.TRUST_ANCHOR_NVIDIA}},
		{"snp and nvidia", []string{ar.TYPE_EVIDENCE_SNP, ar.TYPE_EVIDENCE_NVIDIA}, ar.LevelHardware,
			[]string{ar.TRUST_ANCHOR_SNP, ar.TRUST_ANCHOR_NVIDIA}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var evidences []ar.Evidence
			for _, typ := range tt.evidences {
				evidences = append(evidences, ar.Evidence{Type: typ})
			}
			covered := coveredTrustAnchors(evidences)
			if got := slices.Sorted(maps.Keys(covered)); !slices.Equal(got, slices.Sorted(slices.Values(tt.covers))) {
				t.Errorf("coveredTrustAnchors() = %v, want %v", got, tt.covers)
			}
			if got := attestLevel(covered); got != tt.want {
				t.Errorf("attestLevel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTpmAkTrust(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vTPM AK"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		// As created by the TPM driver for the vTPM AK
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	selfSigned, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ekuChain, _ := reissueAk(t, validAk, []asn1.ObjectIdentifier{internal.OidAkCertificate})
	metadataCas := []*x509.Certificate{validCa}

	tpm := ar.Evidence{Type: ar.TYPE_EVIDENCE_TPM}
	snp := ar.Evidence{Type: ar.TYPE_EVIDENCE_SNP}
	tdx := ar.Evidence{Type: ar.TYPE_EVIDENCE_TDX}

	tests := []struct {
		name        string
		evidences   []ar.Evidence
		certs       [][]byte
		wantCa      string
		wantRequire bool
	}{
		{"tpm primary", []ar.Evidence{tpm}, ekuChain, validCa.Subject.CommonName, true},
		{"vtpm snp", []ar.Evidence{tpm, snp}, [][]byte{selfSigned}, "vTPM AK", false},
		{"vtpm tdx", []ar.Evidence{tdx, tpm}, [][]byte{selfSigned}, "vTPM AK", false},
		{"self-signed without cvm", []ar.Evidence{tpm}, [][]byte{selfSigned},
			validCa.Subject.CommonName, true},
		{"ca-issued with cvm", []ar.Evidence{tpm, snp}, ekuChain, validCa.Subject.CommonName, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cas, require := tpmAkTrust(tt.evidences, ar.Collateral{Certs: tt.certs}, metadataCas)
			if len(cas) != 1 || cas[0].Subject.CommonName != tt.wantCa {
				t.Errorf("tpmAkTrust() CAs = %v, want %v", cas, tt.wantCa)
			}
			if require != tt.wantRequire {
				t.Errorf("tpmAkTrust() requireAkEku = %v, want %v", require, tt.wantRequire)
			}
		})
	}
}

func Test_sortArtifacts(t *testing.T) {

	measurements := []ar.MeasurementResult{
		{
			Type: "TPM Result",
			Artifacts: []ar.DigestResult{
				{Index: 1, Name: "pcr1-event1", Type: ar.TYPE_DIGEST_VERIFIED},
				{Index: 1, Name: "pcr1-event2", Type: ar.TYPE_DIGEST_MEASUREMENT},
				{Index: 4, Name: "pcr4-event1", Type: ar.TYPE_DIGEST_VERIFIED},
				{Index: 1, Name: "pcr1-refval", Type: ar.TYPE_DIGEST_REFERENCE_VALUE},
				{Index: 4, Name: "pcr4-refval", Type: ar.TYPE_DIGEST_REFERENCE_VALUE},
			},
		},
		{
			Type: "SW Result",
		},
	}

	sortArtifacts(measurements)

	want := []string{"pcr1-event1", "pcr1-event2", "pcr1-refval", "pcr4-event1", "pcr4-refval"}
	got := make([]string, 0, len(measurements[0].Artifacts))
	for _, a := range measurements[0].Artifacts {
		got = append(got, a.Name)
	}
	if !slices.Equal(got, want) {
		t.Errorf("sortArtifacts() --GOT-- %v, --WANT-- %v", got, want)
	}
}

// variables for TestVerify & Test_checkMetadataCompatibility
var (
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
			Validity: &ar.Validity{
				NotBefore: "2023-04-10T20:00:00Z",
				NotAfter:  "2030-04-10T20:00:00Z",
			},
			Description: "de.test.rtm",
		},
		Manifest: ar.Manifest{
			DevCommonName: "Test Developer",
			BaseLayers:    []string{"de.test.rtm"},
			OmspServer:    "https://10.0.2.2:9000/",
		},
	}

	validOsManifest = ar.Metadata{
		MetaInfo: ar.MetaInfo{
			Type:    ar.TYPE_MANIFEST,
			Name:    "de.test.os",
			Version: "2023-04-10T20:00:00Z",
			Validity: &ar.Validity{
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
		},
	}

	validAppManifest = ar.Metadata{
		MetaInfo: ar.MetaInfo{
			Type:    ar.TYPE_MANIFEST,
			Name:    "de.test.app",
			Version: "2023-04-10T20:00:00Z",
			Validity: &ar.Validity{
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
		},
	}

	incompatibleOsManifest = ar.Metadata{
		MetaInfo: ar.MetaInfo{
			Type:    ar.TYPE_MANIFEST,
			Name:    "de.test.os",
			Version: "2023-04-10T20:00:00Z",
			Validity: &ar.Validity{
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
		},
	}

	validMetaInfo = ar.MetaInfo{
		Type:    ar.TYPE_IMAGE_DESCRIPTION,
		Name:    "test-device.test.de",
		Version: "2023-04-10T20:00:00Z",
		Validity: &ar.Validity{
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

	validOmspResponse = ar.Metadata{
		MetaInfo: ar.MetaInfo{
			Type: ar.TYPE_OMSP_RESPONSE,
		},
		OmspResponse: ar.OmspResponse{
			Server:     "https://10.0.2.2:9000/",
			ProducedAt: "2026-04-16T20:00:00Z",
			Responses: []ar.SingleOmspResponse{
				{
					ManifestHash: "rtmhash", //is replaced with hash of signed artefact in the test function
					Status:       ar.OmspStatusGood,
					ThisUpdate:   "2026-04-01T20:00:00Z",
					NextUpdate:   "2030-04-01T20:00:00Z",
				},
			},
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

// rtmManifestWith returns a copy of the valid RTM manifest with the given reference values and
// SNP policy
func rtmManifestWith(components []ar.Component, snpPolicy *ar.SnpPolicy) ar.Metadata {
	m := validRtmManifest
	m.Sbom = &ar.Sbom{Components: components}
	m.SnpPolicy = snpPolicy
	return m
}

func tdxComponent(optional bool) []ar.Component {
	return []ar.Component{{
		Type:     ar.TYPE_FIRMWARE,
		Name:     "MRTD",
		Optional: optional,
		Hashes:   []ar.ReferenceHash{{Alg: "SHA-384", Content: make([]byte, 48)}},
		Properties: []ar.Property{
			{Name: ar.PROPERTY_TRUST_ANCHOR, Value: ar.TRUST_ANCHOR_TDX},
		},
	}}
}
