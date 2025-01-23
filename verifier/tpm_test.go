// Copyright (c) 2021 - 2024 Fraunhofer AISEC
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
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"reflect"
	"testing"

	"github.com/sirupsen/logrus"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

func Test_verifyTpmMeasurements(t *testing.T) {
	type args struct {
		measurements    *ar.Measurement
		nonce           []byte
		s               ar.Serializer
		rootManifest    *ar.MetadataResult
		referenceValues []ar.ReferenceValue
	}
	tests := []struct {
		name  string
		args  args
		want  *ar.MeasurementResult
		want1 bool
	}{
		{
			name: "Valid TPM Measurement Summary",
			args: args{
				measurements: &ar.Measurement{
					Type:      "TPM Measurement",
					Evidence:  validQuote,
					Signature: validSignature,
					Certs:     validTpmCertChain,
					Artifacts: validSummaryHashChain,
				},
				nonce: validTpmNonce,
				s:     ar.JsonSerializer{},
				rootManifest: &ar.MetadataResult{
					Metadata: ar.Metadata{
						Manifest: ar.Manifest{
							CaFingerprint: validCaFingerprint,
						},
					},
				},
				referenceValues: validReferenceValues,
			},
			want:  &validTpmMeasurementResult,
			want1: true,
		},
		{
			name: "Valid TPM Measurement",
			args: args{
				measurements: &ar.Measurement{
					Type:      "TPM Measurement",
					Evidence:  validQuote,
					Signature: validSignature,
					Certs:     validTpmCertChain,
					Artifacts: validHashChain,
				},
				nonce: validTpmNonce,
				s:     ar.JsonSerializer{},
				rootManifest: &ar.MetadataResult{
					Metadata: ar.Metadata{
						Manifest: ar.Manifest{
							CaFingerprint: validCaFingerprint,
						},
					},
				},
				referenceValues: validReferenceValues,
			},
			want:  &validTpmMeasurementResult,
			want1: true,
		},
		{
			name: "Invalid Nonce",
			args: args{
				measurements: &ar.Measurement{
					Type:      "TPM Measurement",
					Evidence:  validQuote,
					Signature: validSignature,
					Certs:     validTpmCertChain,
					Artifacts: validSummaryHashChain,
				},
				nonce: invalidTpmNonce,
				s:     ar.JsonSerializer{},
				rootManifest: &ar.MetadataResult{
					Metadata: ar.Metadata{
						Manifest: ar.Manifest{
							CaFingerprint: validCaFingerprint,
						},
					},
				},
				referenceValues: validReferenceValues,
			},
			want:  nil,
			want1: false,
		},
		{
			name: "Invalid Signature",
			args: args{
				measurements: &ar.Measurement{
					Type:      "TPM Measurement",
					Evidence:  validQuote,
					Signature: invalidSignature,
					Certs:     validTpmCertChain,
					Artifacts: validSummaryHashChain,
				},
				nonce: validTpmNonce,
				s:     ar.JsonSerializer{},
				rootManifest: &ar.MetadataResult{
					Metadata: ar.Metadata{
						Manifest: ar.Manifest{
							CaFingerprint: validCaFingerprint,
						},
					},
				},
				referenceValues: validReferenceValues,
			},
			want:  nil,
			want1: false,
		},
		{
			name: "Invalid HashChain Summary",
			args: args{
				measurements: &ar.Measurement{
					Type:      "TPM Measurement",
					Evidence:  validQuote,
					Signature: validSignature,
					Certs:     validTpmCertChain,
					Artifacts: invalidSummaryHashChain,
				},
				nonce: validTpmNonce,
				s:     ar.JsonSerializer{},
				rootManifest: &ar.MetadataResult{
					Metadata: ar.Metadata{
						Manifest: ar.Manifest{
							CaFingerprint: validCaFingerprint,
						},
					},
				},
				referenceValues: validReferenceValues,
			},
			want:  nil,
			want1: false,
		},
		{
			name: "Invalid HashChain",
			args: args{
				measurements: &ar.Measurement{
					Type:      "TPM Measurement",
					Evidence:  validQuote,
					Signature: validSignature,
					Certs:     validTpmCertChain,
					Artifacts: invalidHashChain,
				},
				nonce: validTpmNonce,
				s:     ar.JsonSerializer{},
				rootManifest: &ar.MetadataResult{
					Metadata: ar.Metadata{
						Manifest: ar.Manifest{
							CaFingerprint: validCaFingerprint,
						},
					},
				},
				referenceValues: validReferenceValues,
			},
			want:  nil,
			want1: false,
		},
		{
			name: "Invalid Reference Values",
			args: args{
				measurements: &ar.Measurement{
					Type:      "TPM Measurement",
					Evidence:  validQuote,
					Signature: invalidSignature,
					Certs:     validTpmCertChain,
					Artifacts: validSummaryHashChain,
				},
				nonce: validTpmNonce,
				s:     ar.JsonSerializer{},
				rootManifest: &ar.MetadataResult{
					Metadata: ar.Metadata{
						Manifest: ar.Manifest{
							CaFingerprint: validCaFingerprint,
						},
					},
				},
				referenceValues: invalidReferenceValues,
			},
			want:  nil,
			want1: false,
		},
		{
			name: "Invalid CA",
			args: args{
				measurements: &ar.Measurement{
					Type:      "TPM Measurement",
					Evidence:  validQuote,
					Signature: validSignature,
					Certs:     validTpmCertChain,
					Artifacts: validSummaryHashChain,
				},
				nonce: validTpmNonce,
				s:     ar.JsonSerializer{},
				rootManifest: &ar.MetadataResult{
					Metadata: ar.Metadata{
						Manifest: ar.Manifest{
							CaFingerprint: invalidCaFingerprint,
						},
					},
				},
				referenceValues: validReferenceValues,
			},
			want:  nil,
			want1: false,
		},
		{
			name: "Invalid Cert Chain",
			args: args{
				measurements: &ar.Measurement{
					Type:      "TPM Measurement",
					Evidence:  validQuote,
					Signature: validSignature,
					Certs:     invalidTpmCertChain,
					Artifacts: validSummaryHashChain,
				},
				nonce: validTpmNonce,
				s:     ar.JsonSerializer{},
				rootManifest: &ar.MetadataResult{
					Metadata: ar.Metadata{
						Manifest: ar.Manifest{
							CaFingerprint: validCaFingerprint,
						},
					},
				},
				referenceValues: validReferenceValues,
			},
			want:  nil,
			want1: false,
		},
	}

	logrus.SetLevel(logrus.TraceLevel)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := verifyTpmMeasurements(*tt.args.measurements, tt.args.nonce, tt.args.s, tt.args.rootManifest, tt.args.referenceValues)
			if got1 != tt.want1 {
				t.Errorf("verifyTpmMeasurements() --GOT1-- = %v, --WANT1-- %v", got1, tt.want1)
			}

			if tt.want != nil && !reflect.DeepEqual(got, tt.want) {
				if !reflect.DeepEqual(got.Artifacts, tt.want.Artifacts) {
					// Output result as json to make it easier to compare
					g, _ := json.Marshal(got.Artifacts)
					w, _ := json.Marshal(tt.want.Artifacts)
					t.Errorf("verifyTpmMeasurements ARTIFACTS Mismatch \n---GOT = %v\n\n--WANT = %v", string(g), string(w))
				}
				if !reflect.DeepEqual(got.TpmResult, tt.want.TpmResult) {
					t.Errorf("verifyTpmMeasurements TPMResult Mismatch \n---GOT = %v\n\n--WANT = %v", got.TpmResult, tt.want.TpmResult)
				}
			}
		})
	}
}

func dec(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("Failed to decode: %v", err)
	}
	return b
}

func conv(d []byte) *x509.Certificate {
	input := d
	block, _ := pem.Decode(d)
	if block != nil {
		input = block.Bytes
	}
	cert, err := x509.ParseCertificate(input)
	if err != nil {
		log.Fatal("failed to convert certificate")
	}
	return cert
}

var (
	validQuote, _ = hex.DecodeString("ff54434780180022000b518b2cf29ba4f1c5ae463aec4159a9b7e7d6ec3b7632eac14119b73d3bb39e930008db6c3c042fa12645000000004c1efc09d977f45ed5c84b9501262219245c49af3000000001000b03120000002083a306865290be1f8912c44dc520f1b9271b9ecd23b2bbf3a41c9586c69464b2")

	validSignature, _ = hex.DecodeString("0014000b0100b03c414fd7ae091f3c0b1bf2917f4e947ce951f36f00107c5ea088c30a4bc20164a9e2a1671209863299b5df0649a93cb50c76b01365f2bdfd8299c4118dd48d7952c9f92957dd3cd78f5935972aa478099a725d57f2ce42e600e0c2cfd537cd8fa708a82c4deaf02959a1fb0a998c8018f598db51217affb8e37a45ae0d07b0ea9e68d8ec5fbb9f9027105ba2bccd0e33decc30cbf8335065efeb124c5c0869fbed3e45378ac580a2ce099470d893685263339291a586fefff0ccee2b811e627509e027d4eb697d490d7d55819dd8233e35d404762f274c0eea8b057e79148aac79834984d47926acb57c1e8e0c1a404d113c7fe39e0a7d6a49ec90e8d07378")

	invalidSignature, _ = hex.DecodeString("0014000b0100740e077a77ff6ac21754d036f751f5f8ec5ec59448aab05bb5fd2b5d81df58bde3550d855ecf16cd25e36b5688122cfaac1a86ab94954b81d49a1b7fc7648ad26b8b808ce846fe7fd49355d2461d049904e97aa687749d55510f09b7c8610b95b6d557ebdaa25a19bfa1663f236419a1a8d974dd05b14de7f28fbce0a54c3ac428a9cf7f0752cc290580ff8d63e33050c0f53582ae24fe4d30792da71d5ef93581e3371147ed4732a0c0c0461489b1b64b1f28dd5153dbc674f04a21e279833433eabec1642cd386fdca6e52b583b2c914ebcd3c7a334214dc5e7c02880b033e321cb261ed6044785e70599d269511f83a20ee45034f0803d623763d461ce763")

	validSummaryHashChain = []ar.Artifact{
		{
			Type:  "PCR Summary",
			Index: 1,
			Events: []ar.MeasureEvent{
				{Sha256: dec("5f96aec0a6b390185495c35bc76dceb9fa6addb4e59b6fc1b3e1992eeb08a5c6")},
			},
		},
		{
			Type:  "PCR Summary",
			Index: 4,
			Events: []ar.MeasureEvent{
				{Sha256: dec("d3f67dbed9bce9d391a3567edad08971339e4dbabadd5b7eaf082860296e5e72")},
			},
		},
	}

	invalidSummaryHashChain = []ar.Artifact{
		{
			Type:  "PCR Summary",
			Index: 1,
			Events: []ar.MeasureEvent{
				{Sha256: dec("2a814d03d22568e2d669595dd8be199fd7b3df2acb8caae38e24e92605e15c80")},
			},
		},
		{
			Type:  "PCR Summary",
			Index: 4,
			Events: []ar.MeasureEvent{
				{Sha256: dec("1fe8f1a49cf178748a6f6167473bca3cf882ff70b4b4e458e2421c871c9c5bb9")},
			},
		},
	}

	validHashChain = []ar.Artifact{
		{
			Type:  "PCR Eventlog",
			Index: 1,
			Events: []ar.MeasureEvent{
				{Sha256: dec("ef5631c7bbb8d98ad220e211933fcde16aac6154cf229fea3c728fb0f2c27e39")},
				{Sha256: dec("131462b45df65ac00834c7e73356c246037456959674acd24b08357690a03845")},
				{Sha256: dec("8574d91b49f1c9a6ecc8b1e8565bd668f819ea8ed73c5f682948141587aecd3b")},
				{Sha256: dec("afffbd73d1e4e658d5a1768f6fa11a6c38a1b5c94694015bc96418a7b5291b39")},
				{Sha256: dec("6cf2851f19f1c3ec3070f20400892cb8e6ee712422efd77d655e2ebde4e00d69")},
				{Sha256: dec("faf98c184d571dd4e928f55bbf3b2a6e0fc60ba1fb393a9552f004f76ecf06a7")},
				{Sha256: dec("b785d921b9516221dff929db343c124a832cceee1b508b36b7eb37dc50fc18d8")},
				{Sha256: dec("df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
				{Sha256: dec("b997bc194a4b65980eb0cb172bd5cc51a6460b79c047a92e8f4ff9f85d578bd4")},
			},
		},
		{
			Type:  "PCR Eventlog",
			Index: 4,
			Events: []ar.MeasureEvent{
				{Sha256: dec("3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba")},
				{Sha256: dec("df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
				{Sha256: dec("dbffd70a2c43fd2c1931f18b8f8c08c5181db15f996f747dfed34def52fad036")},
				{Sha256: dec("acc00aad4b0413a8b349b4493f95830da6a7a44bd6fc1579f6f53c339c26cb05")},
				{Sha256: dec("3ba11d87f4450f0b92bd53676d88a3622220a7d53f0338bf387badc31cf3c025")},
			},
		},
	}

	invalidHashChain = []ar.Artifact{
		{
			Type:  "PCR Eventlog",
			Index: 1,
			Events: []ar.MeasureEvent{
				{Sha256: dec("ff5631c7bbb8d98ad220e211933fcde16aac6154cf229fea3c728fb0f2c27e39")},
				{Sha256: dec("131462b45df65ac00834c7e73356c246037456959674acd24b08357690a03845")},
				{Sha256: dec("8574d91b49f1c9a6ecc8b1e8565bd668f819ea8ed73c5f682948141587aecd3b")},
				{Sha256: dec("afffbd73d1e4e658d5a1768f6fa11a6c38a1b5c94694015bc96418a7b5291b39")},
				{Sha256: dec("6cf2851f19f1c3ec3070f20400892cb8e6ee712422efd77d655e2ebde4e00d69")},
				{Sha256: dec("faf98c184d571dd4e928f55bbf3b2a6e0fc60ba1fb393a9552f004f76ecf06a7")},
				{Sha256: dec("b785d921b9516221dff929db343c124a832cceee1b508b36b7eb37dc50fc18d8")},
				{Sha256: dec("df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
				{Sha256: dec("b997bc194a4b65980eb0cb172bd5cc51a6460b79c047a92e8f4ff9f85d578bd4")},
			},
		},
		{
			Type:  "PCR Eventlog",
			Index: 4,
			Events: []ar.MeasureEvent{
				{Sha256: dec("3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba")},
				{Sha256: dec("df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
				{Sha256: dec("dbffd70a2c43fd2c1931f18b8f8c08c5181db15f996f747dfed34def52fad036")},
				{Sha256: dec("acc00aad4b0413a8b349b4493f95830da6a7a44bd6fc1579f6f53c339c26cb05")},
				{Sha256: dec("3ba11d87f4450f0b92bd53676d88a3622220a7d53f0338bf387badc31cf3c025")},
			},
		},
	}

	validTpmNonce = []byte{0xdb, 0x6c, 0x3c, 0x04, 0x2f, 0xa1, 0x26, 0x45}

	invalidTpmNonce = []byte{0x6d, 0xb4, 0x8f, 0x3e, 0x33, 0xc9, 0x79, 0x2a}

	validAk = conv([]byte("-----BEGIN CERTIFICATE-----\nMIIDGjCCAr+gAwIBAgIBATAKBggqhkjOPQQDAjBhMQswCQYDVQQGEwJERTESMBAG\nA1UEBxMJVGVzdCBDaXR5MRUwEwYDVQQKEwxUZXN0IENvbXBhbnkxEDAOBgNVBAsT\nB1Jvb3QgQ0ExFTATBgNVBAMTDFRlc3QgUm9vdCBDQTAeFw0yMjExMDcwODUxNDla\nFw0yNzEwMTIwODUxNDlaMIGdMQswCQYDVQQGEwJERTELMAkGA1UECBMCQlkxDzAN\nBgNVBAcTBk11bmljaDEWMBQGA1UECRMNdGVzdHN0cmVldCAxNTEOMAwGA1UEERMF\nODU3NDgxGjAYBgNVBAoTEVRlc3QgT3JnYW5pemF0aW9uMQ8wDQYDVQQLEwZkZXZp\nY2UxGzAZBgNVBAMTEmRlLnRlc3QuYWsuZGV2aWNlMDCCASIwDQYJKoZIhvcNAQEB\nBQADggEPADCCAQoCggEBALMxAElQ+xiBcNrfpPNd6ksmoftvdIAwBHaXJXta0JcN\n28aveILx2gWuAlhpB90h0IngWpETUckxmAJ/KvTtsOH1lhRQeWwXLmFciXc2lKD3\nNk//dtp6LVd7WaJzx8MtNMlsrYgG9tpjGggISTQyFACQYnmapbqvf8OS0UP93vUT\neAnCKBRDAOKT3FjpUl6y66buAnU1u1I9N7XBUem6nQSlw9KymrgXSG0Hvbpe7f6c\nWmNJC2dJOdxxpN523Fq9I9iMIOi+K2DXfsw2ShxtIj0NEWx+/gKNhsdVln5EnYar\nSef7N12tHTSZnl6oTWtnTGMaSmOfa1bkEpXguM9xV9cCAwEAAaNgMF4wDgYDVR0P\nAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFNKgV/REoVQpy8eJ/cOR\nXsE58bLRMB8GA1UdIwQYMBaAFD+Fycu3JAX3sNTSRMvABDRDeOICMAoGCCqGSM49\nBAMCA0kAMEYCIQDIC7CTHr1RYwUIvmd+lfZme2g1lUmuLWlWRzpEhP1K5AIhAMnp\nFhf+1eNqcZkg2ISsZ5GefN/A/5xvbQXPj06hHwZq\n-----END CERTIFICATE-----"))

	validCa = conv([]byte("-----BEGIN CERTIFICATE-----\nMIICBjCCAaygAwIBAgIUbzIW+iUiIFmCWbOL4rW4UBQfj7AwCgYIKoZIzj0EAwIw\nYTELMAkGA1UEBhMCREUxEjAQBgNVBAcTCVRlc3QgQ2l0eTEVMBMGA1UEChMMVGVz\ndCBDb21wYW55MRAwDgYDVQQLEwdSb290IENBMRUwEwYDVQQDEwxUZXN0IFJvb3Qg\nQ0EwHhcNMjIxMDIzMTcwMTAwWhcNMjcxMDIyMTcwMTAwWjBhMQswCQYDVQQGEwJE\nRTESMBAGA1UEBxMJVGVzdCBDaXR5MRUwEwYDVQQKEwxUZXN0IENvbXBhbnkxEDAO\nBgNVBAsTB1Jvb3QgQ0ExFTATBgNVBAMTDFRlc3QgUm9vdCBDQTBZMBMGByqGSM49\nAgEGCCqGSM49AwEHA0IABEqaNo91iTSSbc9BL1iIQIVpZLd88RL5LfH15SVugJy4\n3d0jeE+KHtpQA8FpAvxXQHJm31z5V6+oLG4MQfVHN/GjQjBAMA4GA1UdDwEB/wQE\nAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQ/hcnLtyQF97DU0kTLwAQ0\nQ3jiAjAKBggqhkjOPQQDAgNIADBFAiAFsmaZDBu+cfOqX9a5YAOgSeYB4Sb+r18m\nBIcuxwthhgIhALRHfA32ZcOA6piTKtWLZsdsG6CH50KGImHlkj4TwfXw\n-----END CERTIFICATE-----"))

	validCaFingerprint = "9FA4D2FDFD76D3699148CD5529D946DEC80EC32409C120DA866CF9F5BEA6298E"

	invalidCaFingerprint = "AAA4D2FDFD76D3699148CD5529D946DEC80EC32409C120DA866CF9F5BEA6298E"

	invalidCaTpm = conv([]byte("-----BEGIN CERTIFICATE-----\nMIICSDCCAc2gAwIBAgIUHxAyr1Y3QlrYutGU317Uy5FhdpQwCgYIKoZIzj0EAwMw\nYzELMAkGA1UEBhMCREUxETAPBgNVBAcTCEdhcmNoaW5nMRkwFwYDVQQKExBGcmF1\nbmhvZmVyIEFJU0VDMRAwDgYDVQQLEwdSb290IENBMRQwEgYDVQQDEwtJRFMgUm9v\ndCBDQTAeFw0yMjA0MDQxNTE3MDBaFw0yNzA0MDMxNTE3MDBaMGMxCzAJBgNVBAYT\nAkRFMREwDwYDVQQHEwhHYXJjaGluZzEZMBcGA1UEChMQRnJhdW5ob2ZlciBBSVNF\nQzEQMA4GA1UECxMHUm9vdCBDQTEUMBIGA1UEAxMLSURTIFJvb3QgQ0EwdjAQBgcq\nhkjOPQIBBgUrgQQAIgNiAAQSneAVxZRShdfwEu3HtCcwRnV5b4UtOnxJaVZ/bILS\n4dThZVWpXNm+ikvp6Sk0RlI30mKl2X7fX8aRew+HvvFT08xJw9dGAkm2Fsp+4/c7\nM3rMhiHXyCpu/Xg4OlxAYOajQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E\nBTADAQH/MB0GA1UdDgQWBBTyFTqqlt0/YxJBiCB3WM7lkpqWVjAKBggqhkjOPQQD\nAwNpADBmAjEAizrjlmYQmrMbsEaGaFzouMT02iMu0NLILhm1wkfAl3UUWymcliy8\nf1IAI1nO4448AjEAkd74w4WEaTqvslmkPktxNhDA1cVL55LDLbUNXLcSdzr2UBhp\nK8Vv1j4nATtg1Vkf\n-----END CERTIFICATE-----\n"))

	validTpmCertChain   = [][]byte{validAk.Raw, validCa.Raw}
	invalidTpmCertChain = [][]byte{validAk.Raw, invalidCaTpm.Raw}

	validReferenceValues = []ar.ReferenceValue{
		{
			Type:    "TPM Reference Value",
			Sha256:  dec("ef5631c7bbb8d98ad220e211933fcde16aac6154cf229fea3c728fb0f2c27e39"),
			SubType: "EV_CPU_MICROCODE",
			Index:   1,
		},
		{
			Type:    "TPM Reference Value",
			Sha256:  dec("131462b45df65ac00834c7e73356c246037456959674acd24b08357690a03845"),
			SubType: "Unknown Event Type",
			Index:   1,
		},
		{
			Type:    "TPM Reference Value",
			Sha256:  dec("8574d91b49f1c9a6ecc8b1e8565bd668f819ea8ed73c5f682948141587aecd3b"),
			SubType: "EV_NONHOST_CONFIG",
			Index:   1,
		},
		{
			Type:    "TPM Reference Value",
			Sha256:  dec("afffbd73d1e4e658d5a1768f6fa11a6c38a1b5c94694015bc96418a7b5291b39"),
			SubType: "EV_EFI_VARIABLE_BOOT",
			Index:   1,
		},
		{
			Type:    "TPM Reference Value",
			Sha256:  dec("6cf2851f19f1c3ec3070f20400892cb8e6ee712422efd77d655e2ebde4e00d69"),
			SubType: "EV_EFI_VARIABLE_BOOT",
			Index:   1,
		},
		{
			Type:    "TPM Reference Value",
			Sha256:  dec("faf98c184d571dd4e928f55bbf3b2a6e0fc60ba1fb393a9552f004f76ecf06a7"),
			SubType: "EV_EFI_VARIABLE_BOOT",
			Index:   1,
		},
		{
			Type:    "TPM Reference Value",
			Sha256:  dec("b785d921b9516221dff929db343c124a832cceee1b508b36b7eb37dc50fc18d8"),
			SubType: "EV_EFI_VARIABLE_BOOT",
			Index:   1,
		},
		{
			Type:    "TPM Reference Value",
			Sha256:  dec("df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"),
			SubType: "EV_SEPARATOR",
			Index:   1,
		},
		{
			Type:    "TPM Reference Value",
			Sha256:  dec("b997bc194a4b65980eb0cb172bd5cc51a6460b79c047a92e8f4ff9f85d578bd4"),
			SubType: "EV_PLATFORM_CONFIG_FLAGS",
			Index:   1,
		},
		{
			Type:    "TPM Reference Value",
			Sha256:  dec("3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba"),
			SubType: "EV_EFI_ACTION",
			Index:   4,
		},
		{
			Type:    "TPM Reference Value",
			Sha256:  dec("df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"),
			SubType: "EV_SEPARATOR",
			Index:   4,
		},
		{
			Type:    "TPM Reference Value",
			Sha256:  dec("dbffd70a2c43fd2c1931f18b8f8c08c5181db15f996f747dfed34def52fad036"),
			SubType: "EV_EFI_BOOT_SERVICES_APPLICATION",
			Index:   4,
		},
		{
			Type:    "TPM Reference Value",
			Sha256:  dec("acc00aad4b0413a8b349b4493f95830da6a7a44bd6fc1579f6f53c339c26cb05"),
			SubType: "EV_EFI_BOOT_SERVICES_APPLICATION",
			Index:   4,
		},
		{
			Type:    "TPM Reference Value",
			Sha256:  dec("3ba11d87f4450f0b92bd53676d88a3622220a7d53f0338bf387badc31cf3c025"),
			SubType: "EV_EFI_BOOT_SERVICES_APPLICATION",
			Index:   4,
		},
	}

	invalidReferenceValues = []ar.ReferenceValue{
		{
			Type:    "TPM Reference Value",
			Sha256:  dec("1310b2b63dc1222516e5c12cedc1cc48e338f85430849b5a5b5256467e2cd0f0"),
			SubType: "SINIT ACM Digest",
			Index:   4,
		},
	}

	validResult = ar.Result{
		Success: true,
	}

	validArtifacts = []ar.DigestResult{
		{
			Digest:   "ef5631c7bbb8d98ad220e211933fcde16aac6154cf229fea3c728fb0f2c27e39",
			SubType:  "EV_CPU_MICROCODE",
			Index:    1,
			Success:  true,
			Launched: true,
		},
		{
			Digest:   "131462b45df65ac00834c7e73356c246037456959674acd24b08357690a03845",
			SubType:  "Unknown Event Type",
			Index:    1,
			Success:  true,
			Launched: true,
		},
		{
			Digest:   "8574d91b49f1c9a6ecc8b1e8565bd668f819ea8ed73c5f682948141587aecd3b",
			SubType:  "EV_NONHOST_CONFIG",
			Index:    1,
			Success:  true,
			Launched: true,
		},
		{
			Digest:   "afffbd73d1e4e658d5a1768f6fa11a6c38a1b5c94694015bc96418a7b5291b39",
			SubType:  "EV_EFI_VARIABLE_BOOT",
			Index:    1,
			Success:  true,
			Launched: true,
		},
		{
			Digest:   "6cf2851f19f1c3ec3070f20400892cb8e6ee712422efd77d655e2ebde4e00d69",
			SubType:  "EV_EFI_VARIABLE_BOOT",
			Index:    1,
			Success:  true,
			Launched: true,
		},
		{
			Digest:   "faf98c184d571dd4e928f55bbf3b2a6e0fc60ba1fb393a9552f004f76ecf06a7",
			SubType:  "EV_EFI_VARIABLE_BOOT",
			Index:    1,
			Success:  true,
			Launched: true,
		},
		{
			Digest:   "b785d921b9516221dff929db343c124a832cceee1b508b36b7eb37dc50fc18d8",
			SubType:  "EV_EFI_VARIABLE_BOOT",
			Index:    1,
			Success:  true,
			Launched: true,
		},
		{
			Digest:   "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
			SubType:  "EV_SEPARATOR",
			Index:    1,
			Success:  true,
			Launched: true,
		},
		{
			Digest:   "b997bc194a4b65980eb0cb172bd5cc51a6460b79c047a92e8f4ff9f85d578bd4",
			SubType:  "EV_PLATFORM_CONFIG_FLAGS",
			Index:    1,
			Success:  true,
			Launched: true,
		},
		{
			Digest:   "3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba",
			SubType:  "EV_EFI_ACTION",
			Index:    4,
			Success:  true,
			Launched: true,
		},
		{
			Digest:   "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
			SubType:  "EV_SEPARATOR",
			Index:    4,
			Success:  true,
			Launched: true,
		},
		{
			Digest:   "dbffd70a2c43fd2c1931f18b8f8c08c5181db15f996f747dfed34def52fad036",
			SubType:  "EV_EFI_BOOT_SERVICES_APPLICATION",
			Index:    4,
			Success:  true,
			Launched: true,
		},
		{
			Digest:   "acc00aad4b0413a8b349b4493f95830da6a7a44bd6fc1579f6f53c339c26cb05",
			SubType:  "EV_EFI_BOOT_SERVICES_APPLICATION",
			Index:    4,
			Success:  true,
			Launched: true,
		},
		{
			Digest:   "3ba11d87f4450f0b92bd53676d88a3622220a7d53f0338bf387badc31cf3c025",
			SubType:  "EV_EFI_BOOT_SERVICES_APPLICATION",
			Index:    4,
			Success:  true,
			Launched: true,
		},
	}

	deviceCertserial, _ = new(big.Int).SetString("1", 10)
	caCertserial, _     = new(big.Int).SetString("634815014411613577372985193537194269253199433648", 10)

	validSignatureResult = ar.SignatureResult{
		Certs: [][]ar.X509CertExtracted{
			{
				{
					Version:      3,
					SerialNumber: deviceCertserial,
					Issuer: ar.X509Name{
						Country:            []string{"DE"},
						Organization:       []string{"Test Company"},
						OrganizationalUnit: []string{"Root CA"},
						Locality:           []string{"Test City"},
						CommonName:         "Test Root CA",
					},
					Subject: ar.X509Name{
						Country:            []string{"DE"},
						Organization:       []string{"Test Organization"},
						OrganizationalUnit: []string{"device"},
						Locality:           []string{"Munich"},
						Province:           []string{"BY"},
						StreetAddress:      []string{"teststreet 15"},
						PostalCode:         []string{"85748"},
						CommonName:         "de.test.ak.device0",
					},
					Validity: ar.Validity{
						NotBefore: "2022-11-07 08:51:49 +0000 UTC",
						NotAfter:  "2027-10-12 08:51:49 +0000 UTC",
					},
					KeyUsage:           []string{"Digital Signature"},
					SignatureAlgorithm: "ECDSA-SHA256",
					PublicKeyAlgorithm: "RSA",
					PublicKey:          "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAszEASVD7GIFw2t+k813q\nSyah+290gDAEdpcle1rQlw3bxq94gvHaBa4CWGkH3SHQieBakRNRyTGYAn8q9O2w\n4fWWFFB5bBcuYVyJdzaUoPc2T/922notV3tZonPHwy00yWytiAb22mMaCAhJNDIU\nAJBieZqluq9/w5LRQ/3e9RN4CcIoFEMA4pPcWOlSXrLrpu4CdTW7Uj03tcFR6bqd\nBKXD0rKauBdIbQe9ul7t/pxaY0kLZ0k53HGk3nbcWr0j2Iwg6L4rYNd+zDZKHG0i\nPQ0RbH7+Ao2Gx1WWfkSdhqtJ5/s3Xa0dNJmeXqhNa2dMYxpKY59rVuQSleC4z3FX\n1wIDAQAB\n-----END PUBLIC KEY-----\n",
					Extensions: []ar.PkixExtension{
						{
							Id:       "2.5.29.15",
							Critical: true,
							Value:    []byte{0x03, 0x02, 0x07, 0x80},
						},
						{
							Id:       "2.5.29.19",
							Critical: true,
							Value:    []byte{0x30, 0x00},
						},
						{
							Id:       "2.5.29.14",
							Critical: false,
							Value:    []byte{0x04, 0x14, 0xd2, 0xa0, 0x57, 0xf4, 0x44, 0xa1, 0x54, 0x29, 0xcb, 0xc7, 0x89, 0xfd, 0xc3, 0x91, 0x5e, 0xc1, 0x39, 0xf1, 0xb2, 0xd1},
						},
						{
							Id:       "2.5.29.35",
							Critical: false,
							Value:    []byte{0x30, 0x16, 0x80, 0x14, 0x3f, 0x85, 0xc9, 0xcb, 0xb7, 0x24, 0x05, 0xf7, 0xb0, 0xd4, 0xd2, 0x44, 0xcb, 0xc0, 0x04, 0x34, 0x43, 0x78, 0xe2, 0x02},
						},
					},
					ExtKeyUsage:           []string{},
					BasicConstraintsValid: true,
					MaxPathLen:            -1,
					SubjectKeyId:          []byte{0xd2, 0xa0, 0x57, 0xf4, 0x44, 0xa1, 0x54, 0x29, 0xcb, 0xc7, 0x89, 0xfd, 0xc3, 0x91, 0x5e, 0xc1, 0x39, 0xf1, 0xb2, 0xd1},
					AuthorityKeyId:        []byte{0x3f, 0x85, 0xc9, 0xcb, 0xb7, 0x24, 0x5, 0xf7, 0xb0, 0xd4, 0xd2, 0x44, 0xcb, 0xc0, 0x4, 0x34, 0x43, 0x78, 0xe2, 0x02},
				},
				{
					Version:      3,
					SerialNumber: caCertserial,
					Issuer: ar.X509Name{
						Country:            []string{"DE"},
						Organization:       []string{"Test Company"},
						OrganizationalUnit: []string{"Root CA"},
						Locality:           []string{"Test City"},
						CommonName:         "Test Root CA",
					},
					Subject: ar.X509Name{
						Country:            []string{"DE"},
						Organization:       []string{"Test Company"},
						OrganizationalUnit: []string{"Root CA"},
						Locality:           []string{"Test City"},
						CommonName:         "Test Root CA",
					},
					Validity: ar.Validity{
						NotBefore: "2022-10-23 17:01:00 +0000 UTC",
						NotAfter:  "2027-10-22 17:01:00 +0000 UTC",
					},
					KeyUsage:           []string{"Cert Sign", "CRL Sign"},
					SignatureAlgorithm: "ECDSA-SHA256",
					PublicKeyAlgorithm: "ECDSA",
					PublicKey:          "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESpo2j3WJNJJtz0EvWIhAhWlkt3zx\nEvkt8fXlJW6AnLjd3SN4T4oe2lADwWkC/FdAcmbfXPlXr6gsbgxB9Uc38Q==\n-----END PUBLIC KEY-----\n",
					Extensions: []ar.PkixExtension{
						{
							Id:       "2.5.29.15",
							Critical: true,
							Value:    []byte{0x03, 0x02, 0x01, 0x06},
						},
						{
							Id:       "2.5.29.19",
							Critical: true,
							Value:    []byte{0x30, 0x03, 0x01, 0x01, 0xff},
						},
						{
							Id:       "2.5.29.14",
							Critical: false,
							Value:    []byte{0x04, 0x14, 0x3f, 0x85, 0xc9, 0xcb, 0xb7, 0x24, 0x05, 0xf7, 0xb0, 0xd4, 0xd2, 0x44, 0xcb, 0xc0, 0x04, 0x34, 0x43, 0x78, 0xe2, 0x02},
						},
					},
					ExtKeyUsage:           []string{},
					BasicConstraintsValid: true,
					IsCA:                  true,
					MaxPathLen:            -1,
					SubjectKeyId:          []byte{0x3f, 0x85, 0xc9, 0xcb, 0xb7, 0x24, 0x5, 0xf7, 0xb0, 0xd4, 0xd2, 0x44, 0xcb, 0xc0, 0x4, 0x34, 0x43, 0x78, 0xe2, 0x02},
					AuthorityKeyId:        nil,
				},
			},
		},
		SignCheck:      validResult,
		CertChainCheck: validResult,
	}

	validTpmMeasurementResult = ar.MeasurementResult{
		Type:      "TPM Result",
		Summary:   validResult,
		Freshness: validResult,
		Signature: validSignatureResult,
		Artifacts: validArtifacts,
		TpmResult: &ar.TpmResult{
			PcrMatch: []ar.DigestResult{
				{
					Index:   1,
					Digest:  "5f96aec0a6b390185495c35bc76dceb9fa6addb4e59b6fc1b3e1992eeb08a5c6",
					Success: true,
				},
				{
					Index:   4,
					Digest:  "d3f67dbed9bce9d391a3567edad08971339e4dbabadd5b7eaf082860296e5e72",
					Success: true,
				},
			},
			AggPcrQuoteMatch: validResult,
		},
	}
)
