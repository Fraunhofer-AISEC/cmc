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
	"encoding/base64"
	"encoding/json"
	"testing"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

func Test_verifySwMeasurements(t *testing.T) {
	type args struct {
		swMeasurement ar.Measurement
		nonce         []byte
		cas           []*x509.Certificate
		s             ar.Serializer
		manifests     []ar.MetadataResult
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Valid SW Measurement",
			args: args{
				swMeasurement: ar.Measurement{
					Type:      "SW Measurement",
					Evidence:  validSwEvidence,
					Certs:     validSwCertChain,
					Artifacts: validSwArtifacts,
				},
				nonce:     validSwNonce,
				cas:       []*x509.Certificate{validSwCa},
				s:         ar.JsonSerializer{},
				manifests: []ar.MetadataResult{validUbuntuManifest, validNginxManifest},
			},
			want: true,
		},
		{
			name: "Invalid Nonce",
			args: args{
				swMeasurement: ar.Measurement{
					Type:      "SW Measurement",
					Evidence:  validSwEvidence,
					Certs:     validSwCertChain,
					Artifacts: validSwArtifacts,
				},
				nonce:     invalidSwNonce,
				cas:       []*x509.Certificate{validSwCa},
				s:         ar.JsonSerializer{},
				manifests: []ar.MetadataResult{validUbuntuManifest, validNginxManifest},
			},
			want: false,
		},
		{
			name: "Invalid Refvals",
			args: args{
				swMeasurement: ar.Measurement{
					Type:      "SW Measurement",
					Evidence:  validSwEvidence,
					Certs:     validSwCertChain,
					Artifacts: validSwArtifacts,
				},
				nonce:     validSwNonce,
				cas:       []*x509.Certificate{validSwCa},
				s:         ar.JsonSerializer{},
				manifests: []ar.MetadataResult{invalidManifest, validUbuntuManifest},
			},
			want: false,
		},
		{
			name: "Invalid Artifacts",
			args: args{
				swMeasurement: ar.Measurement{
					Type:      "SW Measurement",
					Evidence:  validSwEvidence,
					Certs:     validSwCertChain,
					Artifacts: invalidSwArtifacts,
				},
				nonce:     validSwNonce,
				cas:       []*x509.Certificate{validSwCa},
				s:         ar.JsonSerializer{},
				manifests: []ar.MetadataResult{validUbuntuManifest, validNginxManifest},
			},
			want: false,
		},
		{
			name: "Invalid Evidence",
			args: args{
				swMeasurement: ar.Measurement{
					Type:      "SW Measurement",
					Evidence:  invalidSwEvidence,
					Certs:     validSwCertChain,
					Artifacts: validSwArtifacts,
				},
				nonce:     validSwNonce,
				cas:       []*x509.Certificate{validSwCa},
				s:         ar.JsonSerializer{},
				manifests: []ar.MetadataResult{validUbuntuManifest, validNginxManifest},
			},
			want: false,
		},
	}
	logrus.SetLevel(logrus.TraceLevel)

	for _, tt := range tests {

		// Preparation
		refVals, err := collectReferenceValues(tt.args.manifests)
		if err != nil {
			log.Debugf("Failed to collect reference values: %v", err)
		}

		// Begin FUT
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := verifySwMeasurements(tt.args.swMeasurement,
				tt.args.nonce,
				tt.args.cas,
				refVals["SW Reference Value"],
				tt.args.s)
			if got.Summary.Success != tt.want {
				t.Errorf("verifySwMeasurements() got = %v, want %v", got.Summary.Success, tt.want)
			}
			if got1 != tt.want {
				t.Errorf("verifySwMeasurements() got = %v, want %v", got1, tt.want)
			}
		})
		// End FUT
	}
}

var (
	validSwArtifacts = []ar.Artifact{
		{
			Type: "SW Eventlog",
			Events: []ar.MeasureEvent{
				{
					Sha256:    dec("07195e879b9724517bf2e9dbcb21096a2d65c2fdf590786422d52cef6549daa0"),
					EventName: "75d95688b827605a6bf29b298d1a81be07e8e6d52830a8d5ae8a5fafad63b159",
					CtrData: &ar.CtrData{
						ConfigSha256: dec("f65a5933aa368e140d547bcb20268a778f0eed459c63a360b4cf53ff08846117"),
						RootfsSha256: dec("b3efcaa760118501b34effbb07d099d774ecf7ee0bddf6233c7e8bc958c16d1e"),
					},
				},
				{
					Sha256:    dec("dd9197d6e671f9e4237971098b7509e4b699dc91e2a1df75a17371276ef82446"),
					EventName: "2cd1a01e0f98dc4b3259fdf2bc213dca4032d70f3fcc3b964b9e3c8d0667b25b",
					CtrData: &ar.CtrData{
						ConfigSha256: dec("5531d2de39a3e607fd2a6e4f4c83f80904164a713644de34db8c6ab85c059bca"),
						RootfsSha256: dec("627a04fe9d8c2b32aa07b6363fbd9ed0f9a533ff0ea9a25804f9cbdd7faba068"),
					},
				},
			},
		},
	}

	invalidSwArtifacts = []ar.Artifact{
		{
			Type: "SW Eventlog",
			Events: []ar.MeasureEvent{
				{
					Sha256:    dec("6dc7a115a4c4a4f02b49cb0866d8f63f33e86cbf933238276411a8f26961e9ff"),
					EventName: "07f475b29a92233363d27544683b5ea04f54ca514d742ab5a0b41bdb5914d4b",
					CtrData: &ar.CtrData{
						ConfigSha256: dec("333c809d8ed04b01af781b964dd05fc888aea04732edcaff9d940757d2e48be8"),
						RootfsSha256: dec("44563228698774cb66bf3fe1432ab3c8ea1adfffd9d6d388bc40d73a68cb533c"),
					},
				},
				{
					Sha256:    dec("715ed62e8fb85decea88ffee33274245d2924e2e961b3cc95be6e09a6ae5a25d"),
					EventName: "e4c079503bff631a3433bf34965eb432ecdd6793654a4b83433fa9981ad1833f",
					CtrData: &ar.CtrData{
						ConfigSha256: dec("362f6c2fbe2eedb86c96cdd0584e28ccbf1542edb2ec3d52ab1dc5151dfacfd0"),
						RootfsSha256: dec("3310d0d0902bc4e5c6c3077910ecd85e303762331fdb5d2f899c30263a5a50c7"),
					},
				},
			},
		},
	}

	validUbuntuRefVal = ar.ReferenceValue{
		Type:     "SW Reference Value",
		SubType:  "OCI Runtime Bundle Rootfs Digest: ubuntu:24.04",
		Sha256:   dec("b3efcaa760118501b34effbb07d099d774ecf7ee0bddf6233c7e8bc958c16d1e"),
		Optional: true,
	}

	validNginxRefVal = ar.ReferenceValue{
		Type:     "SW Reference Value",
		SubType:  "OCI Runtime Bundle Rootfs Digest: nginx:latest",
		Sha256:   dec("627a04fe9d8c2b32aa07b6363fbd9ed0f9a533ff0ea9a25804f9cbdd7faba068"),
		Optional: true,
	}

	invalidSwRefVal = ar.ReferenceValue{
		Type:     "SW Reference Value",
		SubType:  "OCI Runtime Bundle Digest",
		Sha256:   dec("ff5ed62e8fb85decea88ffee33274245d2924e2e961b3cc95be6e09a6ae5a25d"),
		Optional: true,
	}

	validNginxManifest = ar.MetadataResult{
		Metadata: ar.Metadata{
			Manifest: ar.Manifest{
				ReferenceValues: []ar.ReferenceValue{validNginxRefVal},
				OciSpec:         validNginxOciConfig,
			},
		},
	}

	validUbuntuManifest = ar.MetadataResult{
		Metadata: ar.Metadata{
			Manifest: ar.Manifest{
				ReferenceValues: []ar.ReferenceValue{validUbuntuRefVal},
				OciSpec:         validUbuntuOciConfig,
			},
		},
	}

	invalidManifest = ar.MetadataResult{
		Metadata: ar.Metadata{
			Manifest: ar.Manifest{
				ReferenceValues: []ar.ReferenceValue{invalidSwRefVal},
			},
		},
	}

	validSwNonce, _ = base64.StdEncoding.DecodeString("1WXtnpqe2Ic=")

	invalidSwNonce = dec("ff021a63554e0e58")

	validSwAk = conv([]byte(`-----BEGIN CERTIFICATE-----
MIICgDCCAiWgAwIBAgIQJG9X9xbZLAuJPAZTCv3l2DAKBggqhkjOPQQDAjBhMQsw
CQYDVQQGEwJERTESMBAGA1UEBxMJVGVzdCBDaXR5MRUwEwYDVQQKEwxUZXN0IENv
bXBhbnkxEDAOBgNVBAsTB1Jvb3QgQ0ExFTATBgNVBAMTDFRlc3QgUm9vdCBDQTAe
Fw0yNTAxMTYxMzM4MzlaFw0yNTA3MTUxMzM4MzlaMIGgMQswCQYDVQQGEwJERTEL
MAkGA1UECBMCQlkxDzANBgNVBAcTBk11bmljaDEWMBQGA1UECRMNdGVzdHN0cmVl
dCAxNTEOMAwGA1UEERMFODU3NDgxGjAYBgNVBAoTEVRlc3QgT3JnYW5pemF0aW9u
MQ8wDQYDVQQLEwZkZXZpY2UxHjAcBgNVBAMTFWRlLnRlc3Quc3cuYWsuZGV2aWNl
MDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEzHtbk3f2NUzQoFBPB479NfWXe0
9f+dVCDt2CUZEz99Iiixr68YkRI6W+s/b756onmvhod61eWXZpWNtvN91jWjfzB9
MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
DAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUPX06bD5zK6s7VJoTlZvaMHE6r4gwHwYD
VR0jBBgwFoAUrWG77lGTdbtu8pakNt44nxYjPecwCgYIKoZIzj0EAwIDSQAwRgIh
ALkEKLcZ1HlaxTfDtFMFWbzr1pq/PtZoQcQubKjWpTO+AiEAqkMnTAQ5r8onkwyU
uUTXOdGzsuMD65lAB1yAmlvnQWU=
-----END CERTIFICATE-----`))

	validSwCa = conv([]byte(`-----BEGIN CERTIFICATE-----
MIICBzCCAa6gAwIBAgIUHLFAeuszCwaI6BQv8z38oVHNWrIwCgYIKoZIzj0EAwIw
YTELMAkGA1UEBhMCREUxEjAQBgNVBAcTCVRlc3QgQ2l0eTEVMBMGA1UEChMMVGVz
dCBDb21wYW55MRAwDgYDVQQLEwdSb290IENBMRUwEwYDVQQDEwxUZXN0IFJvb3Qg
Q0EwIBcNMjUwMTExMTY0NjAwWhgPMjEyNDEyMTgxNjQ2MDBaMGExCzAJBgNVBAYT
AkRFMRIwEAYDVQQHEwlUZXN0IENpdHkxFTATBgNVBAoTDFRlc3QgQ29tcGFueTEQ
MA4GA1UECxMHUm9vdCBDQTEVMBMGA1UEAxMMVGVzdCBSb290IENBMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEM5VmTYUS/kppMjYI6cFedRN53as3cK16DrZMYsX7
kmx500Uehz77wyty/R6MNbmsammUAYLRpoDtfav6YfjZWaNCMEAwDgYDVR0PAQH/
BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK1hu+5Rk3W7bvKWpDbe
OJ8WIz3nMAoGCCqGSM49BAMCA0cAMEQCIB8ofxoLQphUlWl7kemsoTSDKflekD1U
8RkB8MCHgJzwAiBnaHair33TyJgUgukxBeHoR6woCZ49k9OIOvo9QDH7GQ==
-----END CERTIFICATE-----`))

	validSwCertChain = [][]byte{validSwAk.Raw, validSwCa.Raw}

	validSwEvidence, _ = base64.StdEncoding.DecodeString("eyJwYXlsb2FkIjoiZXlKdWIyNWpaU0k2SWpGWFdIUnVjSEZsTWtsalBTSXNJbk5vWVRJMU5pSTZJblpRTUdkeWIyd3dkMmRqYTAxaWJISlVVRWh4T1hwNloyWnFlbTFzVkUxaWJGUlZOakUwWkhObE9FRTlJbjAiLCJwcm90ZWN0ZWQiOiJleUpoYkdjaU9pSkZVekkxTmlJc0luZzFZeUk2V3lKTlNVbERaMFJEUTBGcFYyZEJkMGxDUVdkSlVVcEhPVmc1ZUdKYVRFRjFTbEJCV2xSRGRqTnNNa1JCUzBKblozRm9hMnBQVUZGUlJFRnFRbWhOVVhOM1ExRlpSRlpSVVVkRmQwcEZVbFJGVTAxQ1FVZEJNVlZGUW5oTlNsWkhWbnBrUTBKRVlWaFNOVTFTVlhkRmQxbEVWbEZSUzBWM2VGVmFXRTR3U1VWT2RtSllRbWhpYm10NFJVUkJUMEpuVGxaQ1FYTlVRakZLZG1JelVXZFJNRVY0UmxSQlZFSm5UbFpDUVUxVVJFWlNiR016VVdkVmJUbDJaRU5DUkZGVVFXVkdkekI1VGxSQmVFMVVXWGhOZWswMFRYcHNZVVozTUhsT1ZFRXpUVlJWZUUxNlRUUk5lbXhoVFVsSFowMVJjM2REVVZsRVZsRlJSMFYzU2tWU1ZFVk1UVUZyUjBFeFZVVkRRazFEVVd4cmVFUjZRVTVDWjA1V1FrRmpWRUpyTVRGaWJXeHFZVVJGVjAxQ1VVZEJNVlZGUTFKTlRtUkhWbnBrU0U0d1kyMVdiR1JEUVhoT1ZFVlBUVUYzUjBFeFZVVkZVazFHVDBSVk0wNUVaM2hIYWtGWlFtZE9Wa0pCYjFSRlZsSnNZek5SWjFRelNtNVpWelZ3WlcxR01HRlhPWFZOVVRoM1JGRlpSRlpSVVV4RmQxcHJXbGhhY0ZreVZYaElha0ZqUW1kT1ZrSkJUVlJHVjFKc1RHNVNiR016VVhWak0yTjFXVmR6ZFZwSFZqSmhWMDVzVFVSQ1drMUNUVWRDZVhGSFUwMDBPVUZuUlVkRFEzRkhVMDAwT1VGM1JVaEJNRWxCUWtWNlNIUmlhek5tTWs1VmVsRnZSa0pRUWpRM09VNW1WMWhsTURsbUsyUldRMFIwTWtOVldrVjZPVGxKYVdsNGNqWTRXV3RTU1RaWEszTXZZamMxTm05dWJYWm9iMlEyTVdWWFdGcHdWMDUwZGs0NU1XcFhhbVo2UWpsTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkSlJtOUVRV1JDWjA1V1NGTlZSVVpxUVZWQ1oyZHlRbWRGUmtKUlkwUkJVVmxKUzNkWlFrSlJWVWhCZDBsM1JFRlpSRlpTTUZSQlVVZ3ZRa0ZKZDBGRVFXUkNaMDVXU0ZFMFJVWm5VVlZRV0RBMllrUTFla3MyY3pkV1NtOVViRnAyWVUxSVJUWnlOR2QzU0hkWlJGWlNNR3BDUW1kM1JtOUJWWEpYUnpjM2JFZFVaR0owZFRod1lXdE9kRFEwYm5oWmFsQmxZM2REWjFsSlMyOWFTWHBxTUVWQmQwbEVVMUZCZDFKblNXaEJUR3RGUzB4aldqRkliR0Y0VkdaRWRFWk5SbGRpZW5JeGNIRXZVSFJhYjFGalVYVmlTMnBYY0ZSUEswRnBSVUZ4YTAxdVZFRlJOWEk0YjI1cmQzbFZkVlZVV0U5a1IzcHpkVTFFTmpWc1FVSXhlVUZ0YkhadVVWZFZQU0lzSWsxSlNVTkNla05EUVdFMlowRjNTVUpCWjBsVlNFeEdRV1YxYzNwRGQyRkpOa0pSZGpoNk16aHZWa2hPVjNKSmQwTm5XVWxMYjFwSmVtb3dSVUYzU1hkWlZFVk1UVUZyUjBFeFZVVkNhRTFEVWtWVmVFVnFRVkZDWjA1V1FrRmpWRU5XVW14ak0xRm5VVEpzTUdWVVJWWk5RazFIUVRGVlJVTm9UVTFXUjFaNlpFTkNSR0l5TVhkWlZ6VTFUVkpCZDBSbldVUldVVkZNUlhka1UySXlPVEJKUlU1Q1RWSlZkMFYzV1VSV1VWRkVSWGQ0VlZwWVRqQkpSa3AyWWpOUloxRXdSWGRKUW1OT1RXcFZkMDFVUlhoTlZGa3dUbXBCZDFkb1oxQk5ha1Y1VGtSRmVVMVVaM2hPYWxFeVRVUkNZVTFIUlhoRGVrRktRbWRPVmtKQldWUkJhMUpHVFZKSmQwVkJXVVJXVVZGSVJYZHNWVnBZVGpCSlJVNXdaRWhyZUVaVVFWUkNaMDVXUWtGdlZFUkdVbXhqTTFGblVUSTVkR05IUm5WbFZFVlJUVUUwUjBFeFZVVkRlRTFJVlcwNWRtUkRRa1JSVkVWV1RVSk5SMEV4VlVWQmVFMU5Wa2RXZW1SRFFsTmlNamt3U1VWT1FrMUdhM2RGZDFsSVMyOWFTWHBxTUVOQlVWbEpTMjlhU1hwcU1FUkJVV05FVVdkQlJVMDFWbTFVV1ZWVEwydHdjRTFxV1VrMlkwWmxaRkpPTlROaGN6TmpTekUyUkhKYVRWbHpXRGRyYlhnMU1EQlZaV2g2TnpkM2VYUjVMMUkyVFU1aWJYTmhiVzFWUVZsTVVuQnZSSFJtWVhZMldXWnFXbGRoVGtOTlJVRjNSR2RaUkZaU01GQkJVVWd2UWtGUlJFRm5SVWROUVRoSFFURlZaRVYzUlVJdmQxRkdUVUZOUWtGbU9IZElVVmxFVmxJd1QwSkNXVVZHU3pGb2RTczFVbXN6VnpkaWRrdFhjRVJpWlU5S09GZEplak51VFVGdlIwTkRjVWRUVFRRNVFrRk5RMEV3WTBGTlJWRkRTVUk0YjJaNGIweFJjR2hWYkZkc04ydGxiWE52VkZORVMyWnNaV3RFTVZVNFVtdENPRTFEU0dkS2VuZEJhVUp1WVVoaGFYSXpNMVI1U21kVlozVnJlRUpsU0c5U05uZHZRMW8wT1dzNVQwbFBkbTg1VVVSSU4wZFJQVDBpWFgwIiwic2lnbmF0dXJlIjoiV0I5VHp3SGd5OUpkM2pCYkdCdFo3SXp3aTJDM2xpSjQ0dHFrcWJFM0NYYnluVUZVMUVCQzNJR3lVYzkzd3JJMjZUamotVVJzWmMzNENsMFFDNmY4WEEifQ==")

	invalidSwEvidence, _ = base64.StdEncoding.DecodeString("eyJwYXlsb2FkIjoiZXlKdWIyNWpaU0k3SWpGWFdIUnVjSEZsTWtsalBTSXNJbk5vWVRJMU5pSTZJblpRTUdkeWIyd3dkMmRqYTAxaWJISlVVRWh4T1hwNloyWnFlbTFzVkUxaWJGUlZOakUwWkhObE9FRTlJbjAiLCJwcm90ZWN0ZWQiOiJleUpoYkdjaU9pSkZVekkxTmlJc0luZzFZeUk2V3lKTlNVbERaMFJEUTBGcFYyZEJkMGxDUVdkSlVVcEhPVmc1ZUdKYVRFRjFTbEJCV2xSRGRqTnNNa1JCUzBKblozRm9hMnBQVUZGUlJFRnFRbWhOVVhOM1ExRlpSRlpSVVVkRmQwcEZVbFJGVTAxQ1FVZEJNVlZGUW5oTlNsWkhWbnBrUTBKRVlWaFNOVTFTVlhkRmQxbEVWbEZSUzBWM2VGVmFXRTR3U1VWT2RtSllRbWhpYm10NFJVUkJUMEpuVGxaQ1FYTlVRakZLZG1JelVXZFJNRVY0UmxSQlZFSm5UbFpDUVUxVVJFWlNiR016VVdkVmJUbDJaRU5DUkZGVVFXVkdkekI1VGxSQmVFMVVXWGhOZWswMFRYcHNZVVozTUhsT1ZFRXpUVlJWZUUxNlRUUk5lbXhoVFVsSFowMVJjM2REVVZsRVZsRlJSMFYzU2tWU1ZFVk1UVUZyUjBFeFZVVkRRazFEVVd4cmVFUjZRVTVDWjA1V1FrRmpWRUpyTVRGaWJXeHFZVVJGVjAxQ1VVZEJNVlZGUTFKTlRtUkhWbnBrU0U0d1kyMVdiR1JEUVhoT1ZFVlBUVUYzUjBFeFZVVkZVazFHVDBSVk0wNUVaM2hIYWtGWlFtZE9Wa0pCYjFSRlZsSnNZek5SWjFRelNtNVpWelZ3WlcxR01HRlhPWFZOVVRoM1JGRlpSRlpSVVV4RmQxcHJXbGhhY0ZreVZYaElha0ZqUW1kT1ZrSkJUVlJHVjFKc1RHNVNiR016VVhWak0yTjFXVmR6ZFZwSFZqSmhWMDVzVFVSQ1drMUNUVWRDZVhGSFUwMDBPVUZuUlVkRFEzRkhVMDAwT1VGM1JVaEJNRWxCUWtWNlNIUmlhek5tTWs1VmVsRnZSa0pRUWpRM09VNW1WMWhsTURsbUsyUldRMFIwTWtOVldrVjZPVGxKYVdsNGNqWTRXV3RTU1RaWEszTXZZamMxTm05dWJYWm9iMlEyTVdWWFdGcHdWMDUwZGs0NU1XcFhhbVo2UWpsTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkSlJtOUVRV1JDWjA1V1NGTlZSVVpxUVZWQ1oyZHlRbWRGUmtKUlkwUkJVVmxKUzNkWlFrSlJWVWhCZDBsM1JFRlpSRlpTTUZSQlVVZ3ZRa0ZKZDBGRVFXUkNaMDVXU0ZFMFJVWm5VVlZRV0RBMllrUTFla3MyY3pkV1NtOVViRnAyWVUxSVJUWnlOR2QzU0hkWlJGWlNNR3BDUW1kM1JtOUJWWEpYUnpjM2JFZFVaR0owZFRod1lXdE9kRFEwYm5oWmFsQmxZM2REWjFsSlMyOWFTWHBxTUVWQmQwbEVVMUZCZDFKblNXaEJUR3RGUzB4aldqRkliR0Y0VkdaRWRFWk5SbGRpZW5JeGNIRXZVSFJhYjFGalVYVmlTMnBYY0ZSUEswRnBSVUZ4YTAxdVZFRlJOWEk0YjI1cmQzbFZkVlZVV0U5a1IzcHpkVTFFTmpWc1FVSXhlVUZ0YkhadVVWZFZQU0lzSWsxSlNVTkNla05EUVdFMlowRjNTVUpCWjBsVlNFeEdRV1YxYzNwRGQyRkpOa0pSZGpoNk16aHZWa2hPVjNKSmQwTm5XVWxMYjFwSmVtb3dSVUYzU1hkWlZFVk1UVUZyUjBFeFZVVkNhRTFEVWtWVmVFVnFRVkZDWjA1V1FrRmpWRU5XVW14ak0xRm5VVEpzTUdWVVJWWk5RazFIUVRGVlJVTm9UVTFXUjFaNlpFTkNSR0l5TVhkWlZ6VTFUVkpCZDBSbldVUldVVkZNUlhka1UySXlPVEJKUlU1Q1RWSlZkMFYzV1VSV1VWRkVSWGQ0VlZwWVRqQkpSa3AyWWpOUloxRXdSWGRKUW1OT1RXcFZkMDFVUlhoTlZGa3dUbXBCZDFkb1oxQk5ha1Y1VGtSRmVVMVVaM2hPYWxFeVRVUkNZVTFIUlhoRGVrRktRbWRPVmtKQldWUkJhMUpHVFZKSmQwVkJXVVJXVVZGSVJYZHNWVnBZVGpCSlJVNXdaRWhyZUVaVVFWUkNaMDVXUWtGdlZFUkdVbXhqTTFGblVUSTVkR05IUm5WbFZFVlJUVUUwUjBFeFZVVkRlRTFJVlcwNWRtUkRRa1JSVkVWV1RVSk5SMEV4VlVWQmVFMU5Wa2RXZW1SRFFsTmlNamt3U1VWT1FrMUdhM2RGZDFsSVMyOWFTWHBxTUVOQlVWbEpTMjlhU1hwcU1FUkJVV05FVVdkQlJVMDFWbTFVV1ZWVEwydHdjRTFxV1VrMlkwWmxaRkpPTlROaGN6TmpTekUyUkhKYVRWbHpXRGRyYlhnMU1EQlZaV2g2TnpkM2VYUjVMMUkyVFU1aWJYTmhiVzFWUVZsTVVuQnZSSFJtWVhZMldXWnFXbGRoVGtOTlJVRjNSR2RaUkZaU01GQkJVVWd2UWtGUlJFRm5SVWROUVRoSFFURlZaRVYzUlVJdmQxRkdUVUZOUWtGbU9IZElVVmxFVmxJd1QwSkNXVVZHU3pGb2RTczFVbXN6VnpkaWRrdFhjRVJpWlU5S09GZEplak51VFVGdlIwTkRjVWRUVFRRNVFrRk5RMEV3WTBGTlJWRkRTVUk0YjJaNGIweFJjR2hWYkZkc04ydGxiWE52VkZORVMyWnNaV3RFTVZVNFVtdENPRTFEU0dkS2VuZEJhVUp1WVVoaGFYSXpNMVI1U21kVlozVnJlRUpsU0c5U05uZHZRMW8wT1dzNVQwbFBkbTg1VVVSSU4wZFJQVDBpWFgwIiwic2lnbmF0dXJlIjoiV0I5VHp3SGd5OUpkM2pCYkdCdFo3SXp3aTJDM2xpSjQ0dHFrcWJFM0NYYnluVUZVMUVCQzNJR3lVYzkzd3JJMjZUamotVVJzWmMzNENsMFFDNmY4WEEifQ==")

	validUbuntuOciConfig = unmarshalSpec([]byte(`{"hooks":{"prestart":[{"args":["libnetwork-setkey","-exec-root=/var/run/docker","<container-id>","<docker-network-controller-id>"],"path":"/usr/bin/dockerd"}]},"hostname":"<container-id>","linux":{"cgroupsPath":"system.slice:docker:<container-id>","maskedPaths":["/proc/asound","/proc/acpi","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/proc/scsi","/sys/firmware","/sys/devices/virtual/powercap"],"namespaces":[{"type":"mount"},{"type":"network"},{"type":"uts"},{"type":"pid"},{"type":"ipc"},{"type":"cgroup"}],"readonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"],"resources":{"blockIO":{},"devices":[{"access":"rwm","allow":false},{"access":"rwm","allow":true,"major":1,"minor":5,"type":"c"},{"access":"rwm","allow":true,"major":1,"minor":3,"type":"c"},{"access":"rwm","allow":true,"major":1,"minor":9,"type":"c"},{"access":"rwm","allow":true,"major":1,"minor":8,"type":"c"},{"access":"rwm","allow":true,"major":5,"minor":0,"type":"c"},{"access":"rwm","allow":true,"major":5,"minor":1,"type":"c"},{"access":"rwm","allow":false,"major":10,"minor":229,"type":"c"},{"access":"rwm","allow":false},{"access":"rwm","allow":true,"major":1,"minor":5,"type":"c"},{"access":"rwm","allow":true,"major":1,"minor":3,"type":"c"},{"access":"rwm","allow":true,"major":1,"minor":9,"type":"c"},{"access":"rwm","allow":true,"major":1,"minor":8,"type":"c"},{"access":"rwm","allow":true,"major":5,"minor":0,"type":"c"},{"access":"rwm","allow":true,"major":5,"minor":1,"type":"c"},{"access":"rwm","allow":false,"major":10,"minor":229,"type":"c"}]},"seccomp":{"architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_X32"],"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"syscalls":[{"action":"SCMP_ACT_ALLOW","names":["accept","accept4","access","adjtimex","alarm","bind","brk","cachestat","capget","capset","chdir","chmod","chown","chown32","clock_adjtime","clock_adjtime64","clock_getres","clock_getres_time64","clock_gettime","clock_gettime64","clock_nanosleep","clock_nanosleep_time64","close","close_range","connect","copy_file_range","creat","dup","dup2","dup3","epoll_create","epoll_create1","epoll_ctl","epoll_ctl_old","epoll_pwait","epoll_pwait2","epoll_wait","epoll_wait_old","eventfd","eventfd2","execve","execveat","exit","exit_group","faccessat","faccessat2","fadvise64","fadvise64_64","fallocate","fanotify_mark","fchdir","fchmod","fchmodat","fchmodat2","fchown","fchown32","fchownat","fcntl","fcntl64","fdatasync","fgetxattr","flistxattr","flock","fork","fremovexattr","fsetxattr","fstat","fstat64","fstatat64","fstatfs","fstatfs64","fsync","ftruncate","ftruncate64","futex","futex_requeue","futex_time64","futex_wait","futex_waitv","futex_wake","futimesat","getcpu","getcwd","getdents","getdents64","getegid","getegid32","geteuid","geteuid32","getgid","getgid32","getgroups","getgroups32","getitimer","getpeername","getpgid","getpgrp","getpid","getppid","getpriority","getrandom","getresgid","getresgid32","getresuid","getresuid32","getrlimit","get_robust_list","getrusage","getsid","getsockname","getsockopt","get_thread_area","gettid","gettimeofday","getuid","getuid32","getxattr","inotify_add_watch","inotify_init","inotify_init1","inotify_rm_watch","io_cancel","ioctl","io_destroy","io_getevents","io_pgetevents","io_pgetevents_time64","ioprio_get","ioprio_set","io_setup","io_submit","ipc","kill","landlock_add_rule","landlock_create_ruleset","landlock_restrict_self","lchown","lchown32","lgetxattr","link","linkat","listen","listxattr","llistxattr","_llseek","lremovexattr","lseek","lsetxattr","lstat","lstat64","madvise","map_shadow_stack","membarrier","memfd_create","memfd_secret","mincore","mkdir","mkdirat","mknod","mknodat","mlock","mlock2","mlockall","mmap","mmap2","mprotect","mq_getsetattr","mq_notify","mq_open","mq_timedreceive","mq_timedreceive_time64","mq_timedsend","mq_timedsend_time64","mq_unlink","mremap","msgctl","msgget","msgrcv","msgsnd","msync","munlock","munlockall","munmap","name_to_handle_at","nanosleep","newfstatat","_newselect","open","openat","openat2","pause","pidfd_open","pidfd_send_signal","pipe","pipe2","pkey_alloc","pkey_free","pkey_mprotect","poll","ppoll","ppoll_time64","prctl","pread64","preadv","preadv2","prlimit64","process_mrelease","pselect6","pselect6_time64","pwrite64","pwritev","pwritev2","read","readahead","readlink","readlinkat","readv","recv","recvfrom","recvmmsg","recvmmsg_time64","recvmsg","remap_file_pages","removexattr","rename","renameat","renameat2","restart_syscall","rmdir","rseq","rt_sigaction","rt_sigpending","rt_sigprocmask","rt_sigqueueinfo","rt_sigreturn","rt_sigsuspend","rt_sigtimedwait","rt_sigtimedwait_time64","rt_tgsigqueueinfo","sched_getaffinity","sched_getattr","sched_getparam","sched_get_priority_max","sched_get_priority_min","sched_getscheduler","sched_rr_get_interval","sched_rr_get_interval_time64","sched_setaffinity","sched_setattr","sched_setparam","sched_setscheduler","sched_yield","seccomp","select","semctl","semget","semop","semtimedop","semtimedop_time64","send","sendfile","sendfile64","sendmmsg","sendmsg","sendto","setfsgid","setfsgid32","setfsuid","setfsuid32","setgid","setgid32","setgroups","setgroups32","setitimer","setpgid","setpriority","setregid","setregid32","setresgid","setresgid32","setresuid","setresuid32","setreuid","setreuid32","setrlimit","set_robust_list","setsid","setsockopt","set_thread_area","set_tid_address","setuid","setuid32","setxattr","shmat","shmctl","shmdt","shmget","shutdown","sigaltstack","signalfd","signalfd4","sigprocmask","sigreturn","socketcall","socketpair","splice","stat","stat64","statfs","statfs64","statx","symlink","symlinkat","sync","sync_file_range","syncfs","sysinfo","tee","tgkill","time","timer_create","timer_delete","timer_getoverrun","timer_gettime","timer_gettime64","timer_settime","timer_settime64","timerfd_create","timerfd_gettime","timerfd_gettime64","timerfd_settime","timerfd_settime64","times","tkill","truncate","truncate64","ugetrlimit","umask","uname","unlink","unlinkat","utime","utimensat","utimensat_time64","utimes","vfork","vmsplice","wait4","waitid","waitpid","write","writev"]},{"action":"SCMP_ACT_ALLOW","names":["process_vm_readv","process_vm_writev","ptrace"]},{"action":"SCMP_ACT_ALLOW","args":[{"index":0,"op":"SCMP_CMP_NE","value":40}],"names":["socket"]},{"action":"SCMP_ACT_ALLOW","args":[{"index":0,"op":"SCMP_CMP_EQ","value":0}],"names":["personality"]},{"action":"SCMP_ACT_ALLOW","args":[{"index":0,"op":"SCMP_CMP_EQ","value":8}],"names":["personality"]},{"action":"SCMP_ACT_ALLOW","args":[{"index":0,"op":"SCMP_CMP_EQ","value":131072}],"names":["personality"]},{"action":"SCMP_ACT_ALLOW","args":[{"index":0,"op":"SCMP_CMP_EQ","value":131080}],"names":["personality"]},{"action":"SCMP_ACT_ALLOW","args":[{"index":0,"op":"SCMP_CMP_EQ","value":4294967295}],"names":["personality"]},{"action":"SCMP_ACT_ALLOW","names":["arch_prctl"]},{"action":"SCMP_ACT_ALLOW","names":["modify_ldt"]},{"action":"SCMP_ACT_ALLOW","args":[{"index":0,"op":"SCMP_CMP_MASKED_EQ","value":2114060288}],"names":["clone"]},{"action":"SCMP_ACT_ERRNO","errnoRet":38,"names":["clone3"]},{"action":"SCMP_ACT_ALLOW","names":["chroot"]}]},"sysctl":{"net.ipv4.ip_unprivileged_port_start":"0","net.ipv4.ping_group_range":"0 2147483647"}},"mounts":[{"destination":"/etc/hostname","options":["rbind","rprivate"],"source":"/var/lib/docker/containers/<container-id>/hostname","type":"bind"},{"destination":"/etc/hosts","options":["rbind","rprivate"],"source":"/var/lib/docker/containers/<container-id>/hosts","type":"bind"},{"destination":"/etc/resolv.conf","options":["rbind","rprivate"],"source":"/var/lib/docker/containers/<container-id>/resolv.conf","type":"bind"},{"destination":"/sys/fs/cgroup","options":["ro","nosuid","noexec","nodev"],"source":"cgroup","type":"cgroup"},{"destination":"/dev/pts","options":["nosuid","noexec","newinstance","ptmxmode=0666","mode=0620","gid=5"],"source":"devpts","type":"devpts"},{"destination":"/dev/mqueue","options":["nosuid","noexec","nodev"],"source":"mqueue","type":"mqueue"},{"destination":"/proc","options":["nosuid","noexec","nodev"],"source":"proc","type":"proc"},{"destination":"/dev/shm","options":["nosuid","noexec","nodev","mode=1777","size=67108864"],"source":"shm","type":"tmpfs"},{"destination":"/sys","options":["nosuid","noexec","nodev","ro"],"source":"sysfs","type":"sysfs"},{"destination":"/dev","options":["nosuid","strictatime","mode=755","size=65536k"],"source":"tmpfs","type":"tmpfs"}],"ociVersion":"1.2.0","process":{"apparmorProfile":"docker-default","args":["/bin/bash"],"capabilities":{"bounding":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"effective":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"permitted":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"]},"cwd":"/","env":["HOSTNAME=<container-id>","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"oomScoreAdj":0,"user":{"additionalGids":[0],"gid":0,"uid":0}}}`))

	validNginxOciConfig = unmarshalSpec([]byte(`{"hooks":{"prestart":[{"args":["libnetwork-setkey","-exec-root=/var/run/docker","<container-id>","<docker-network-controller-id>"],"path":"/usr/bin/dockerd"}]},"hostname":"<container-id>","linux":{"cgroupsPath":"system.slice:docker:<container-id>","maskedPaths":["/proc/asound","/proc/acpi","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/proc/scsi","/sys/firmware","/sys/devices/virtual/powercap"],"namespaces":[{"type":"mount"},{"type":"network"},{"type":"uts"},{"type":"pid"},{"type":"ipc"},{"type":"cgroup"}],"readonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"],"resources":{"blockIO":{},"devices":[{"access":"rwm","allow":false},{"access":"rwm","allow":true,"major":1,"minor":5,"type":"c"},{"access":"rwm","allow":true,"major":1,"minor":3,"type":"c"},{"access":"rwm","allow":true,"major":1,"minor":9,"type":"c"},{"access":"rwm","allow":true,"major":1,"minor":8,"type":"c"},{"access":"rwm","allow":true,"major":5,"minor":0,"type":"c"},{"access":"rwm","allow":true,"major":5,"minor":1,"type":"c"},{"access":"rwm","allow":false,"major":10,"minor":229,"type":"c"},{"access":"rwm","allow":false},{"access":"rwm","allow":true,"major":1,"minor":5,"type":"c"},{"access":"rwm","allow":true,"major":1,"minor":3,"type":"c"},{"access":"rwm","allow":true,"major":1,"minor":9,"type":"c"},{"access":"rwm","allow":true,"major":1,"minor":8,"type":"c"},{"access":"rwm","allow":true,"major":5,"minor":0,"type":"c"},{"access":"rwm","allow":true,"major":5,"minor":1,"type":"c"},{"access":"rwm","allow":false,"major":10,"minor":229,"type":"c"}]},"seccomp":{"architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_X32"],"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"syscalls":[{"action":"SCMP_ACT_ALLOW","names":["accept","accept4","access","adjtimex","alarm","bind","brk","cachestat","capget","capset","chdir","chmod","chown","chown32","clock_adjtime","clock_adjtime64","clock_getres","clock_getres_time64","clock_gettime","clock_gettime64","clock_nanosleep","clock_nanosleep_time64","close","close_range","connect","copy_file_range","creat","dup","dup2","dup3","epoll_create","epoll_create1","epoll_ctl","epoll_ctl_old","epoll_pwait","epoll_pwait2","epoll_wait","epoll_wait_old","eventfd","eventfd2","execve","execveat","exit","exit_group","faccessat","faccessat2","fadvise64","fadvise64_64","fallocate","fanotify_mark","fchdir","fchmod","fchmodat","fchmodat2","fchown","fchown32","fchownat","fcntl","fcntl64","fdatasync","fgetxattr","flistxattr","flock","fork","fremovexattr","fsetxattr","fstat","fstat64","fstatat64","fstatfs","fstatfs64","fsync","ftruncate","ftruncate64","futex","futex_requeue","futex_time64","futex_wait","futex_waitv","futex_wake","futimesat","getcpu","getcwd","getdents","getdents64","getegid","getegid32","geteuid","geteuid32","getgid","getgid32","getgroups","getgroups32","getitimer","getpeername","getpgid","getpgrp","getpid","getppid","getpriority","getrandom","getresgid","getresgid32","getresuid","getresuid32","getrlimit","get_robust_list","getrusage","getsid","getsockname","getsockopt","get_thread_area","gettid","gettimeofday","getuid","getuid32","getxattr","inotify_add_watch","inotify_init","inotify_init1","inotify_rm_watch","io_cancel","ioctl","io_destroy","io_getevents","io_pgetevents","io_pgetevents_time64","ioprio_get","ioprio_set","io_setup","io_submit","ipc","kill","landlock_add_rule","landlock_create_ruleset","landlock_restrict_self","lchown","lchown32","lgetxattr","link","linkat","listen","listxattr","llistxattr","_llseek","lremovexattr","lseek","lsetxattr","lstat","lstat64","madvise","map_shadow_stack","membarrier","memfd_create","memfd_secret","mincore","mkdir","mkdirat","mknod","mknodat","mlock","mlock2","mlockall","mmap","mmap2","mprotect","mq_getsetattr","mq_notify","mq_open","mq_timedreceive","mq_timedreceive_time64","mq_timedsend","mq_timedsend_time64","mq_unlink","mremap","msgctl","msgget","msgrcv","msgsnd","msync","munlock","munlockall","munmap","name_to_handle_at","nanosleep","newfstatat","_newselect","open","openat","openat2","pause","pidfd_open","pidfd_send_signal","pipe","pipe2","pkey_alloc","pkey_free","pkey_mprotect","poll","ppoll","ppoll_time64","prctl","pread64","preadv","preadv2","prlimit64","process_mrelease","pselect6","pselect6_time64","pwrite64","pwritev","pwritev2","read","readahead","readlink","readlinkat","readv","recv","recvfrom","recvmmsg","recvmmsg_time64","recvmsg","remap_file_pages","removexattr","rename","renameat","renameat2","restart_syscall","rmdir","rseq","rt_sigaction","rt_sigpending","rt_sigprocmask","rt_sigqueueinfo","rt_sigreturn","rt_sigsuspend","rt_sigtimedwait","rt_sigtimedwait_time64","rt_tgsigqueueinfo","sched_getaffinity","sched_getattr","sched_getparam","sched_get_priority_max","sched_get_priority_min","sched_getscheduler","sched_rr_get_interval","sched_rr_get_interval_time64","sched_setaffinity","sched_setattr","sched_setparam","sched_setscheduler","sched_yield","seccomp","select","semctl","semget","semop","semtimedop","semtimedop_time64","send","sendfile","sendfile64","sendmmsg","sendmsg","sendto","setfsgid","setfsgid32","setfsuid","setfsuid32","setgid","setgid32","setgroups","setgroups32","setitimer","setpgid","setpriority","setregid","setregid32","setresgid","setresgid32","setresuid","setresuid32","setreuid","setreuid32","setrlimit","set_robust_list","setsid","setsockopt","set_thread_area","set_tid_address","setuid","setuid32","setxattr","shmat","shmctl","shmdt","shmget","shutdown","sigaltstack","signalfd","signalfd4","sigprocmask","sigreturn","socketcall","socketpair","splice","stat","stat64","statfs","statfs64","statx","symlink","symlinkat","sync","sync_file_range","syncfs","sysinfo","tee","tgkill","time","timer_create","timer_delete","timer_getoverrun","timer_gettime","timer_gettime64","timer_settime","timer_settime64","timerfd_create","timerfd_gettime","timerfd_gettime64","timerfd_settime","timerfd_settime64","times","tkill","truncate","truncate64","ugetrlimit","umask","uname","unlink","unlinkat","utime","utimensat","utimensat_time64","utimes","vfork","vmsplice","wait4","waitid","waitpid","write","writev"]},{"action":"SCMP_ACT_ALLOW","names":["process_vm_readv","process_vm_writev","ptrace"]},{"action":"SCMP_ACT_ALLOW","args":[{"index":0,"op":"SCMP_CMP_NE","value":40}],"names":["socket"]},{"action":"SCMP_ACT_ALLOW","args":[{"index":0,"op":"SCMP_CMP_EQ","value":0}],"names":["personality"]},{"action":"SCMP_ACT_ALLOW","args":[{"index":0,"op":"SCMP_CMP_EQ","value":8}],"names":["personality"]},{"action":"SCMP_ACT_ALLOW","args":[{"index":0,"op":"SCMP_CMP_EQ","value":131072}],"names":["personality"]},{"action":"SCMP_ACT_ALLOW","args":[{"index":0,"op":"SCMP_CMP_EQ","value":131080}],"names":["personality"]},{"action":"SCMP_ACT_ALLOW","args":[{"index":0,"op":"SCMP_CMP_EQ","value":4294967295}],"names":["personality"]},{"action":"SCMP_ACT_ALLOW","names":["arch_prctl"]},{"action":"SCMP_ACT_ALLOW","names":["modify_ldt"]},{"action":"SCMP_ACT_ALLOW","args":[{"index":0,"op":"SCMP_CMP_MASKED_EQ","value":2114060288}],"names":["clone"]},{"action":"SCMP_ACT_ERRNO","errnoRet":38,"names":["clone3"]},{"action":"SCMP_ACT_ALLOW","names":["chroot"]}]},"sysctl":{"net.ipv4.ip_unprivileged_port_start":"0","net.ipv4.ping_group_range":"0 2147483647"}},"mounts":[{"destination":"/etc/hostname","options":["rbind","rprivate"],"source":"/var/lib/docker/containers/<container-id>/hostname","type":"bind"},{"destination":"/etc/hosts","options":["rbind","rprivate"],"source":"/var/lib/docker/containers/<container-id>/hosts","type":"bind"},{"destination":"/etc/resolv.conf","options":["rbind","rprivate"],"source":"/var/lib/docker/containers/<container-id>/resolv.conf","type":"bind"},{"destination":"/sys/fs/cgroup","options":["ro","nosuid","noexec","nodev"],"source":"cgroup","type":"cgroup"},{"destination":"/dev/pts","options":["nosuid","noexec","newinstance","ptmxmode=0666","mode=0620","gid=5"],"source":"devpts","type":"devpts"},{"destination":"/dev/mqueue","options":["nosuid","noexec","nodev"],"source":"mqueue","type":"mqueue"},{"destination":"/proc","options":["nosuid","noexec","nodev"],"source":"proc","type":"proc"},{"destination":"/dev/shm","options":["nosuid","noexec","nodev","mode=1777","size=67108864"],"source":"shm","type":"tmpfs"},{"destination":"/sys","options":["nosuid","noexec","nodev","ro"],"source":"sysfs","type":"sysfs"},{"destination":"/dev","options":["nosuid","strictatime","mode=755","size=65536k"],"source":"tmpfs","type":"tmpfs"}],"ociVersion":"1.2.0","process":{"apparmorProfile":"docker-default","args":["/docker-entrypoint.sh","nginx","-g","daemon off;"],"capabilities":{"bounding":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"effective":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"permitted":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"]},"cwd":"/","env":["DYNPKG_RELEASE=1~bookworm","HOSTNAME=<container-id>","NGINX_VERSION=1.27.2","NJS_RELEASE=1~bookworm","NJS_VERSION=0.8.6","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","PKG_RELEASE=1~bookworm"],"oomScoreAdj":0,"user":{"additionalGids":[0],"gid":0,"uid":0}}}`))
)

func unmarshalSpec(raw []byte) *specs.Spec {
	spec := new(specs.Spec)
	err := json.Unmarshal(raw, spec)
	if err != nil {
		log.Errorf("generate test vectors: failed to unmarshal spec: %v", err)
	}
	return spec
}
