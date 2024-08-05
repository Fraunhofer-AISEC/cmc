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
	"crypto/x509"
	"encoding/base64"
	"testing"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

func Test_verifySwMeasurements(t *testing.T) {
	type args struct {
		swMeasurement ar.Measurement
		nonce         []byte
		cas           []*x509.Certificate
		s             ar.Serializer
		refVals       []ar.ReferenceValue
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
				nonce:   validSwNonce,
				cas:     []*x509.Certificate{validSwCa},
				s:       ar.JsonSerializer{},
				refVals: validSwRefVals,
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
				nonce:   invalidSwNonce,
				cas:     []*x509.Certificate{validSwCa},
				s:       ar.JsonSerializer{},
				refVals: validSwRefVals,
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
				nonce:   validSwNonce,
				cas:     []*x509.Certificate{validSwCa},
				s:       ar.JsonSerializer{},
				refVals: invalidSwRefVals,
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
				nonce:   validSwNonce,
				cas:     []*x509.Certificate{validSwCa},
				s:       ar.JsonSerializer{},
				refVals: validSwRefVals,
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
					Artifacts: invalidSwArtifacts,
				},
				nonce:   validSwNonce,
				cas:     []*x509.Certificate{validSwCa},
				s:       ar.JsonSerializer{},
				refVals: validSwRefVals,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got := verifySwMeasurements(tt.args.swMeasurement, tt.args.nonce, tt.args.cas, tt.args.s, tt.args.refVals)
			if got != tt.want {
				t.Errorf("verifySwMeasurements() got = %v, want %v", got, tt.want)
			}
		})
	}
}

var (
	validSwArtifacts = []ar.Artifact{
		{
			Type: "SW Eventlog",
			Events: []ar.MeasureEvent{
				{
					Sha256:    dec("6dc7a115a4c4a4f02b49cb0866d8f63f33e86cbf933238276411a8f26961e9a6"),
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

	validSwRefVals = []ar.ReferenceValue{
		{
			Type:     "SW Reference Value",
			Sha256:   dec("715ed62e8fb85decea88ffee33274245d2924e2e961b3cc95be6e09a6ae5a25d"),
			Name:     "OCI Runtime Bundle Digest: tenzir",
			Optional: true,
		},
		{
			Type:     "SW Reference Value",
			Sha256:   dec("6dc7a115a4c4a4f02b49cb0866d8f63f33e86cbf933238276411a8f26961e9a6"),
			Name:     "OCI Runtime Bundle Digest: rtkcsm",
			Optional: true,
		},
	}

	invalidSwRefVals = []ar.ReferenceValue{
		{
			Type:     "SW Reference Value",
			Sha256:   dec("ff5ed62e8fb85decea88ffee33274245d2924e2e961b3cc95be6e09a6ae5a25d"),
			Name:     "OCI Runtime Bundle Digest: tenzir",
			Optional: true,
		},
		{
			Type:     "SW Reference Value",
			Sha256:   dec("6dc7a115a4c4a4f02b49cb0866d8f63f33e86cbf933238276411a8f26961e9a6"),
			Name:     "OCI Runtime Bundle Digest: rtkcsm",
			Optional: true,
		},
	}

	validSwNonce = dec("89021a63554e0e58")

	invalidSwNonce = dec("ff021a63554e0e58")

	validSwAk = conv([]byte(`-----BEGIN CERTIFICATE-----
MIICuzCCAmGgAwIBAgIQE3yJJSK718VSl4UNgIqNpzAKBggqhkjOPQQDAjBhMQsw
CQYDVQQGEwJERTESMBAGA1UEBxMJVGVzdCBDaXR5MRUwEwYDVQQKEwxUZXN0IENv
bXBhbnkxEDAOBgNVBAsTB1Jvb3QgQ0ExFTATBgNVBAMTDFRlc3QgUm9vdCBDQTAe
Fw0yNDA4MDYxODAwMzZaFw0yNTAyMDIxODAwMzZaMIGdMQswCQYDVQQGEwJERTEL
MAkGA1UECBMCQlkxDzANBgNVBAcTBk11bmljaDEWMBQGA1UECRMNdGVzdHN0cmVl
dCAxNjEOMAwGA1UEERMFODU3NDgxGjAYBgNVBAoTEVRlc3Qgb3JnYW5pemF0aW9u
MQ8wDQYDVQQLEwZkZXZpY2UxGzAZBgNVBAMTEmRlLnRlc3QuaWsuZGV2aWNlMDBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABPFIprOMyXRjShtt88Mi6dPatlNRlhcv
zQaCuHrMTudDqGBRKZi1e6VAXh7+Ct7B3VDmxGmDjo3QrINCwYZs1S+jgb0wgbow
DgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAM
BgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTTjuK3G2wMFJnszTfAG+lIbTJqdDAfBgNV
HSMEGDAWgBRGAy2mnhOO91nZGITXWKGTsHPJOTA7BgNVHREENDAyggkxMjcuMC4w
LjGCCWxvY2FsaG9zdIIabnVjLTAyLmFpc2VjLmZyYXVuaG9mZXIuZGUwCgYIKoZI
zj0EAwIDSAAwRQIgDEB9QmPWFyyiOO0qa236LEBqG2nJvgAN3uxJMN0El+wCIQDH
x/0jlApG+q4X3ot7AbvKXjgJA9B3wxGg9+QZhbKA2A==
-----END CERTIFICATE-----`))

	validSwCa = conv([]byte(`-----BEGIN CERTIFICATE-----
MIICCDCCAa6gAwIBAgIUEImN1VPFfruKHN7uf2rR+AbdDFMwCgYIKoZIzj0EAwIw
YTELMAkGA1UEBhMCREUxEjAQBgNVBAcTCVRlc3QgQ2l0eTEVMBMGA1UEChMMVGVz
dCBDb21wYW55MRAwDgYDVQQLEwdSb290IENBMRUwEwYDVQQDEwxUZXN0IFJvb3Qg
Q0EwIBcNMjQwNjI4MTEwNTAwWhgPMjEyNDA2MDQxMTA1MDBaMGExCzAJBgNVBAYT
AkRFMRIwEAYDVQQHEwlUZXN0IENpdHkxFTATBgNVBAoTDFRlc3QgQ29tcGFueTEQ
MA4GA1UECxMHUm9vdCBDQTEVMBMGA1UEAxMMVGVzdCBSb290IENBMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEXTn3MfowwWQ8vb/MUgHGMitmPly9OW04xmP0FPHS
JfM0/WJBKOIpdPx01GhKD3hgyw1kd8LIqvDx5scb1JU2iqNCMEAwDgYDVR0PAQH/
BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFEYDLaaeE473WdkYhNdY
oZOwc8k5MAoGCCqGSM49BAMCA0gAMEUCICDteP7WnMoCjgaVkeZzFx1uug2h/Z8G
6HhWfMozwVpaAiEAuOyzkVIveBYCN4wG0WfZZqhyeRd0jwwRwUWWg8KKhyg=
-----END CERTIFICATE-----`))

	validSwCertChain = [][]byte{validSwAk.Raw, validSwCa.Raw}

	validSwEvidence, _ = base64.StdEncoding.DecodeString("eyJwYXlsb2FkIjoiaVFJYVkxVk9EbGciLCJwcm90ZWN0ZWQiOiJleUpoYkdjaU9pSkZVekkxTmlJc0luZzFZeUk2V3lKTlNVbERkWHBEUTBGdFIyZEJkMGxDUVdkSlVVVXplVXBLVTBzM01UaFdVMncwVlU1blNYRk9jSHBCUzBKblozRm9hMnBQVUZGUlJFRnFRbWhOVVhOM1ExRlpSRlpSVVVkRmQwcEZVbFJGVTAxQ1FVZEJNVlZGUW5oTlNsWkhWbnBrUTBKRVlWaFNOVTFTVlhkRmQxbEVWbEZSUzBWM2VGVmFXRTR3U1VWT2RtSllRbWhpYm10NFJVUkJUMEpuVGxaQ1FYTlVRakZLZG1JelVXZFJNRVY0UmxSQlZFSm5UbFpDUVUxVVJFWlNiR016VVdkVmJUbDJaRU5DUkZGVVFXVkdkekI1VGtSQk5FMUVXWGhQUkVGM1RYcGFZVVozTUhsT1ZFRjVUVVJKZUU5RVFYZE5lbHBoVFVsSFpFMVJjM2REVVZsRVZsRlJSMFYzU2tWU1ZFVk1UVUZyUjBFeFZVVkRRazFEVVd4cmVFUjZRVTVDWjA1V1FrRmpWRUpyTVRGaWJXeHFZVVJGVjAxQ1VVZEJNVlZGUTFKTlRtUkhWbnBrU0U0d1kyMVdiR1JEUVhoT2FrVlBUVUYzUjBFeFZVVkZVazFHVDBSVk0wNUVaM2hIYWtGWlFtZE9Wa0pCYjFSRlZsSnNZek5SWjJJelNtNVpWelZ3WlcxR01HRlhPWFZOVVRoM1JGRlpSRlpSVVV4RmQxcHJXbGhhY0ZreVZYaEhla0ZhUW1kT1ZrSkJUVlJGYlZKc1RHNVNiR016VVhWaFYzTjFXa2RXTW1GWFRteE5SRUphVFVKTlIwSjVjVWRUVFRRNVFXZEZSME5EY1VkVFRUUTVRWGRGU0VFd1NVRkNVRVpKY0hKUFRYbFlVbXBUYUhSME9EaE5hVFprVUdGMGJFNVNiR2hqZG5wUllVTjFTSEpOVkhWa1JIRkhRbEpMV21reFpUWldRVmhvTnl0RGREZENNMVpFYlhoSGJVUnFiek5SY2tsT1EzZFpXbk14VXl0cVoySXdkMmRpYjNkRVoxbEVWbEl3VUVGUlNDOUNRVkZFUVdkWFowMUNNRWRCTVZWa1NsRlJWMDFDVVVkRFEzTkhRVkZWUmtKM1RVSkNaMmR5UW1kRlJrSlJZMFJCYWtGTlFtZE9Wa2hTVFVKQlpqaEZRV3BCUVUxQ01FZEJNVlZrUkdkUlYwSkNWRlJxZFVzelJ6SjNUVVpLYm5ONlZHWkJSeXRzU1dKVVNuRmtSRUZtUW1kT1ZraFRUVVZIUkVGWFowSlNSMEY1TW0xdWFFOVBPVEZ1V2tkSlZGaFhTMGRVYzBoUVNrOVVRVGRDWjA1V1NGSkZSVTVFUVhsbloydDRUV3BqZFUxRE5IZE1ha2REUTFkNGRsa3lSbk5oUnpsNlpFbEpZV0p1Vm1wTVZFRjVURzFHY0dNeVZtcE1iVnA1V1ZoV2RXRkhPVzFhV0VsMVdrZFZkME5uV1VsTGIxcEplbW93UlVGM1NVUlRRVUYzVWxGSlowUkZRamxSYlZCWFJubDVhVTlQTUhGaE1qTTJURVZDY1VjeWJrcDJaMEZPTTNWNFNrMU9NRVZzSzNkRFNWRkVTSGd2TUdwc1FYQkhLM0UwV0ROdmREZEJZblpMV0dwblNrRTVRak4zZUVkbk9TdFJXbWhpUzBFeVFUMDlJaXdpVFVsSlEwTkVRME5CWVRablFYZEpRa0ZuU1ZWRlNXMU9NVlpRUm1aeWRVdElUamQxWmpKeVVpdEJZbVJFUmsxM1EyZFpTVXR2V2tsNmFqQkZRWGRKZDFsVVJVeE5RV3RIUVRGVlJVSm9UVU5TUlZWNFJXcEJVVUpuVGxaQ1FXTlVRMVpTYkdNelVXZFJNbXd3WlZSRlZrMUNUVWRCTVZWRlEyaE5UVlpIVm5wa1EwSkVZakl4ZDFsWE5UVk5Va0YzUkdkWlJGWlJVVXhGZDJSVFlqSTVNRWxGVGtKTlVsVjNSWGRaUkZaUlVVUkZkM2hWV2xoT01FbEdTblppTTFGblVUQkZkMGxDWTA1TmFsRjNUbXBKTkUxVVJYZE9WRUYzVjJoblVFMXFSWGxPUkVFeVRVUlJlRTFVUVRGTlJFSmhUVWRGZUVONlFVcENaMDVXUWtGWlZFRnJVa1pOVWtsM1JVRlpSRlpSVVVoRmQyeFZXbGhPTUVsRlRuQmtTR3Q0UmxSQlZFSm5UbFpDUVc5VVJFWlNiR016VVdkUk1qbDBZMGRHZFdWVVJWRk5RVFJIUVRGVlJVTjRUVWhWYlRsMlpFTkNSRkZVUlZaTlFrMUhRVEZWUlVGNFRVMVdSMVo2WkVOQ1UySXlPVEJKUlU1Q1RVWnJkMFYzV1VoTGIxcEplbW93UTBGUldVbExiMXBKZW1vd1JFRlJZMFJSWjBGRldGUnVNMDFtYjNkM1YxRTRkbUl2VFZWblNFZE5hWFJ0VUd4NU9VOVhNRFI0YlZBd1JsQklVMHBtVFRBdlYwcENTMDlKY0dSUWVEQXhSMmhMUkROb1ozbDNNV3RrT0V4SmNYWkVlRFZ6WTJJeFNsVXlhWEZPUTAxRlFYZEVaMWxFVmxJd1VFRlJTQzlDUVZGRVFXZEZSMDFCT0VkQk1WVmtSWGRGUWk5M1VVWk5RVTFDUVdZNGQwaFJXVVJXVWpCUFFrSlpSVVpGV1VSTVlXRmxSVFEzTTFka2ExbG9UbVJaYjFwUGQyTTRhelZOUVc5SFEwTnhSMU5OTkRsQ1FVMURRVEJuUVUxRlZVTkpRMFIwWlZBM1YyNU5iME5xWjJGV2EyVmFla1o0TVhWMVp6Sm9MMW80UnpaSWFGZG1UVzk2ZDFad1lVRnBSVUYxVDNsNmExWkpkbVZDV1VOT05IZEhNRmRtV2xweGFIbGxVbVF3YW5kM1VuZFZWMWRuT0V0TGFIbG5QU0pkZlEiLCJzaWduYXR1cmUiOiJ3TFpuNmJ4VTJJdXBhaWdBcmVSVTBoSkxsWURkaFlTSlpUeUprRkJmTjdPVkJWWFZyOUhSWjBLUHhTV0dQQU1TaU00b3dKZGZlSVMtMnBDWVNRUzNmZyJ9")

	invalidSwEvidence, _ = base64.StdEncoding.DecodeString("eyJwYXlsb2FkIjoiMktQejBsNUpTNjAiLCJwcm90ZWN0ZWQiOiJleUpoYkdjaU9pSkZVekkxTmlJc0luZzFZeUk2V3lKTlNVbERka1JEUTBGdFMyZEJkMGxDUVdkSlVrRkxka1ZtTmt0YVQwMUxVbEJsU2s4MlIxVkxiazlKZDBObldVbExiMXBKZW1vd1JVRjNTWGRaVkVWTVRVRnJSMEV4VlVWQ2FFMURVa1ZWZUVWcVFWRkNaMDVXUWtGalZFTldVbXhqTTFGblVUSnNNR1ZVUlZaTlFrMUhRVEZWUlVOb1RVMVdSMVo2WkVOQ1JHSXlNWGRaVnpVMVRWSkJkMFJuV1VSV1VWRk1SWGRrVTJJeU9UQkpSVTVDVFZKVmQwVjNXVVJXVVZGRVJYZDRWVnBZVGpCSlJrcDJZak5SWjFFd1JYZElhR05PVFdwUmQwOUVRVEpOVkdjeFRtcEZkMWRvWTA1TmFsVjNUV3BCZVUxVVp6Rk9ha1YzVjJwRFFtNVVSVXhOUVd0SFFURlZSVUpvVFVOU1JWVjRRM3BCU2tKblRsWkNRV2RVUVd0S1drMVJPSGRFVVZsRVZsRlJTRVYzV2s1a1Z6VndXVEpuZUVacVFWVkNaMDVXUWtGclZFUllVbXhqTTFKNlpFaEtiRnBZVVdkTlZGbDRSR3BCVFVKblRsWkNRa1ZVUWxSbk1VNTZVVFJOVW05M1IwRlpSRlpSVVV0RmVFWlZXbGhPTUVsSE9YbGFNa1oxWVZod2FHUkhiSFppYWtWUVRVRXdSMEV4VlVWRGVFMUhXa2RXTW1GWFRteE5Vbk4zUjFGWlJGWlJVVVJGZUVwcldsTTFNRnBZVGpCTWJXeHlURzFTYkdSdGJHcGFWRUYzVjFSQlZFSm5ZM0ZvYTJwUFVGRkpRa0puWjNGb2EycFBVRkZOUWtKM1RrTkJRVlJqTW01QlpXVm1aMVpqV0hkUVdFMDROVGN5UmpWTlNGRlNNVWxsYVhaeVFXRlRVRkZPVWxvNGExTXdjV0p3TkRsd2NVNTFUVUpoUjJzMU5FdFhNR1p0U2pVMVExb3JVbVJOTjI4MGMwWmhVVWRVVHpVM2J6UkhPVTFKUnpaTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkSlJtOUVRV1JDWjA1V1NGTlZSVVpxUVZWQ1oyZHlRbWRGUmtKUlkwUkJVVmxKUzNkWlFrSlJWVWhCZDBsM1JFRlpSRlpTTUZSQlVVZ3ZRa0ZKZDBGRVFXUkNaMDVXU0ZFMFJVWm5VVlZ4Um1acE5rbEljbmRCWlhOaldVMTJjR2QyTkVwUGFFbzNkbXQzU0hkWlJGWlNNR3BDUW1kM1JtOUJWVkpuVFhSd2NEUlVhblprV2pKU2FVVXhNV2xvYXpkQ2VubFVhM2RQZDFsRVZsSXdVa0pFVVhkTmIwbEtUVlJKTTB4cVFYVk5RelI0WjJkc2MySXlUbWhpUjJoMll6TlRRMGR0TlRGWmVUQjNUV2sxYUdGWVRteFplVFZ0WTIxR01XSnRhSFphYlZaNVRHMVNiRTFCYjBkRFEzRkhVMDAwT1VKQlRVTkJNR2RCVFVWVlEwbFJSSG96WjBRMmJuWlZXbTQzTWtRdlVHTTBNR1ZoTW5kYWQzSmhObWx4Y1dVNWVXdG1WMGQxSzFBNGFYZEpaMDE0Y1RWd04zRndlRTFUVEZCM09HWmFURFZ4VlZrNGNreE1hVUpVWkhoT1psQTBZamswTVZsUFZ6ZzlJaXdpVFVsSlEwTkVRME5CWVRablFYZEpRa0ZuU1ZWRlNXMU9NVlpRUm1aeWRVdElUamQxWmpKeVVpdEJZbVJFUmsxM1EyZFpTVXR2V2tsNmFqQkZRWGRKZDFsVVJVeE5RV3RIUVRGVlJVSm9UVU5TUlZWNFJXcEJVVUpuVGxaQ1FXTlVRMVpTYkdNelVXZFJNbXd3WlZSRlZrMUNUVWRCTVZWRlEyaE5UVlpIVm5wa1EwSkVZakl4ZDFsWE5UVk5Va0YzUkdkWlJGWlJVVXhGZDJSVFlqSTVNRWxGVGtKTlVsVjNSWGRaUkZaUlVVUkZkM2hWV2xoT01FbEdTblppTTFGblVUQkZkMGxDWTA1TmFsRjNUbXBKTkUxVVJYZE9WRUYzVjJoblVFMXFSWGxPUkVFeVRVUlJlRTFVUVRGTlJFSmhUVWRGZUVONlFVcENaMDVXUWtGWlZFRnJVa1pOVWtsM1JVRlpSRlpSVVVoRmQyeFZXbGhPTUVsRlRuQmtTR3Q0UmxSQlZFSm5UbFpDUVc5VVJFWlNiR016VVdkUk1qbDBZMGRHZFdWVVJWRk5RVFJIUVRGVlJVTjRUVWhWYlRsMlpFTkNSRkZVUlZaTlFrMUhRVEZWUlVGNFRVMVdSMVo2WkVOQ1UySXlPVEJKUlU1Q1RVWnJkMFYzV1VoTGIxcEplbW93UTBGUldVbExiMXBKZW1vd1JFRlJZMFJSWjBGRldGUnVNMDFtYjNkM1YxRTRkbUl2VFZWblNFZE5hWFJ0VUd4NU9VOVhNRFI0YlZBd1JsQklVMHBtVFRBdlYwcENTMDlKY0dSUWVEQXhSMmhMUkROb1ozbDNNV3RrT0V4SmNYWkVlRFZ6WTJJeFNsVXlhWEZPUTAxRlFYZEVaMWxFVmxJd1VFRlJTQzlDUVZGRVFXZEZSMDFCT0VkQk1WVmtSWGRGUWk5M1VVWk5RVTFDUVdZNGQwaFJXVVJXVWpCUFFrSlpSVVpGV1VSTVlXRmxSVFEzTTFka2ExbG9UbVJaYjFwUGQyTTRhelZOUVc5SFEwTnhSMU5OTkRsQ1FVMURRVEJuUVUxRlZVTkpRMFIwWlZBM1YyNU5iME5xWjJGV2EyVmFla1o0TVhWMVp6Sm9MMW80UnpaSWFGZG1UVzk2ZDFad1lVRnBSVUYxVDNsNmExWkpkbVZDV1VOT05IZEhNRmRtV2xweGFIbGxVbVF3YW5kM1VuZFZWMWRuT0V0TGFIbG5QU0pkZlEiLCJzaWduYXR1cmUiOiJQVXU4SmV6aml3ZUl0eTRpS3gtQXZMcktqQlpTRHVWUnpsaFNZYTZyNGVfcjN1Qjc1emdQcDZjbWpPWWpjMFkteVdBOVBUMnZqMWFnOUV5OXEyakNOQSJ9")
)
