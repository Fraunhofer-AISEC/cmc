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
		name  string
		args  args
		want  ar.Status
		want1 bool
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
				manifests: []ar.MetadataResult{validUbuntuManifest},
			},
			want:  ar.StatusSuccess,
			want1: true,
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
				manifests: []ar.MetadataResult{validUbuntuManifest},
			},
			want:  ar.StatusFail,
			want1: false,
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
				manifests: []ar.MetadataResult{invalidRefvalManifest},
			},
			want:  ar.StatusFail,
			want1: false,
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
				manifests: []ar.MetadataResult{validUbuntuManifest},
			},
			want:  ar.StatusFail,
			want1: false,
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
				manifests: []ar.MetadataResult{validUbuntuManifest},
			},
			want:  ar.StatusFail,
			want1: false,
		},
		{
			name: "Invalid OCI Config",
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
				manifests: []ar.MetadataResult{invalidOciConfigUbuntuManifest},
			},
			want:  ar.StatusFail,
			want1: false,
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
			if got.Summary.Status != tt.want {
				t.Errorf("verifySwMeasurements() got = %v, want %v", got.Summary.Status, tt.want)
			}
			if got1 != tt.want1 {
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
					Sha256:    dec("4df198145daeb97c758b6764f9bbaa982207b022c943949942c8be7a688ab4d7"),
					EventName: "359e464721925b79c836b8a7997b5645d9b3a6b46998b7377ebec72cb971b94b",
					CtrData: &ar.CtrData{
						ConfigSha256: dec("c92d8fe5d63250b2895d4fa7dc16e3f67bd57d8d428c6cbb614619bdee84ee26"),
						RootfsSha256: dec("b3efcaa760118501b34effbb07d099d774ecf7ee0bddf6233c7e8bc958c16d1e"),
						OciSpec:      validUbuntuOciConfig,
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
						OciSpec:      validUbuntuOciConfig,
					},
				},
			},
		},
	}

	validUbuntuRefVal = ar.ReferenceValue{
		Type:     "SW Reference Value",
		SubType:  "OCI Runtime Bundle Rootfs Digest: 359e464721925b79c836b8a7997b5645d9b3a6b46998b7377ebec72cb971b94b",
		Sha256:   dec("b3efcaa760118501b34effbb07d099d774ecf7ee0bddf6233c7e8bc958c16d1e"),
		Optional: true,
	}

	invalidSwRefVal = ar.ReferenceValue{
		Type:     "SW Reference Value",
		SubType:  "OCI Runtime Bundle Digest",
		Sha256:   dec("ff5ed62e8fb85decea88ffee33274245d2924e2e961b3cc95be6e09a6ae5a25d"),
		Optional: true,
	}

	validUbuntuManifest = ar.MetadataResult{
		Metadata: ar.Metadata{
			Manifest: ar.Manifest{
				ReferenceValues: []ar.ReferenceValue{validUbuntuRefVal},
				OciSpec:         validUbuntuOciConfig,
			},
		},
	}

	invalidRefvalManifest = ar.MetadataResult{
		Metadata: ar.Metadata{
			Manifest: ar.Manifest{
				ReferenceValues: []ar.ReferenceValue{invalidSwRefVal},
			},
		},
	}

	invalidOciConfigUbuntuManifest = ar.MetadataResult{
		Metadata: ar.Metadata{
			Manifest: ar.Manifest{
				ReferenceValues: []ar.ReferenceValue{validUbuntuRefVal},
				OciSpec:         invalidUbuntuOciConfig,
			},
		},
	}

	validSwNonce = dec("7a9368d7ef7796e2")

	invalidSwNonce = dec("ff021a63554e0e58")

	validSwAk = conv([]byte(`-----BEGIN CERTIFICATE-----
MIICgjCCAiigAwIBAgIRALNVA/kdknQk5FeLMw/if7QwCgYIKoZIzj0EAwIwYTEL
MAkGA1UEBhMCREUxEjAQBgNVBAcTCVRlc3QgQ2l0eTEVMBMGA1UEChMMVGVzdCBD
b21wYW55MRAwDgYDVQQLEwdSb290IENBMRUwEwYDVQQDEwxUZXN0IFJvb3QgQ0Ew
IBcNMjUwNzI0MDc0NDI5WhgPMjEyNTA3MDEwNzQ0MjlaMIGgMQswCQYDVQQGEwJE
RTELMAkGA1UECBMCQlkxDzANBgNVBAcTBk11bmljaDEWMBQGA1UECRMNdGVzdHN0
cmVldCAxNTEOMAwGA1UEERMFODU3NDgxGjAYBgNVBAoTEVRlc3QgT3JnYW5pemF0
aW9uMQ8wDQYDVQQLEwZkZXZpY2UxHjAcBgNVBAMTFWRlLnRlc3Quc3cuYWsuZGV2
aWNlMDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOJQRf5UcbV1XKGVRIWMjAhu
RN4bkUoNwcE1x9UH2c90BnPRR0r0wN8OZo2pj+VaImvpSjafVWsxknjk8+ghNyuj
fzB9MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH
AwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUtcM3sFG27seAZvRnac0675Yhqikw
HwYDVR0jBBgwFoAUCvxFgZW8ajY3AXQzumYRCs/IldcwCgYIKoZIzj0EAwIDSAAw
RQIgAf/Fysl2WIkXnaKeP+gJHn846MZ9nexzbRPyg6PSRG4CIQD3nmVubcUcHIbe
8M4mTA8mMTpezihNmWlAzSQOGbj0Iw==
-----END CERTIFICATE-----`))

	validSwCa = conv([]byte(`-----BEGIN CERTIFICATE-----
MIICCDCCAa6gAwIBAgIUWt85/7XJ0wUBuEgeIEA/S9aUA8UwCgYIKoZIzj0EAwIw
YTELMAkGA1UEBhMCREUxEjAQBgNVBAcTCVRlc3QgQ2l0eTEVMBMGA1UEChMMVGVz
dCBDb21wYW55MRAwDgYDVQQLEwdSb290IENBMRUwEwYDVQQDEwxUZXN0IFJvb3Qg
Q0EwIBcNMjUwNzI1MDczMjAwWhgPMjEyNTA3MDEwNzMyMDBaMGExCzAJBgNVBAYT
AkRFMRIwEAYDVQQHEwlUZXN0IENpdHkxFTATBgNVBAoTDFRlc3QgQ29tcGFueTEQ
MA4GA1UECxMHUm9vdCBDQTEVMBMGA1UEAxMMVGVzdCBSb290IENBMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEiFEEPux3zrUt2SDt+wHnPv+0kKEbWRALabHbGsW/
8xjWymgdoEO8mRPMYScJGD77I8cv7p2PkOzR5RPCIT/40aNCMEAwDgYDVR0PAQH/
BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFAr8RYGVvGo2NwF0M7pm
EQrPyJXXMAoGCCqGSM49BAMCA0gAMEUCIGK9/Y2Lf8a3woMbuZ7TxzlWk0RN9BaA
o4bXS7AHSCEYAiEAg8fmgTsTCeNEht2Y58hfxDQNQnA5PQmTCZZ2Sm8YLcM=
-----END CERTIFICATE-----`))

	validSwCertChain = [][]byte{validSwAk.Raw, validSwCa.Raw}

	validSwEvidence = []byte(`{"payload":"eyJub25jZSI6ImVwTm8xKzkzbHVJPSIsInNoYTI1NiI6IjNwYUptcEY4QUlxR3NBcDJLSC9IdjlLZTZDL3V4QUU4R0oyNTlPQUJRckk9In0","protected":"eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDZ2pDQ0FpaWdBd0lCQWdJUkFMTlZBL2tka25RazVGZUxNdy9pZjdRd0NnWUlLb1pJemowRUF3SXdZVEVMTUFrR0ExVUVCaE1DUkVVeEVqQVFCZ05WQkFjVENWUmxjM1FnUTJsMGVURVZNQk1HQTFVRUNoTU1WR1Z6ZENCRGIyMXdZVzU1TVJBd0RnWURWUVFMRXdkU2IyOTBJRU5CTVJVd0V3WURWUVFERXd4VVpYTjBJRkp2YjNRZ1EwRXdJQmNOTWpVd056STBNRGMwTkRJNVdoZ1BNakV5TlRBM01ERXdOelEwTWpsYU1JR2dNUXN3Q1FZRFZRUUdFd0pFUlRFTE1Ba0dBMVVFQ0JNQ1Fsa3hEekFOQmdOVkJBY1RCazExYm1samFERVdNQlFHQTFVRUNSTU5kR1Z6ZEhOMGNtVmxkQ0F4TlRFT01Bd0dBMVVFRVJNRk9EVTNORGd4R2pBWUJnTlZCQW9URVZSbGMzUWdUM0puWVc1cGVtRjBhVzl1TVE4d0RRWURWUVFMRXdaa1pYWnBZMlV4SGpBY0JnTlZCQU1URldSbExuUmxjM1F1YzNjdVlXc3VaR1YyYVdObE1EQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJPSlFSZjVVY2JWMVhLR1ZSSVdNakFodVJONGJrVW9Od2NFMXg5VUgyYzkwQm5QUlIwcjB3TjhPWm8ycGorVmFJbXZwU2phZlZXc3hrbmprOCtnaE55dWpmekI5TUE0R0ExVWREd0VCL3dRRUF3SUZvREFkQmdOVkhTVUVGakFVQmdnckJnRUZCUWNEQVFZSUt3WUJCUVVIQXdJd0RBWURWUjBUQVFIL0JBSXdBREFkQmdOVkhRNEVGZ1FVdGNNM3NGRzI3c2VBWnZSbmFjMDY3NVlocWlrd0h3WURWUjBqQkJnd0ZvQVVDdnhGZ1pXOGFqWTNBWFF6dW1ZUkNzL0lsZGN3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUlnQWYvRnlzbDJXSWtYbmFLZVArZ0pIbjg0Nk1aOW5leHpiUlB5ZzZQU1JHNENJUUQzbm1WdWJjVWNISWJlOE00bVRBOG1NVHBlemloTm1XbEF6U1FPR2JqMEl3PT0iLCJNSUlDQ0RDQ0FhNmdBd0lCQWdJVVd0ODUvN1hKMHdVQnVFZ2VJRUEvUzlhVUE4VXdDZ1lJS29aSXpqMEVBd0l3WVRFTE1Ba0dBMVVFQmhNQ1JFVXhFakFRQmdOVkJBY1RDVlJsYzNRZ1EybDBlVEVWTUJNR0ExVUVDaE1NVkdWemRDQkRiMjF3WVc1NU1SQXdEZ1lEVlFRTEV3ZFNiMjkwSUVOQk1SVXdFd1lEVlFRREV3eFVaWE4wSUZKdmIzUWdRMEV3SUJjTk1qVXdOekkxTURjek1qQXdXaGdQTWpFeU5UQTNNREV3TnpNeU1EQmFNR0V4Q3pBSkJnTlZCQVlUQWtSRk1SSXdFQVlEVlFRSEV3bFVaWE4wSUVOcGRIa3hGVEFUQmdOVkJBb1RERlJsYzNRZ1EyOXRjR0Z1ZVRFUU1BNEdBMVVFQ3hNSFVtOXZkQ0JEUVRFVk1CTUdBMVVFQXhNTVZHVnpkQ0JTYjI5MElFTkJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVpRkVFUHV4M3pyVXQyU0R0K3dIblB2KzBrS0ViV1JBTGFiSGJHc1cvOHhqV3ltZ2RvRU84bVJQTVlTY0pHRDc3SThjdjdwMlBrT3pSNVJQQ0lULzQwYU5DTUVBd0RnWURWUjBQQVFIL0JBUURBZ0VHTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3SFFZRFZSME9CQllFRkFyOFJZR1Z2R28yTndGME03cG1FUXJQeUpYWE1Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lHSzkvWTJMZjhhM3dvTWJ1WjdUeHpsV2swUk45QmFBbzRiWFM3QUhTQ0VZQWlFQWc4Zm1nVHNUQ2VORWh0Mlk1OGhmeERRTlFuQTVQUW1UQ1paMlNtOFlMY009Il19","signature":"IRndhgZP6VLihiLiYP05CJyyq2gNaIOYEA92A6vcUQxkV08R9WNzcNqBstltBc-Wu3HRWmSU3wa6SllRUQUuUQ"}`)

	invalidSwEvidence = []byte(`{"payload":"dGhpcyBpcyBqdXN0IGFuIGludmFsaWQgcGF5bG9hZA==","protected":"eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDZ2pDQ0FpaWdBd0lCQWdJUkFMTlZBL2tka25RazVGZUxNdy9pZjdRd0NnWUlLb1pJemowRUF3SXdZVEVMTUFrR0ExVUVCaE1DUkVVeEVqQVFCZ05WQkFjVENWUmxjM1FnUTJsMGVURVZNQk1HQTFVRUNoTU1WR1Z6ZENCRGIyMXdZVzU1TVJBd0RnWURWUVFMRXdkU2IyOTBJRU5CTVJVd0V3WURWUVFERXd4VVpYTjBJRkp2YjNRZ1EwRXdJQmNOTWpVd056STBNRGMwTkRJNVdoZ1BNakV5TlRBM01ERXdOelEwTWpsYU1JR2dNUXN3Q1FZRFZRUUdFd0pFUlRFTE1Ba0dBMVVFQ0JNQ1Fsa3hEekFOQmdOVkJBY1RCazExYm1samFERVdNQlFHQTFVRUNSTU5kR1Z6ZEhOMGNtVmxkQ0F4TlRFT01Bd0dBMVVFRVJNRk9EVTNORGd4R2pBWUJnTlZCQW9URVZSbGMzUWdUM0puWVc1cGVtRjBhVzl1TVE4d0RRWURWUVFMRXdaa1pYWnBZMlV4SGpBY0JnTlZCQU1URldSbExuUmxjM1F1YzNjdVlXc3VaR1YyYVdObE1EQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJPSlFSZjVVY2JWMVhLR1ZSSVdNakFodVJONGJrVW9Od2NFMXg5VUgyYzkwQm5QUlIwcjB3TjhPWm8ycGorVmFJbXZwU2phZlZXc3hrbmprOCtnaE55dWpmekI5TUE0R0ExVWREd0VCL3dRRUF3SUZvREFkQmdOVkhTVUVGakFVQmdnckJnRUZCUWNEQVFZSUt3WUJCUVVIQXdJd0RBWURWUjBUQVFIL0JBSXdBREFkQmdOVkhRNEVGZ1FVdGNNM3NGRzI3c2VBWnZSbmFjMDY3NVlocWlrd0h3WURWUjBqQkJnd0ZvQVVDdnhGZ1pXOGFqWTNBWFF6dW1ZUkNzL0lsZGN3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUlnQWYvRnlzbDJXSWtYbmFLZVArZ0pIbjg0Nk1aOW5leHpiUlB5ZzZQU1JHNENJUUQzbm1WdWJjVWNISWJlOE00bVRBOG1NVHBlemloTm1XbEF6U1FPR2JqMEl3PT0iLCJNSUlDQ0RDQ0FhNmdBd0lCQWdJVVd0ODUvN1hKMHdVQnVFZ2VJRUEvUzlhVUE4VXdDZ1lJS29aSXpqMEVBd0l3WVRFTE1Ba0dBMVVFQmhNQ1JFVXhFakFRQmdOVkJBY1RDVlJsYzNRZ1EybDBlVEVWTUJNR0ExVUVDaE1NVkdWemRDQkRiMjF3WVc1NU1SQXdEZ1lEVlFRTEV3ZFNiMjkwSUVOQk1SVXdFd1lEVlFRREV3eFVaWE4wSUZKdmIzUWdRMEV3SUJjTk1qVXdOekkxTURjek1qQXdXaGdQTWpFeU5UQTNNREV3TnpNeU1EQmFNR0V4Q3pBSkJnTlZCQVlUQWtSRk1SSXdFQVlEVlFRSEV3bFVaWE4wSUVOcGRIa3hGVEFUQmdOVkJBb1RERlJsYzNRZ1EyOXRjR0Z1ZVRFUU1BNEdBMVVFQ3hNSFVtOXZkQ0JEUVRFVk1CTUdBMVVFQXhNTVZHVnpkQ0JTYjI5MElFTkJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVpRkVFUHV4M3pyVXQyU0R0K3dIblB2KzBrS0ViV1JBTGFiSGJHc1cvOHhqV3ltZ2RvRU84bVJQTVlTY0pHRDc3SThjdjdwMlBrT3pSNVJQQ0lULzQwYU5DTUVBd0RnWURWUjBQQVFIL0JBUURBZ0VHTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3SFFZRFZSME9CQllFRkFyOFJZR1Z2R28yTndGME03cG1FUXJQeUpYWE1Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lHSzkvWTJMZjhhM3dvTWJ1WjdUeHpsV2swUk45QmFBbzRiWFM3QUhTQ0VZQWlFQWc4Zm1nVHNUQ2VORWh0Mlk1OGhmeERRTlFuQTVQUW1UQ1paMlNtOFlMY009Il19","signature":"IRndhgZP6VLihiLiYP05CJyyq2gNaIOYEA92A6vcUQxkV08R9WNzcNqBstltBc-Wu3HRWmSU3wa6SllRUQUuUQ"}`)

	validUbuntuOciConfig = unmarshalSpec([]byte(`{"ociVersion":"1.2.0","process":{"user":{"uid":0,"gid":0,"additionalGids":[0]},"args":["/bin/bash"],"env":["HOSTNAME=\u003ccontainer-id\u003e","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"cwd":"/","capabilities":{"bounding":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"effective":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"permitted":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"]},"apparmorProfile":"docker-default","oomScoreAdj":0},"hostname":"\u003ccontainer-id\u003e","mounts":[{"destination":"/etc/hostname","type":"bind","source":"/var/lib/docker/containers/\u003ccontainer-id\u003e/hostname","options":["rbind","rprivate"]},{"destination":"/etc/hosts","type":"bind","source":"/var/lib/docker/containers/\u003ccontainer-id\u003e/hosts","options":["rbind","rprivate"]},{"destination":"/etc/resolv.conf","type":"bind","source":"/var/lib/docker/containers/\u003ccontainer-id\u003e/resolv.conf","options":["rbind","rprivate"]},{"destination":"/sys/fs/cgroup","type":"cgroup","source":"cgroup","options":["ro","nosuid","noexec","nodev"]},{"destination":"/dev/pts","type":"devpts","source":"devpts","options":["nosuid","noexec","newinstance","ptmxmode=0666","mode=0620","gid=5"]},{"destination":"/dev/mqueue","type":"mqueue","source":"mqueue","options":["nosuid","noexec","nodev"]},{"destination":"/proc","type":"proc","source":"proc","options":["nosuid","noexec","nodev"]},{"destination":"/dev/shm","type":"tmpfs","source":"shm","options":["nosuid","noexec","nodev","mode=1777","size=67108864"]},{"destination":"/sys","type":"sysfs","source":"sysfs","options":["nosuid","noexec","nodev","ro"]},{"destination":"/dev","type":"tmpfs","source":"tmpfs","options":["nosuid","strictatime","mode=755","size=65536k"]}],"linux":{"sysctl":{"net.ipv4.ip_unprivileged_port_start":"0","net.ipv4.ping_group_range":"0 2147483647"},"resources":{"devices":[{"allow":false,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":5,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":3,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":9,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":8,"access":"rwm"},{"allow":true,"type":"c","major":5,"minor":0,"access":"rwm"},{"allow":true,"type":"c","major":5,"minor":1,"access":"rwm"},{"allow":false,"type":"c","major":10,"minor":229,"access":"rwm"},{"allow":false,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":5,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":3,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":9,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":8,"access":"rwm"},{"allow":true,"type":"c","major":5,"minor":0,"access":"rwm"},{"allow":true,"type":"c","major":5,"minor":1,"access":"rwm"},{"allow":false,"type":"c","major":10,"minor":229,"access":"rwm"}],"blockIO":{}},"cgroupsPath":"system.slice:docker:\u003ccontainer-id\u003e","namespaces":[{"type":"mount"},{"type":"network"},{"type":"uts"},{"type":"pid"},{"type":"ipc"},{"type":"cgroup"}],"seccomp":{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_X32"],"syscalls":[{"names":["accept","accept4","access","adjtimex","alarm","bind","brk","cachestat","capget","capset","chdir","chmod","chown","chown32","clock_adjtime","clock_adjtime64","clock_getres","clock_getres_time64","clock_gettime","clock_gettime64","clock_nanosleep","clock_nanosleep_time64","close","close_range","connect","copy_file_range","creat","dup","dup2","dup3","epoll_create","epoll_create1","epoll_ctl","epoll_ctl_old","epoll_pwait","epoll_pwait2","epoll_wait","epoll_wait_old","eventfd","eventfd2","execve","execveat","exit","exit_group","faccessat","faccessat2","fadvise64","fadvise64_64","fallocate","fanotify_mark","fchdir","fchmod","fchmodat","fchmodat2","fchown","fchown32","fchownat","fcntl","fcntl64","fdatasync","fgetxattr","flistxattr","flock","fork","fremovexattr","fsetxattr","fstat","fstat64","fstatat64","fstatfs","fstatfs64","fsync","ftruncate","ftruncate64","futex","futex_requeue","futex_time64","futex_wait","futex_waitv","futex_wake","futimesat","getcpu","getcwd","getdents","getdents64","getegid","getegid32","geteuid","geteuid32","getgid","getgid32","getgroups","getgroups32","getitimer","getpeername","getpgid","getpgrp","getpid","getppid","getpriority","getrandom","getresgid","getresgid32","getresuid","getresuid32","getrlimit","get_robust_list","getrusage","getsid","getsockname","getsockopt","get_thread_area","gettid","gettimeofday","getuid","getuid32","getxattr","inotify_add_watch","inotify_init","inotify_init1","inotify_rm_watch","io_cancel","ioctl","io_destroy","io_getevents","io_pgetevents","io_pgetevents_time64","ioprio_get","ioprio_set","io_setup","io_submit","ipc","kill","landlock_add_rule","landlock_create_ruleset","landlock_restrict_self","lchown","lchown32","lgetxattr","link","linkat","listen","listxattr","llistxattr","_llseek","lremovexattr","lseek","lsetxattr","lstat","lstat64","madvise","map_shadow_stack","membarrier","memfd_create","memfd_secret","mincore","mkdir","mkdirat","mknod","mknodat","mlock","mlock2","mlockall","mmap","mmap2","mprotect","mq_getsetattr","mq_notify","mq_open","mq_timedreceive","mq_timedreceive_time64","mq_timedsend","mq_timedsend_time64","mq_unlink","mremap","msgctl","msgget","msgrcv","msgsnd","msync","munlock","munlockall","munmap","name_to_handle_at","nanosleep","newfstatat","_newselect","open","openat","openat2","pause","pidfd_open","pidfd_send_signal","pipe","pipe2","pkey_alloc","pkey_free","pkey_mprotect","poll","ppoll","ppoll_time64","prctl","pread64","preadv","preadv2","prlimit64","process_mrelease","pselect6","pselect6_time64","pwrite64","pwritev","pwritev2","read","readahead","readlink","readlinkat","readv","recv","recvfrom","recvmmsg","recvmmsg_time64","recvmsg","remap_file_pages","removexattr","rename","renameat","renameat2","restart_syscall","rmdir","rseq","rt_sigaction","rt_sigpending","rt_sigprocmask","rt_sigqueueinfo","rt_sigreturn","rt_sigsuspend","rt_sigtimedwait","rt_sigtimedwait_time64","rt_tgsigqueueinfo","sched_getaffinity","sched_getattr","sched_getparam","sched_get_priority_max","sched_get_priority_min","sched_getscheduler","sched_rr_get_interval","sched_rr_get_interval_time64","sched_setaffinity","sched_setattr","sched_setparam","sched_setscheduler","sched_yield","seccomp","select","semctl","semget","semop","semtimedop","semtimedop_time64","send","sendfile","sendfile64","sendmmsg","sendmsg","sendto","setfsgid","setfsgid32","setfsuid","setfsuid32","setgid","setgid32","setgroups","setgroups32","setitimer","setpgid","setpriority","setregid","setregid32","setresgid","setresgid32","setresuid","setresuid32","setreuid","setreuid32","setrlimit","set_robust_list","setsid","setsockopt","set_thread_area","set_tid_address","setuid","setuid32","setxattr","shmat","shmctl","shmdt","shmget","shutdown","sigaltstack","signalfd","signalfd4","sigprocmask","sigreturn","socketcall","socketpair","splice","stat","stat64","statfs","statfs64","statx","symlink","symlinkat","sync","sync_file_range","syncfs","sysinfo","tee","tgkill","time","timer_create","timer_delete","timer_getoverrun","timer_gettime","timer_gettime64","timer_settime","timer_settime64","timerfd_create","timerfd_gettime","timerfd_gettime64","timerfd_settime","timerfd_settime64","times","tkill","truncate","truncate64","ugetrlimit","umask","uname","unlink","unlinkat","utime","utimensat","utimensat_time64","utimes","vfork","vmsplice","wait4","waitid","waitpid","write","writev"],"action":"SCMP_ACT_ALLOW"},{"names":["process_vm_readv","process_vm_writev","ptrace"],"action":"SCMP_ACT_ALLOW"},{"names":["socket"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":40,"op":"SCMP_CMP_NE"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":0,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":8,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":131072,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":131080,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":4294967295,"op":"SCMP_CMP_EQ"}]},{"names":["arch_prctl"],"action":"SCMP_ACT_ALLOW"},{"names":["modify_ldt"],"action":"SCMP_ACT_ALLOW"},{"names":["clone"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":2114060288,"op":"SCMP_CMP_MASKED_EQ"}]},{"names":["clone3"],"action":"SCMP_ACT_ERRNO","errnoRet":38},{"names":["chroot"],"action":"SCMP_ACT_ALLOW"}]},"maskedPaths":["/proc/asound","/proc/acpi","/proc/interrupts","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/proc/scsi","/sys/firmware","/sys/devices/virtual/powercap","/sys/devices/system/cpu/cpu0/thermal_throttle","/sys/devices/system/cpu/cpu1/thermal_throttle","/sys/devices/system/cpu/cpu2/thermal_throttle","/sys/devices/system/cpu/cpu3/thermal_throttle","/sys/devices/system/cpu/cpu4/thermal_throttle","/sys/devices/system/cpu/cpu5/thermal_throttle","/sys/devices/system/cpu/cpu6/thermal_throttle","/sys/devices/system/cpu/cpu7/thermal_throttle"],"readonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"]}}`))

	invalidUbuntuOciConfig = unmarshalSpec([]byte(`{"ociVersion":"1.3.0","process":{"user":{"uid":0,"gid":0,"additionalGids":[0]},"args":["/bin/bash"],"env":["HOSTNAME=\u003ccontainer-id\u003e","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"cwd":"/","capabilities":{"bounding":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"effective":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"permitted":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"]},"apparmorProfile":"docker-default","oomScoreAdj":0},"hostname":"\u003ccontainer-id\u003e","mounts":[{"destination":"/etc/hostname","type":"bind","source":"/var/lib/docker/containers/\u003ccontainer-id\u003e/hostname","options":["rbind","rprivate"]},{"destination":"/etc/hosts","type":"bind","source":"/var/lib/docker/containers/\u003ccontainer-id\u003e/hosts","options":["rbind","rprivate"]},{"destination":"/etc/resolv.conf","type":"bind","source":"/var/lib/docker/containers/\u003ccontainer-id\u003e/resolv.conf","options":["rbind","rprivate"]},{"destination":"/sys/fs/cgroup","type":"cgroup","source":"cgroup","options":["ro","nosuid","noexec","nodev"]},{"destination":"/dev/pts","type":"devpts","source":"devpts","options":["nosuid","noexec","newinstance","ptmxmode=0666","mode=0620","gid=5"]},{"destination":"/dev/mqueue","type":"mqueue","source":"mqueue","options":["nosuid","noexec","nodev"]},{"destination":"/proc","type":"proc","source":"proc","options":["nosuid","noexec","nodev"]},{"destination":"/dev/shm","type":"tmpfs","source":"shm","options":["nosuid","noexec","nodev","mode=1777","size=67108864"]},{"destination":"/sys","type":"sysfs","source":"sysfs","options":["nosuid","noexec","nodev","ro"]},{"destination":"/dev","type":"tmpfs","source":"tmpfs","options":["nosuid","strictatime","mode=755","size=65536k"]}],"linux":{"sysctl":{"net.ipv4.ip_unprivileged_port_start":"0","net.ipv4.ping_group_range":"0 2147483647"},"resources":{"devices":[{"allow":false,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":5,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":3,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":9,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":8,"access":"rwm"},{"allow":true,"type":"c","major":5,"minor":0,"access":"rwm"},{"allow":true,"type":"c","major":5,"minor":1,"access":"rwm"},{"allow":false,"type":"c","major":10,"minor":229,"access":"rwm"},{"allow":false,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":5,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":3,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":9,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":8,"access":"rwm"},{"allow":true,"type":"c","major":5,"minor":0,"access":"rwm"},{"allow":true,"type":"c","major":5,"minor":1,"access":"rwm"},{"allow":false,"type":"c","major":10,"minor":229,"access":"rwm"}],"blockIO":{}},"cgroupsPath":"system.slice:docker:\u003ccontainer-id\u003e","namespaces":[{"type":"mount"},{"type":"network"},{"type":"uts"},{"type":"pid"},{"type":"ipc"},{"type":"cgroup"}],"seccomp":{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_X32"],"syscalls":[{"names":["accept","accept4","access","adjtimex","alarm","bind","brk","cachestat","capget","capset","chdir","chmod","chown","chown32","clock_adjtime","clock_adjtime64","clock_getres","clock_getres_time64","clock_gettime","clock_gettime64","clock_nanosleep","clock_nanosleep_time64","close","close_range","connect","copy_file_range","creat","dup","dup2","dup3","epoll_create","epoll_create1","epoll_ctl","epoll_ctl_old","epoll_pwait","epoll_pwait2","epoll_wait","epoll_wait_old","eventfd","eventfd2","execve","execveat","exit","exit_group","faccessat","faccessat2","fadvise64","fadvise64_64","fallocate","fanotify_mark","fchdir","fchmod","fchmodat","fchmodat2","fchown","fchown32","fchownat","fcntl","fcntl64","fdatasync","fgetxattr","flistxattr","flock","fork","fremovexattr","fsetxattr","fstat","fstat64","fstatat64","fstatfs","fstatfs64","fsync","ftruncate","ftruncate64","futex","futex_requeue","futex_time64","futex_wait","futex_waitv","futex_wake","futimesat","getcpu","getcwd","getdents","getdents64","getegid","getegid32","geteuid","geteuid32","getgid","getgid32","getgroups","getgroups32","getitimer","getpeername","getpgid","getpgrp","getpid","getppid","getpriority","getrandom","getresgid","getresgid32","getresuid","getresuid32","getrlimit","get_robust_list","getrusage","getsid","getsockname","getsockopt","get_thread_area","gettid","gettimeofday","getuid","getuid32","getxattr","inotify_add_watch","inotify_init","inotify_init1","inotify_rm_watch","io_cancel","ioctl","io_destroy","io_getevents","io_pgetevents","io_pgetevents_time64","ioprio_get","ioprio_set","io_setup","io_submit","ipc","kill","landlock_add_rule","landlock_create_ruleset","landlock_restrict_self","lchown","lchown32","lgetxattr","link","linkat","listen","listxattr","llistxattr","_llseek","lremovexattr","lseek","lsetxattr","lstat","lstat64","madvise","map_shadow_stack","membarrier","memfd_create","memfd_secret","mincore","mkdir","mkdirat","mknod","mknodat","mlock","mlock2","mlockall","mmap","mmap2","mprotect","mq_getsetattr","mq_notify","mq_open","mq_timedreceive","mq_timedreceive_time64","mq_timedsend","mq_timedsend_time64","mq_unlink","mremap","msgctl","msgget","msgrcv","msgsnd","msync","munlock","munlockall","munmap","name_to_handle_at","nanosleep","newfstatat","_newselect","open","openat","openat2","pause","pidfd_open","pidfd_send_signal","pipe","pipe2","pkey_alloc","pkey_free","pkey_mprotect","poll","ppoll","ppoll_time64","prctl","pread64","preadv","preadv2","prlimit64","process_mrelease","pselect6","pselect6_time64","pwrite64","pwritev","pwritev2","read","readahead","readlink","readlinkat","readv","recv","recvfrom","recvmmsg","recvmmsg_time64","recvmsg","remap_file_pages","removexattr","rename","renameat","renameat2","restart_syscall","rmdir","rseq","rt_sigaction","rt_sigpending","rt_sigprocmask","rt_sigqueueinfo","rt_sigreturn","rt_sigsuspend","rt_sigtimedwait","rt_sigtimedwait_time64","rt_tgsigqueueinfo","sched_getaffinity","sched_getattr","sched_getparam","sched_get_priority_max","sched_get_priority_min","sched_getscheduler","sched_rr_get_interval","sched_rr_get_interval_time64","sched_setaffinity","sched_setattr","sched_setparam","sched_setscheduler","sched_yield","seccomp","select","semctl","semget","semop","semtimedop","semtimedop_time64","send","sendfile","sendfile64","sendmmsg","sendmsg","sendto","setfsgid","setfsgid32","setfsuid","setfsuid32","setgid","setgid32","setgroups","setgroups32","setitimer","setpgid","setpriority","setregid","setregid32","setresgid","setresgid32","setresuid","setresuid32","setreuid","setreuid32","setrlimit","set_robust_list","setsid","setsockopt","set_thread_area","set_tid_address","setuid","setuid32","setxattr","shmat","shmctl","shmdt","shmget","shutdown","sigaltstack","signalfd","signalfd4","sigprocmask","sigreturn","socketcall","socketpair","splice","stat","stat64","statfs","statfs64","statx","symlink","symlinkat","sync","sync_file_range","syncfs","sysinfo","tee","tgkill","time","timer_create","timer_delete","timer_getoverrun","timer_gettime","timer_gettime64","timer_settime","timer_settime64","timerfd_create","timerfd_gettime","timerfd_gettime64","timerfd_settime","timerfd_settime64","times","tkill","truncate","truncate64","ugetrlimit","umask","uname","unlink","unlinkat","utime","utimensat","utimensat_time64","utimes","vfork","vmsplice","wait4","waitid","waitpid","write","writev"],"action":"SCMP_ACT_ALLOW"},{"names":["process_vm_readv","process_vm_writev","ptrace"],"action":"SCMP_ACT_ALLOW"},{"names":["socket"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":40,"op":"SCMP_CMP_NE"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":0,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":8,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":131072,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":131080,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":4294967295,"op":"SCMP_CMP_EQ"}]},{"names":["arch_prctl"],"action":"SCMP_ACT_ALLOW"},{"names":["modify_ldt"],"action":"SCMP_ACT_ALLOW"},{"names":["clone"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":2114060288,"op":"SCMP_CMP_MASKED_EQ"}]},{"names":["clone3"],"action":"SCMP_ACT_ERRNO","errnoRet":38},{"names":["chroot"],"action":"SCMP_ACT_ALLOW"}]},"maskedPaths":["/proc/asound","/proc/acpi","/proc/interrupts","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/proc/scsi","/sys/firmware","/sys/devices/virtual/powercap","/sys/devices/system/cpu/cpu0/thermal_throttle","/sys/devices/system/cpu/cpu1/thermal_throttle","/sys/devices/system/cpu/cpu2/thermal_throttle","/sys/devices/system/cpu/cpu3/thermal_throttle","/sys/devices/system/cpu/cpu4/thermal_throttle","/sys/devices/system/cpu/cpu5/thermal_throttle","/sys/devices/system/cpu/cpu6/thermal_throttle","/sys/devices/system/cpu/cpu7/thermal_throttle"],"readonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"]}}`))
)

func unmarshalSpec(raw []byte) *specs.Spec {
	spec := new(specs.Spec)
	err := json.Unmarshal(raw, spec)
	if err != nil {
		log.Errorf("generate test vectors: failed to unmarshal spec: %v", err)
	}
	return spec
}
