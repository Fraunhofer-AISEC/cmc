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

package internal

import (
	"testing"
)

func TestParseCert(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "Valid PEM Certificate",
			args:    args{leaf1},
			wantErr: false,
		},
		{
			name:    "Valid DER Certificate",
			args:    args{leaf1Der},
			wantErr: false,
		},
		{
			name:    "Invalid Certificate",
			args:    args{[]byte("-----BEGIN PRIVATE KEY-----")},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCert(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestParseCertsPem(t *testing.T) {
	type args struct {
		data any
	}
	tests := []struct {
		name    string
		args    args
		wantLen int
		wantErr bool
	}{
		{
			name:    "Parse Single Certificate",
			args:    args{leaf1},
			wantLen: 1,
			wantErr: false,
		},
		{
			name:    "Parse Single Array",
			args:    args{append(leaf1, inter1...)},
			wantLen: 2,
			wantErr: false,
		},
		{
			name:    "Parse Multiple",
			args:    args{[][]byte{leaf1, inter1, ca1}},
			wantLen: 3,
			wantErr: false,
		},
		{
			name:    "Parse Invalid",
			args:    args{[][]byte{leaf1, inter1, []byte("abc")}},
			wantLen: 0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCertsPem(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCerts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.wantLen {
				t.Errorf("ParseCerts() len = %v, want %v", got, tt.wantLen)
			}
		})
	}
}

func TestParseCertsDer(t *testing.T) {
	type args struct {
		data any
	}
	tests := []struct {
		name    string
		args    args
		wantLen int
		wantErr bool
	}{
		{
			name:    "Valid certificate",
			args:    args{leaf1Der},
			wantLen: 1,
			wantErr: false,
		},
		{
			name:    "Valid certificates (single array)",
			args:    args{append(leaf1Der, leaf1Der...)},
			wantLen: 2,
			wantErr: false,
		},
		{
			name:    "Valid certificates (list of arrays)",
			args:    args{[][]byte{leaf1Der, leaf1Der}},
			wantLen: 2,
			wantErr: false,
		},
		{
			name:    "Invalid certificates",
			args:    args{leaf1},
			wantLen: 0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCertsDer(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCertsDer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.wantLen {
				t.Errorf("ParseCerts() len = %v, want %v", got, tt.wantLen)
			}
		})
	}
}

func TestVerifyCertChain(t *testing.T) {
	type args struct {
		certs [][]byte
		cas   [][]byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Valid chain (2) including CA",
			args: args{
				certs: [][]byte{leaf1, inter1},
				cas:   [][]byte{inter1},
			},
			wantErr: false,
		},
		{
			name: "Valid chain (2) without CA",
			args: args{
				certs: [][]byte{leaf1},
				cas:   [][]byte{inter1},
			},
			wantErr: false,
		},
		{
			name: "Valid chain (3) including CA",
			args: args{
				certs: [][]byte{leaf1, inter1, ca1},
				cas:   [][]byte{ca1},
			},
			wantErr: false,
		},
		{
			name: "Valid chain (3) without CA",
			args: args{
				certs: [][]byte{leaf1, inter1},
				cas:   [][]byte{ca1},
			},
			wantErr: false,
		},
		{
			name: "Incomplete chain",
			args: args{
				certs: [][]byte{leaf1},
				cas:   [][]byte{ca1},
			},
			wantErr: true,
		},
		{
			name: "Invalid chain",
			args: args{
				certs: [][]byte{leaf1, inter1, ca1},
				cas:   [][]byte{ca2},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Preparation
			certs, err := ParseCertsPem(tt.args.certs)
			if err != nil {
				t.Errorf("Preparation: %v", err)
			}
			cas, err := ParseCertsPem(tt.args.cas)
			if err != nil {
				t.Errorf("Preparation: %v", err)
			}

			// Test
			if _, err := VerifyCertChain(certs, cas); (err != nil) != tt.wantErr {
				t.Errorf("VerifyCertChain() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

var (
	leaf1 = []byte("-----BEGIN CERTIFICATE-----\nMIIFTDCCAvugAwIBAgIBADBGBgkqhkiG9w0BAQowOaAPMA0GCWCGSAFlAwQCAgUA\noRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATCjAwIBATB7MRQwEgYD\nVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDASBgNVBAcMC1NhbnRhIENs\nYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5jZWQgTWljcm8gRGV2aWNl\nczESMBAGA1UEAwwJU0VWLU1pbGFuMB4XDTIyMDQyNjE2Mzc0OVoXDTI5MDQyNjE2\nMzc0OVowejEUMBIGA1UECwwLRW5naW5lZXJpbmcxCzAJBgNVBAYTAlVTMRQwEgYD\nVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExHzAdBgNVBAoMFkFkdmFuY2Vk\nIE1pY3JvIERldmljZXMxETAPBgNVBAMMCFNFVi1WQ0VLMHYwEAYHKoZIzj0CAQYF\nK4EEACIDYgAE+F8EKAE/+McOP30pLAnr+nnKtuzmuOrDzXJkYjn5QD4OX96yQ5T4\nc49aqUt/+bMBJiqEjIRkpRxZBI+E3Kh8E/Gj8lOCAgInc9vSbp7Gwh9zMMD1b6Bx\nIQlw3RqnnPVDo4IBFjCCARIwEAYJKwYBBAGceAEBBAMCAQAwFwYJKwYBBAGceAEC\nBAoWCE1pbGFuLUIwMBEGCisGAQQBnHgBAwEEAwIBAjARBgorBgEEAZx4AQMCBAMC\nAQAwEQYKKwYBBAGceAEDBAQDAgEAMBEGCisGAQQBnHgBAwUEAwIBADARBgorBgEE\nAZx4AQMGBAMCAQAwEQYKKwYBBAGceAEDBwQDAgEAMBEGCisGAQQBnHgBAwMEAwIB\nBjARBgorBgEEAZx4AQMIBAMCAUMwTQYJKwYBBAGceAEEBEDVWeqhxj6gSy9LvZfD\nwdI5jBonNXds2A4Fcdw6OQcPtWT5DbJjXFE/78ckjs/zVC4ehW3cPRuEm9/gH5mv\nuNC2MEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0B\nAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBA4ICAQACKL4ErvzaV0gFYd6ZdY/e\nkM9+pTDqyuOs6xE08aBdgDcfuP0dQPiVZB9cR/xu7pcsVS7GqibjLu9Ffbadyjho\nIbMK4noqgjSXoET+AwsTolFAcuZEoCFcg0s581WDaDf+efMP2yBKvaQy4Aw8PXMs\nd/AUyT59UmOHb+f6i3n6mBMM/FpOvEKQYzfeEHp5dQEhBz1h0Lmvo/TPwPCk1iB4\nG8DTdeLQh7Al2Kb9Sko/kenOXuO/b4av6Vs6t8JcLyJrepXWotf+W0UB5OAe4Ajd\n+RQ6ECYvEJQGsV9453NSCF2nUtllJ8DzPhd9iHFXXzELXNSC8YHW8Lj7/L1aGTlZ\nMjmhUuL3OE0Mw+KJHP0qCY20jCOcBawY3rc/bOXo+adpL+ggJHWBmY8qpWQsZlOi\nhM3CP3eOvI4HZt5fKX4SJumT8R43TqIEnqxgf5ordLdmG8CP/hJqnFGiZnbzAZ6O\nYTTtyb8wmQgLjmIaErToqUZTxwlkpgLScZZS5m8j9zAjWDJe1ncmbn5ivAE0/CmG\nL/s4xcZ+3pXQWkBqpCJuP5QIQ0lMPkk4aJdWHZ3rVtIZriHTDA8iXBfaIX2J5NMp\n7e0QZMhqkOG+jgIWLUok8OU/x466vA4g6o3G+39gZhqPTu9SktbLnqghdeqfF7a6\nBG6E20ctrvs7l8fXs5k1eA==\n-----END CERTIFICATE-----\n")

	inter1 = []byte("-----BEGIN CERTIFICATE-----\n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\n-----END CERTIFICATE-----\n")

	ca1 = []byte("-----BEGIN CERTIFICATE-----\nMIIGYzCCBBKgAwIBAgIDAQAAMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAIC\nBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDAS\nBgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEg\nQ2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZp\nY2VzMRIwEAYDVQQDDAlBUkstTWlsYW4wHhcNMjAxMDIyMTcyMzA1WhcNNDUxMDIy\nMTcyMzA1WjB7MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDAS\nBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5j\nZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJQVJLLU1pbGFuMIICIjANBgkqhkiG\n9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsVmD7FktuotWwX1fNg\nW41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU0V5tkKiU1EesNFta\n1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S1ju8X93+6dxDUrG2\nSzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI52Naz5m2B+O+vjsC0\n60d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3KFYXP59XmJgtcog05\ngmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd/y8KxX7jksTEzAOg\nbKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBkgnlENEWx1UcbQQrs\n+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V9TJQqnN3Q53kt5vi\nQi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnqz55I0u33wh4r0ZNQ\neTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+OgpCCoMNit2uLo9M18\nfHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXoQPHfbkH0CyPfhl1j\nWhJFZasCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSFrBrRQ/fI\nrFXUxR1BSKvVeErUUzAPBgNVHRMBAf8EBTADAQH/MDoGA1UdHwQzMDEwL6AtoCuG\nKWh0dHBzOi8va2RzaW50Zi5hbWQuY29tL3ZjZWsvdjEvTWlsYW4vY3JsMEYGCSqG\nSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZI\nAWUDBAICBQCiAwIBMKMDAgEBA4ICAQC6m0kDp6zv4Ojfgy+zleehsx6ol0ocgVel\nETobpx+EuCsqVFRPK1jZ1sp/lyd9+0fQ0r66n7kagRk4Ca39g66WGTJMeJdqYriw\nSTjjDCKVPSesWXYPVAyDhmP5n2v+BYipZWhpvqpaiO+EGK5IBP+578QeW/sSokrK\ndHaLAxG2LhZxj9aF73fqC7OAJZ5aPonw4RE299FVarh1Tx2eT3wSgkDgutCTB1Yq\nzT5DuwvAe+co2CIVIzMDamYuSFjPN0BCgojl7V+bTou7dMsqIu/TW/rPCX9/EUcp\nKGKqPQ3P+N9r1hjEFY1plBg93t53OOo49GNI+V1zvXPLI6xIFVsh+mto2RtgEX/e\npmMKTNN6psW88qg7c1hTWtN6MbRuQ0vm+O+/2tKBF2h8THb94OvvHHoFDpbCELlq\nHnIYhxy0YKXGyaW1NjfULxrrmxVW4wcn5E8GddmvNa6yYm8scJagEi13mhGu4Jqh\n3QU3sf8iUSUr09xQDwHtOQUVIqx4maBZPBtSMf+qUDtjXSSq8lfWcd8bLr9mdsUn\nJZJ0+tuPMKmBnSH860llKk+VpVQsgqbzDIvOLvD6W1Umq25boxCYJ+TuBoa4s+HH\nCViAvgT9kf/rBq1d+ivj6skkHxuzcxbk1xv6ZGxrteJxVH7KlX7YRdZ6eARKwLe4\nAFZEAwoKCQ==\n-----END CERTIFICATE-----\n")

	ca2 = []byte("-----BEGIN CERTIFICATE-----\nMIICBjCCAaygAwIBAgIUGN9vDjSdwSe2f3xTHu9faZJYRPowCgYIKoZIzj0EAwIw\nYTELMAkGA1UEBhMCREUxEjAQBgNVBAcTCVRlc3QgQ2l0eTEVMBMGA1UEChMMVGVz\ndCBDb21wYW55MRAwDgYDVQQLEwdSb290IENBMRUwEwYDVQQDEwxUZXN0IFJvb3Qg\nQ0EwHhcNMjIxMTEwMTM0MDAwWhcNMjcxMTA5MTM0MDAwWjBhMQswCQYDVQQGEwJE\nRTESMBAGA1UEBxMJVGVzdCBDaXR5MRUwEwYDVQQKEwxUZXN0IENvbXBhbnkxEDAO\nBgNVBAsTB1Jvb3QgQ0ExFTATBgNVBAMTDFRlc3QgUm9vdCBDQTBZMBMGByqGSM49\nAgEGCCqGSM49AwEHA0IABCnjYKXqaoBbMClkPntA9VJcdh7n89bSakJhtXFDSzLU\nrIwLZOny+w2VkBVMESIrpnhchP3BrJIqa2Dnc1zDkiGjQjBAMA4GA1UdDwEB/wQE\nAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRJXUyS6qIPGmMDC1Yujub+\nfLEY6TAKBggqhkjOPQQDAgNIADBFAiEAidPzJuJBCsIwPEjaDFdwZzE8bpUrcICe\nf/pMr5C56EYCIGfjHPqdq1RNYGjAIcxMPikc78266NhSwG267K0v5RvC\n-----END CERTIFICATE-----\n")

	leaf1Der = []byte{
		0x30, 0x82, 0x02, 0x6e, 0x30, 0x82, 0x01, 0xf5, 0xa0, 0x03, 0x02, 0x01,
		0x02, 0x02, 0x14, 0x15, 0x96, 0xa3, 0xba, 0x45, 0xcd, 0xbf, 0x2d, 0xf5,
		0xd6, 0x96, 0x88, 0x8e, 0xdd, 0x39, 0x3e, 0xc3, 0x8a, 0x64, 0x47, 0x30,
		0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30,
		0x69, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
		0x44, 0x45, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13,
		0x08, 0x47, 0x61, 0x72, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x31, 0x19, 0x30,
		0x17, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x10, 0x46, 0x72, 0x61, 0x75,
		0x6e, 0x68, 0x6f, 0x66, 0x65, 0x72, 0x20, 0x41, 0x49, 0x53, 0x45, 0x43,
		0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x0a, 0x55,
		0x73, 0x65, 0x72, 0x20, 0x53, 0x75, 0x62, 0x43, 0x41, 0x31, 0x17, 0x30,
		0x15, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0e, 0x49, 0x44, 0x53, 0x20,
		0x55, 0x73, 0x65, 0x72, 0x20, 0x53, 0x75, 0x62, 0x43, 0x41, 0x30, 0x1e,
		0x17, 0x0d, 0x32, 0x33, 0x30, 0x32, 0x31, 0x32, 0x32, 0x31, 0x33, 0x35,
		0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x34, 0x30, 0x32, 0x31, 0x32, 0x32,
		0x31, 0x33, 0x35, 0x30, 0x30, 0x5a, 0x30, 0x65, 0x31, 0x0b, 0x30, 0x09,
		0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x44, 0x45, 0x31, 0x11, 0x30,
		0x0f, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x08, 0x47, 0x61, 0x72, 0x63,
		0x68, 0x69, 0x6e, 0x67, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04,
		0x0a, 0x13, 0x10, 0x46, 0x72, 0x61, 0x75, 0x6e, 0x68, 0x6f, 0x66, 0x65,
		0x72, 0x20, 0x41, 0x49, 0x53, 0x45, 0x43, 0x31, 0x12, 0x30, 0x10, 0x06,
		0x03, 0x55, 0x04, 0x0b, 0x13, 0x09, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66,
		0x69, 0x65, 0x72, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03,
		0x0c, 0x0b, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x5f,
		0x41, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
		0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
		0x03, 0x42, 0x00, 0x04, 0x3b, 0x23, 0xbc, 0x37, 0x8c, 0xb5, 0x05, 0x5e,
		0xc8, 0xfb, 0x69, 0x0f, 0x3d, 0x35, 0x9a, 0x0e, 0xc1, 0x32, 0xa0, 0x76,
		0x31, 0x42, 0x69, 0x82, 0xdb, 0xbb, 0xe9, 0x23, 0x39, 0xe2, 0xef, 0x51,
		0x1f, 0x7e, 0x76, 0x5c, 0x9d, 0x94, 0xe4, 0xee, 0x24, 0x35, 0x80, 0xe3,
		0x17, 0x63, 0xb2, 0x92, 0x53, 0x82, 0x26, 0x42, 0x4d, 0x2e, 0x57, 0x75,
		0x77, 0x1d, 0xe8, 0xaa, 0x75, 0xb0, 0xd5, 0x9a, 0xa3, 0x7f, 0x30, 0x7d,
		0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04,
		0x03, 0x02, 0x05, 0xa0, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04,
		0x16, 0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03,
		0x01, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x30,
		0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30,
		0x00, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14,
		0x46, 0x8c, 0x0d, 0x74, 0x37, 0x75, 0xe9, 0xb4, 0xb4, 0x98, 0xbe, 0xf1,
		0x34, 0x5d, 0x55, 0x3a, 0xb7, 0x65, 0x96, 0x2e, 0x30, 0x1f, 0x06, 0x03,
		0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xb1, 0xa9, 0xcd,
		0x20, 0xa0, 0xa1, 0x79, 0x4a, 0xbd, 0x78, 0xef, 0xed, 0xc6, 0x18, 0xaa,
		0x35, 0x10, 0x16, 0x08, 0x2d, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
		0xce, 0x3d, 0x04, 0x03, 0x03, 0x03, 0x67, 0x00, 0x30, 0x64, 0x02, 0x30,
		0x1f, 0xc4, 0x7c, 0x55, 0x61, 0xfe, 0x36, 0xc5, 0x7d, 0xdb, 0x6e, 0x90,
		0x6b, 0x90, 0x28, 0xfb, 0x9d, 0xec, 0x82, 0x4b, 0x8c, 0x70, 0x52, 0x6b,
		0xc1, 0xac, 0xe7, 0x10, 0x73, 0xb7, 0x15, 0x73, 0x3d, 0x97, 0xa7, 0xf5,
		0x92, 0xa2, 0xc8, 0x02, 0xb1, 0x71, 0x76, 0xbb, 0x67, 0xd0, 0x57, 0x99,
		0x02, 0x30, 0x45, 0xf2, 0xdd, 0xaa, 0x15, 0xb7, 0x28, 0x3a, 0x1e, 0x95,
		0xfd, 0xc9, 0x38, 0xff, 0xfa, 0x96, 0x55, 0x2f, 0xf4, 0x96, 0xd7, 0xa2,
		0x85, 0xe8, 0xa8, 0x85, 0x2a, 0xe4, 0xe5, 0xf2, 0xe5, 0xb2, 0x44, 0x9c,
		0xec, 0xd7, 0xaa, 0x75, 0x2f, 0x8e, 0x87, 0x85, 0x60, 0x8d, 0x4e, 0xf1,
		0x97, 0x6a,
	}
)
