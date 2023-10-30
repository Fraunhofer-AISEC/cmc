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
	leaf1 = []byte("-----BEGIN CERTIFICATE-----\nMIICbjCCAfWgAwIBAgIUFZajukXNvy311paIjt05PsOKZEcwCgYIKoZIzj0EAwMw\naTELMAkGA1UEBhMCREUxETAPBgNVBAcTCEdhcmNoaW5nMRkwFwYDVQQKExBGcmF1\nbmhvZmVyIEFJU0VDMRMwEQYDVQQLEwpVc2VyIFN1YkNBMRcwFQYDVQQDEw5JRFMg\nVXNlciBTdWJDQTAeFw0yMzAyMTIyMTM1MDBaFw0yNDAyMTIyMTM1MDBaMGUxCzAJ\nBgNVBAYTAkRFMREwDwYDVQQHEwhHYXJjaGluZzEZMBcGA1UEChMQRnJhdW5ob2Zl\nciBBSVNFQzESMBAGA1UECxMJY2VydGlmaWVyMRQwEgYDVQQDDAtjZXJ0aWZpZXJf\nQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDsjvDeMtQVeyPtpDz01mg7BMqB2\nMUJpgtu76SM54u9RH352XJ2U5O4kNYDjF2OyklOCJkJNLld1dx3oqnWw1ZqjfzB9\nMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw\nDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQURowNdDd16bS0mL7xNF1VOrdlli4wHwYD\nVR0jBBgwFoAUsanNIKCheUq9eO/txhiqNRAWCC0wCgYIKoZIzj0EAwMDZwAwZAIw\nH8R8VWH+NsV9226Qa5Ao+53sgkuMcFJrwaznEHO3FXM9l6f1kqLIArFxdrtn0FeZ\nAjBF8t2qFbcoOh6V/ck4//qWVS/0lteiheiohSrk5fLlskSc7NeqdS+Oh4VgjU7x\nl2o=\n-----END CERTIFICATE-----\n")

	inter1 = []byte("-----BEGIN CERTIFICATE-----\nMIIC7DCCAk6gAwIBAgIUe8P38UUdS0Dtc/cp6KwhvRM17bIwCgYIKoZIzj0EAwQw\nYzELMAkGA1UEBhMCREUxETAPBgNVBAcTCEdhcmNoaW5nMRkwFwYDVQQKExBGcmF1\nbmhvZmVyIEFJU0VDMRAwDgYDVQQLEwdSb290IENBMRQwEgYDVQQDEwtJRFMgUm9v\ndCBDQTAeFw0yMzAyMTIyMTM1MDBaFw0yODAyMTMwMzM1MDBaMGkxCzAJBgNVBAYT\nAkRFMREwDwYDVQQHEwhHYXJjaGluZzEZMBcGA1UEChMQRnJhdW5ob2ZlciBBSVNF\nQzETMBEGA1UECxMKVXNlciBTdWJDQTEXMBUGA1UEAxMOSURTIFVzZXIgU3ViQ0Ew\ndjAQBgcqhkjOPQIBBgUrgQQAIgNiAAS1Y6wYGkjfoB5jh6JofPKuNEf2eyMPThFx\nTLcXZNTSpXcDGEjHNMyOEQmiPSWi0/bOcHIWikcnyoh33andzAUVlUsOflYzK20a\nCKXI5dQZY8hThtVVeQeK2K7AjoepDLejgbwwgbkwDgYDVR0PAQH/BAQDAgGGMCcG\nA1UdJQQgMB4GCCsGAQUFBwMJBggrBgEFBQcDAgYIKwYBBQUHAwEwEgYDVR0TAQH/\nBAgwBgEB/wIBADAdBgNVHQ4EFgQUsanNIKCheUq9eO/txhiqNRAWCC0wHwYDVR0j\nBBgwFoAUepdZmupqGVLZUzy740jBYVmzdGIwKgYIKwYBBQUHAQEEHjAcMBoGCCsG\nAQUFBzABhg4xMjcuMC4wLjE6ODg4NzAKBggqhkjOPQQDBAOBiwAwgYcCQV1rtlF5\n23DQXL6qmraA65H4bbzIFvj97nbyJpyj+3WUtFJxtnNSskrgYEzYwwqLck+FGGHV\nQDMG/dpvo9w5NBfhAkIAvnPJA42+y5Ksi0kFg20K7Y5QU8IaSCDyyLRGr0y+td9q\nBAZaPbj4FPtXhgzWmHu7qXceNVWf8EeypcaGJgb45PM=\n-----END CERTIFICATE-----\n")

	ca1 = []byte("-----BEGIN CERTIFICATE-----\nMIICkTCCAfOgAwIBAgIUWT/JwRD1sV6I+E4mIdGc/OGWA58wCgYIKoZIzj0EAwQw\nYzELMAkGA1UEBhMCREUxETAPBgNVBAcTCEdhcmNoaW5nMRkwFwYDVQQKExBGcmF1\nbmhvZmVyIEFJU0VDMRAwDgYDVQQLEwdSb290IENBMRQwEgYDVQQDEwtJRFMgUm9v\ndCBDQTAeFw0yMzAyMTIyMTM1MDBaFw0yODAyMTEyMTM1MDBaMGMxCzAJBgNVBAYT\nAkRFMREwDwYDVQQHEwhHYXJjaGluZzEZMBcGA1UEChMQRnJhdW5ob2ZlciBBSVNF\nQzEQMA4GA1UECxMHUm9vdCBDQTEUMBIGA1UEAxMLSURTIFJvb3QgQ0EwgZswEAYH\nKoZIzj0CAQYFK4EEACMDgYYABACGiusr4j6YFHLGG8T4jAR+i66Zb4K2w9BiOkle\ne8w3A6hYDiIGk1lWsdJW6Ind/kmLAtmEPr3D/bKMVYO0a/3+EwBsv17Ieg4wtblr\n2SwDnHzEes8rr2eVgZT1pwFCfI7erIqdN1ZMuGWrSfISDgoOGZNdD+3y3RaB9AAx\nP9Wxw/t8BqNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYD\nVR0OBBYEFHqXWZrqahlS2VM8u+NIwWFZs3RiMAoGCCqGSM49BAMEA4GLADCBhwJB\nMZJ8nxQIecb7wpTL/xf0TKB9/hy0RnER+0cwpzpqMRYJuiBALmV4RkfCkqzLUriU\nD7FE8BKxABDemUawTq4lbtQCQgG0bYlvdm4BKIdinOlnojj82ER1gH/LqdgHkVHa\n5wcLZbZIh/xOxLdhOpzEWXlm/7IK3GKEsdigqqZnzGB71pqalw==\n-----END CERTIFICATE-----\n")

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
