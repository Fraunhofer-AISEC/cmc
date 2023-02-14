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

func TestParseCerts(t *testing.T) {
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
			name:    "Parse Single",
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
			got, err := ParseCerts(tt.args.data)
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
			certs, err := ParseCerts(tt.args.certs)
			if err != nil {
				t.Errorf("Preparation: %v", err)
			}
			cas, err := ParseCerts(tt.args.cas)
			if err != nil {
				t.Errorf("Preparation: %v", err)
			}

			// Test
			if err := VerifyCertChain(certs, cas); (err != nil) != tt.wantErr {
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
)
