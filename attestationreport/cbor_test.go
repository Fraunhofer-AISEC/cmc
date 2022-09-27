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

package attestationreport

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestVerifyCbor(t *testing.T) {
	type args struct {
		ar ArPlain
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "SignSuccess",
			args: args{
				ar: ArPlain{
					Type: "Attestation Report",
				},
			},
			want: true,
		},
		// TODO add more unit tests
	}

	// Setup logger
	log.SetLevel(log.TraceLevel)

	// Setup certificate chain and keys
	certChain, privateKey := testCreatePki(leaf1Pem, leaf1KeyPem)
	signer := &SwSigner{
		certChain: certChain,
		priv:      privateKey,
	}
	block, _ := pem.Decode(certChain.Ca)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal("failed to decode PEM block containing certificate")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal("failed to parse certificate")
	}

	s := CborSerializer{}

	// Perform unit tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Sign attestation report
			report, err := s.Marshal(tt.args.ar)
			if err != nil {
				t.Errorf("Failed to setup test. Marshal failed")
			}

			ok, coseRaw := s.Sign(report, signer)
			if !ok {
				t.Errorf("Failed to setup test. Sign failed")
			}

			// Verify attestation report
			_, _, got := s.VerifyToken(coseRaw, []*x509.Certificate{ca})
			if got != tt.want {
				t.Errorf("Result.Success = %v, want %v", got, tt.want)
			}
		})
	}
}

func testCreatePki(certPem, keyPem []byte) (CertChain, *ecdsa.PrivateKey) {

	block, _ := pem.Decode(keyPem)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		log.Fatal("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	certChain := CertChain{
		Ca:            caPem,
		Intermediates: [][]byte{intermediatePem},
		Leaf:          certPem,
	}

	return certChain, privateKey
}

var (
	caPem = []byte("-----BEGIN CERTIFICATE-----\nMIICCjCCAbCgAwIBAgIUIW0hxqoduVcaOROA4X/yS59bFA0wCgYIKoZIzj0EAwIw\nYzELMAkGA1UEBhMCREUxETAPBgNVBAcTCEdhcmNoaW5nMRkwFwYDVQQKExBGcmF1\nbmhvZmVyIEFJU0VDMRAwDgYDVQQLEwdSb290IENBMRQwEgYDVQQDEwtJRFMgUm9v\ndCBDQTAeFw0yMjA5MjcxNTE3MDBaFw0yNzA5MjYxNTE3MDBaMGMxCzAJBgNVBAYT\nAkRFMREwDwYDVQQHEwhHYXJjaGluZzEZMBcGA1UEChMQRnJhdW5ob2ZlciBBSVNF\nQzEQMA4GA1UECxMHUm9vdCBDQTEUMBIGA1UEAxMLSURTIFJvb3QgQ0EwWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAARygh2I0eBKrUoRQ4CUnZfS+zZxTEv3JHbN4x7a\n0lAQefGF2mmAuzTtA4j1SsXQ7m8U/q89IQIP6rYNLHwE8bl0o0IwQDAOBgNVHQ8B\nAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUSYRVbRBpCAAiYn12\nvPtNRmpZoMswCgYIKoZIzj0EAwIDSAAwRQIhANDt7shE2JChebypW+lfPJjMWA6i\nVZ7DRGNzNKeZ1lfCAiBIFChtcmYUDjp7wD+5rlz0hsxJWcuwabx8qR+f6RTsiA==\n-----END CERTIFICATE-----")

	intermediatePem = []byte("-----BEGIN CERTIFICATE-----\nMIICijCCAjGgAwIBAgIUKQEsaISr4yBVKyNHlZQG5zmYL10wCgYIKoZIzj0EAwIw\nYzELMAkGA1UEBhMCREUxETAPBgNVBAcTCEdhcmNoaW5nMRkwFwYDVQQKExBGcmF1\nbmhvZmVyIEFJU0VDMRAwDgYDVQQLEwdSb290IENBMRQwEgYDVQQDEwtJRFMgUm9v\ndCBDQTAeFw0yMjA5MjcxNTE3MDBaFw0yNzA5MjcyMTE3MDBaMGkxCzAJBgNVBAYT\nAkRFMREwDwYDVQQHEwhHYXJjaGluZzEZMBcGA1UEChMQRnJhdW5ob2ZlciBBSVNF\nQzETMBEGA1UECxMKVXNlciBTdWJDQTEXMBUGA1UEAxMOSURTIFVzZXIgU3ViQ0Ew\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS3JvwJRT1JvRLfvouZuYEoZiweXQ/H\nssAKvfCocG2lDyeuifCAu/fFrYRrXlSBu1qtn/sUdFN2WaoW/Qc8d9weo4G8MIG5\nMA4GA1UdDwEB/wQEAwIBhjAnBgNVHSUEIDAeBggrBgEFBQcDCQYIKwYBBQUHAwIG\nCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFE66UnTZGC+R\nNYJU8JNdlcDX8IFPMB8GA1UdIwQYMBaAFEmEVW0QaQgAImJ9drz7TUZqWaDLMCoG\nCCsGAQUFBwEBBB4wHDAaBggrBgEFBQcwAYYOMTI3LjAuMC4xOjg4ODcwCgYIKoZI\nzj0EAwIDRwAwRAIgBc2+0V4f6pP0NuzfKQAZVuSE3V1+qgXlQA/+pOCTLDkCIBtC\ninqbAb8VWe6G+hSx9sh8Ulz6cXqO0nTybWMV/Y2J\n-----END CERTIFICATE-----")

	leaf1Pem = []byte("-----BEGIN CERTIFICATE-----\nMIICUDCCAfWgAwIBAgIUHALDKvb31vuALeLmgN9gEGJA6T0wCgYIKoZIzj0EAwIw\naTELMAkGA1UEBhMCREUxETAPBgNVBAcTCEdhcmNoaW5nMRkwFwYDVQQKExBGcmF1\nbmhvZmVyIEFJU0VDMRMwEQYDVQQLEwpVc2VyIFN1YkNBMRcwFQYDVQQDEw5JRFMg\nVXNlciBTdWJDQTAeFw0yMjA5MjcxNTE3MDBaFw0yMzA5MjcxNTE3MDBaMGUxCzAJ\nBgNVBAYTAkRFMREwDwYDVQQHEwhHYXJjaGluZzEZMBcGA1UEChMQRnJhdW5ob2Zl\nciBBSVNFQzESMBAGA1UECxMJZGV2ZWxvcGVyMRQwEgYDVQQDDAtkZXZlbG9wZXJf\nQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBf/hjieTwkQ8LJS+QbcfZp5DlFT\nXn9xbD/QMGqg84ALPoG4cC1I/aDHz6vv5PMZD+OoF4m7JRn0YgpUG8alEvKjfzB9\nMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw\nDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUIIDZ4k769wMU267+KFmZzykKgzEwHwYD\nVR0jBBgwFoAUTrpSdNkYL5E1glTwk12VwNfwgU8wCgYIKoZIzj0EAwIDSQAwRgIh\nAKUzuLJ0O9L0GppwdrWRf6XSjgDcS030AwosEnIrN7LFAiEA41V3Q/qWSmAhg8ve\ngPzN9prUDZfrQHknIGrQGTwe3Kg=\n-----END CERTIFICATE-----")

	leaf2Pem = []byte("-----BEGIN CERTIFICATE-----\nMIICTzCCAfWgAwIBAgIUXpOuEH9UPoi/3xQFzWkzsc5e54MwCgYIKoZIzj0EAwIw\naTELMAkGA1UEBhMCREUxETAPBgNVBAcTCEdhcmNoaW5nMRkwFwYDVQQKExBGcmF1\nbmhvZmVyIEFJU0VDMRMwEQYDVQQLEwpVc2VyIFN1YkNBMRcwFQYDVQQDEw5JRFMg\nVXNlciBTdWJDQTAeFw0yMjA5MjcxNTE3MDBaFw0yMzA5MjcxNTE3MDBaMGUxCzAJ\nBgNVBAYTAkRFMREwDwYDVQQHEwhHYXJjaGluZzEZMBcGA1UEChMQRnJhdW5ob2Zl\nciBBSVNFQzESMBAGA1UECxMJZGV2ZWxvcGVyMRQwEgYDVQQDDAtkZXZlbG9wZXJf\nQjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAcM/6YYCfVcd1+JZdi+vvtpptUJ\nObfzCpN3N7soDuCzFfab99ZZxeI5LDuvWQsK4XwSKeTnT8sokap9s3rfPaGjfzB9\nMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw\nDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUoF0drq348bToMbsX9yXnl17MJlUwHwYD\nVR0jBBgwFoAUTrpSdNkYL5E1glTwk12VwNfwgU8wCgYIKoZIzj0EAwIDSAAwRQIh\nAKHVVnnSlMLxVWY7hD7PG3OSgGkzh/0Nj520ilBV2uYnAiBkyQGgkHwlbxTus1H4\nEvKdWMAH7ewxygqbNMzScc9kVg==\n-----END CERTIFICATE-----")

	leaf1KeyPem = []byte("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIABFPs5yF6+m7kXQ60tPdzP3ef0BxQPLLhWOkfUSOunxoAoGCCqGSM49\nAwEHoUQDQgAEF/+GOJ5PCRDwslL5Btx9mnkOUVNef3FsP9AwaqDzgAs+gbhwLUj9\noMfPq+/k8xkP46gXibslGfRiClQbxqUS8g==\n-----END EC PRIVATE KEY-----\n")

	leaf2KeyPem = []byte("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIFRHQIbxht652eteXrCxmsOEApQS1zfDfhLKZLsfucQWoAoGCCqGSM49\nAwEHoUQDQgAEBwz/phgJ9Vx3X4ll2L6++2mm1Qk5t/MKk3c3uygO4LMV9pv31lnF\n4jksO69ZCwrhfBIp5OdPyyiRqn2zet89oQ==\n-----END EC PRIVATE KEY-----")
)