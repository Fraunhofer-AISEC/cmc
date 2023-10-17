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

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
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
	logrus.SetLevel(logrus.TraceLevel)

	// Setup certificate chain and keys
	certChain, privateKey := testCreatePki(leafPem, leafKeyPem)
	signer := &SwSigner{
		certChain: certChain,
		priv:      privateKey,
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

			coseRaw, err := s.Sign(report, signer)
			if err != nil {
				t.Errorf("Failed to setup test. Sign failed: %v", err)
			}

			// Verify attestation report
			_, _, got := s.VerifyToken(coseRaw, []*x509.Certificate{certChain[len(certChain)-1]})
			if got != tt.want {
				t.Errorf("Result.Success = %v, want %v", got, tt.want)
			}
		})
	}
}

func testCreatePki(certPem, keyPem []byte) ([]*x509.Certificate, *ecdsa.PrivateKey) {

	block, _ := pem.Decode(keyPem)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		log.Fatal("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	leaf, err := internal.ParseCertPem(certPem)
	if err != nil {
		log.Fatal("Failed to parse leaf certificate")
	}

	ca, err := internal.ParseCertPem(caPem)
	if err != nil {
		log.Fatal("Failed to parse ca certificate")
	}

	certChain := []*x509.Certificate{leaf, ca}

	return certChain, privateKey
}

var (
	caPem = []byte("-----BEGIN CERTIFICATE-----\nMIICCDCCAa6gAwIBAgIUHlBy6FprYzqjMvh/LTIgljJU7qAwCgYIKoZIzj0EAwIw\nYTELMAkGA1UEBhMCREUxEjAQBgNVBAcTCVRlc3QgQ2l0eTEVMBMGA1UEChMMVGVz\ndCBDb21wYW55MRAwDgYDVQQLEwdSb290IENBMRUwEwYDVQQDEwxUZXN0IFJvb3Qg\nQ0EwIBcNMjMxMDE3MTMxMzAwWhgPMjEyMzA5MjMxMzEzMDBaMGExCzAJBgNVBAYT\nAkRFMRIwEAYDVQQHEwlUZXN0IENpdHkxFTATBgNVBAoTDFRlc3QgQ29tcGFueTEQ\nMA4GA1UECxMHUm9vdCBDQTEVMBMGA1UEAxMMVGVzdCBSb290IENBMFkwEwYHKoZI\nzj0CAQYIKoZIzj0DAQcDQgAE+o+oQY6CsBJWvUlKgyjYo/4TeZhSTtNkshKyM1m8\neBfwC2uimBN/48Tf3c5vd1j0AfDYoCiXTGNNkAAeaLuilKNCMEAwDgYDVR0PAQH/\nBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFIgDf9NsuRHtvE8loiif\nJSW/Dss/MAoGCCqGSM49BAMCA0gAMEUCIQDmUvdPMueI9AfKnCu/xMxCCRgc5QBd\nDJMJB2960zTM0wIgcD+6ln+vc4pEfore6nEi4PRU9LUzDWoR6p3RTMjYqBs=\n-----END CERTIFICATE-----")

	leafPem = []byte("-----BEGIN CERTIFICATE-----\nMIICiDCCAi2gAwIBAgIUSJGafmo7MmWngNWHH6K4eK4eUjQwCgYIKoZIzj0EAwIw\nYTELMAkGA1UEBhMCREUxEjAQBgNVBAcTCVRlc3QgQ2l0eTEVMBMGA1UEChMMVGVz\ndCBDb21wYW55MRAwDgYDVQQLEwdSb290IENBMRUwEwYDVQQDEwxUZXN0IFJvb3Qg\nQ0EwIBcNMjMxMDE3MTMxMzAwWhgPMjEyMzA5MjMxMzEzMDBaMH8xCzAJBgNVBAYT\nAkRFMRIwEAYDVQQHEwlUZXN0IENpdHkxFTATBgNVBAoTDFRlc3QgQ29tcGFueTEh\nMB8GA1UECxMYVGVzdCBPcmdhbml6YXRpb25hbCBVbml0MSIwIAYDVQQDExlDTUMg\nVGVzdCBMZWFmIENlcnRpZmljYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\ny5aO298rJCVw2Qp6AmLdGJSwuDA8LM10bOm4aaSY3+U1kDVnaLIROqsl4eAQlvk6\nyaPT+449etaSkRIe5/VzoaOBojCBnzAOBgNVHQ8BAf8EBAMCBsAwEwYDVR0lBAww\nCgYIKwYBBQUHAwMwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUOd5fh6j3ti0YEAhL\n+WA2ybmQmjowHwYDVR0jBBgwFoAUiAN/02y5Ee28TyWiKJ8lJb8Oyz8wKgYIKwYB\nBQUHAQEEHjAcMBoGCCsGAQUFBzABhg4xMjcuMC4wLjE6ODg4ODAKBggqhkjOPQQD\nAgNJADBGAiEAwai3YHcyIhkhOwI/4EKkEzg8qF4oECTEuKUCABx7B/QCIQDJ5/Lz\nTRWEeWFgiFNajwtjcb7Zw8GpVCMvmOHXIiyVCg==\n-----END CERTIFICATE-----")

	leafKeyPem = []byte("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBtfuuByqsTuEltJwLiOqwOwq6xbxAs7+/ULS9woePsDoAoGCCqGSM49\nAwEHoUQDQgAEy5aO298rJCVw2Qp6AmLdGJSwuDA8LM10bOm4aaSY3+U1kDVnaLIR\nOqsl4eAQlvk6yaPT+449etaSkRIe5/VzoQ==\n-----END EC PRIVATE KEY-----")
)
