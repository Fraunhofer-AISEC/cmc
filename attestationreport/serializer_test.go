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

package attestationreport

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
)

type SwSigner struct {
	certChain []*x509.Certificate
	priv      crypto.PrivateKey
}

func (s *SwSigner) Name() string {
	return "SW Driver"
}

func (s *SwSigner) Init(c *DriverConfig) error {
	return nil
}

func (s *SwSigner) Measure(nonce []byte) (Measurement, error) {
	return Measurement{}, nil
}

func (s *SwSigner) Lock() error {
	return nil
}

func (s *SwSigner) Unlock() error {
	return nil
}

func (s *SwSigner) GetKeyHandles(sel KeySelection) (crypto.PrivateKey, crypto.PublicKey, error) {
	return s.priv, &s.priv.(*ecdsa.PrivateKey).PublicKey, nil
}

func (s *SwSigner) GetCertChain(sel KeySelection) ([]*x509.Certificate, error) {
	return s.certChain, nil
}

func TestVerify(t *testing.T) {
	type args struct {
		ar             AttestationReport
		roots          []*x509.Certificate
		useSystemCerts bool
		pubKey         crypto.PublicKey
		s              Serializer
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Success Verify Cert Chain JSON",
			args: args{
				ar: AttestationReport{
					Type: "Attestation Report",
				},
				roots:          []*x509.Certificate{getCert(caPem)},
				useSystemCerts: false,
				pubKey:         nil,
				s:              JsonSerializer{},
			},
			want: true,
		},
		{
			name: "Success Verify Key JSON",
			args: args{
				ar: AttestationReport{
					Type: "Attestation Report",
				},
				roots:          nil,
				useSystemCerts: false,
				pubKey:         getPublicKey(leafKeyPem),
				s:              JsonSerializer{},
			},
			want: true,
		},
		{
			name: "Fail Invalid Cert Chain JSON",
			args: args{
				ar: AttestationReport{
					Type: "Attestation Report",
				},
				roots:          []*x509.Certificate{getCert(invalidCaPem)},
				useSystemCerts: false,
				s:              JsonSerializer{},
			},
			want: false,
		},
		{
			name: "Fail Verify Key JSON",
			args: args{
				ar: AttestationReport{
					Type: "Attestation Report",
				},
				roots:          nil,
				useSystemCerts: false,
				pubKey:         getPublicKey(invalidLeafKeyPem),
				s:              JsonSerializer{},
			},
			want: false,
		},
		{
			name: "Success Verify Cert Chain CBOR",
			args: args{
				ar: AttestationReport{
					Type: "Attestation Report",
				},
				roots:          []*x509.Certificate{getCert(caPem)},
				useSystemCerts: false,
				pubKey:         nil,
				s:              CborSerializer{},
			},
			want: true,
		},
		{
			name: "Success Verify Key CBOR",
			args: args{
				ar: AttestationReport{
					Type: "Attestation Report",
				},
				roots:          nil,
				useSystemCerts: false,
				pubKey:         getPublicKey(leafKeyPem),
				s:              CborSerializer{},
			},
			want: true,
		},
		{
			name: "Fail Invalid Cert Chain CBOR",
			args: args{
				ar: AttestationReport{
					Type: "Attestation Report",
				},
				roots:          []*x509.Certificate{getCert(invalidCaPem)},
				useSystemCerts: false,
				s:              CborSerializer{},
			},
			want: false,
		},
		{
			name: "Fail Verify Key CBOR",
			args: args{
				ar: AttestationReport{
					Type: "Attestation Report",
				},
				roots:          nil,
				useSystemCerts: false,
				pubKey:         getPublicKey(invalidLeafKeyPem),
				s:              CborSerializer{},
			},
			want: false,
		},
	}

	// Setup logger
	logrus.SetLevel(logrus.TraceLevel)

	// Setup certificate chain and keys
	certchain := getCertchain(validCertChain)
	key := getPrivateKey(leafKeyPem)
	signer := &SwSigner{
		certChain: certchain,
		priv:      key,
	}

	// Perform unit tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Sign
			report, err := tt.args.s.Marshal(tt.args.ar)
			if err != nil {
				t.Errorf("Failed to setup test. Marshal failed")
			}

			coseRaw, err := tt.args.s.Sign(report, signer, IK)
			if err != nil {
				t.Errorf("Failed to setup test. Sign failed: %v", err)
			}

			// FUT: Verify
			_, _, got := tt.args.s.Verify(coseRaw, tt.args.roots, tt.args.useSystemCerts, tt.args.pubKey)
			if got != tt.want {
				t.Errorf("Result.Success = %v, want %v", got, tt.want)
			}
		})
	}
}

func getPrivateKey(keyPem []byte) *ecdsa.PrivateKey {

	block, _ := pem.Decode(keyPem)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		log.Fatal("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	return privateKey
}

func getPublicKey(keyPem []byte) *ecdsa.PublicKey {
	return &getPrivateKey(keyPem).PublicKey
}

func getCertchain(certs [][]byte) []*x509.Certificate {

	certchain := make([]*x509.Certificate, 0, len(certs))
	for _, c := range certs {
		cert, err := internal.ParseCert(c)
		if err != nil {
			log.Fatal("Failed to parse leaf certificate")
		}
		certchain = append(certchain, cert)
	}

	return certchain
}

func getCert(cert []byte) *x509.Certificate {

	c, err := internal.ParseCert(cert)
	if err != nil {
		log.Fatal("Failed to parse leaf certificate")
	}

	return c
}

var (
	caPem = []byte("-----BEGIN CERTIFICATE-----\nMIICCDCCAa6gAwIBAgIUHlBy6FprYzqjMvh/LTIgljJU7qAwCgYIKoZIzj0EAwIw\nYTELMAkGA1UEBhMCREUxEjAQBgNVBAcTCVRlc3QgQ2l0eTEVMBMGA1UEChMMVGVz\ndCBDb21wYW55MRAwDgYDVQQLEwdSb290IENBMRUwEwYDVQQDEwxUZXN0IFJvb3Qg\nQ0EwIBcNMjMxMDE3MTMxMzAwWhgPMjEyMzA5MjMxMzEzMDBaMGExCzAJBgNVBAYT\nAkRFMRIwEAYDVQQHEwlUZXN0IENpdHkxFTATBgNVBAoTDFRlc3QgQ29tcGFueTEQ\nMA4GA1UECxMHUm9vdCBDQTEVMBMGA1UEAxMMVGVzdCBSb290IENBMFkwEwYHKoZI\nzj0CAQYIKoZIzj0DAQcDQgAE+o+oQY6CsBJWvUlKgyjYo/4TeZhSTtNkshKyM1m8\neBfwC2uimBN/48Tf3c5vd1j0AfDYoCiXTGNNkAAeaLuilKNCMEAwDgYDVR0PAQH/\nBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFIgDf9NsuRHtvE8loiif\nJSW/Dss/MAoGCCqGSM49BAMCA0gAMEUCIQDmUvdPMueI9AfKnCu/xMxCCRgc5QBd\nDJMJB2960zTM0wIgcD+6ln+vc4pEfore6nEi4PRU9LUzDWoR6p3RTMjYqBs=\n-----END CERTIFICATE-----")

	invalidCaPem = []byte("-----BEGIN CERTIFICATE-----\nMIICBjCCAaygAwIBAgIUbzIW+iUiIFmCWbOL4rW4UBQfj7AwCgYIKoZIzj0EAwIw\nYTELMAkGA1UEBhMCREUxEjAQBgNVBAcTCVRlc3QgQ2l0eTEVMBMGA1UEChMMVGVz\ndCBDb21wYW55MRAwDgYDVQQLEwdSb290IENBMRUwEwYDVQQDEwxUZXN0IFJvb3Qg\nQ0EwHhcNMjIxMDIzMTcwMTAwWhcNMjcxMDIyMTcwMTAwWjBhMQswCQYDVQQGEwJE\nRTESMBAGA1UEBxMJVGVzdCBDaXR5MRUwEwYDVQQKEwxUZXN0IENvbXBhbnkxEDAO\nBgNVBAsTB1Jvb3QgQ0ExFTATBgNVBAMTDFRlc3QgUm9vdCBDQTBZMBMGByqGSM49\nAgEGCCqGSM49AwEHA0IABEqaNo91iTSSbc9BL1iIQIVpZLd88RL5LfH15SVugJy4\n3d0jeE+KHtpQA8FpAvxXQHJm31z5V6+oLG4MQfVHN/GjQjBAMA4GA1UdDwEB/wQE\nAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQ/hcnLtyQF97DU0kTLwAQ0\nQ3jiAjAKBggqhkjOPQQDAgNIADBFAiAFsmaZDBu+cfOqX9a5YAOgSeYB4Sb+r18m\nBIcuxwthhgIhALRHfA32ZcOA6piTKtWLZsdsG6CH50KGImHlkj4TwfXw\n-----END CERTIFICATE-----")

	leafPem = []byte("-----BEGIN CERTIFICATE-----\nMIICiDCCAi2gAwIBAgIUSJGafmo7MmWngNWHH6K4eK4eUjQwCgYIKoZIzj0EAwIw\nYTELMAkGA1UEBhMCREUxEjAQBgNVBAcTCVRlc3QgQ2l0eTEVMBMGA1UEChMMVGVz\ndCBDb21wYW55MRAwDgYDVQQLEwdSb290IENBMRUwEwYDVQQDEwxUZXN0IFJvb3Qg\nQ0EwIBcNMjMxMDE3MTMxMzAwWhgPMjEyMzA5MjMxMzEzMDBaMH8xCzAJBgNVBAYT\nAkRFMRIwEAYDVQQHEwlUZXN0IENpdHkxFTATBgNVBAoTDFRlc3QgQ29tcGFueTEh\nMB8GA1UECxMYVGVzdCBPcmdhbml6YXRpb25hbCBVbml0MSIwIAYDVQQDExlDTUMg\nVGVzdCBMZWFmIENlcnRpZmljYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\ny5aO298rJCVw2Qp6AmLdGJSwuDA8LM10bOm4aaSY3+U1kDVnaLIROqsl4eAQlvk6\nyaPT+449etaSkRIe5/VzoaOBojCBnzAOBgNVHQ8BAf8EBAMCBsAwEwYDVR0lBAww\nCgYIKwYBBQUHAwMwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUOd5fh6j3ti0YEAhL\n+WA2ybmQmjowHwYDVR0jBBgwFoAUiAN/02y5Ee28TyWiKJ8lJb8Oyz8wKgYIKwYB\nBQUHAQEEHjAcMBoGCCsGAQUFBzABhg4xMjcuMC4wLjE6ODg4ODAKBggqhkjOPQQD\nAgNJADBGAiEAwai3YHcyIhkhOwI/4EKkEzg8qF4oECTEuKUCABx7B/QCIQDJ5/Lz\nTRWEeWFgiFNajwtjcb7Zw8GpVCMvmOHXIiyVCg==\n-----END CERTIFICATE-----")

	validCertChain = [][]byte{leafPem, caPem}

	leafKeyPem = []byte("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBtfuuByqsTuEltJwLiOqwOwq6xbxAs7+/ULS9woePsDoAoGCCqGSM49\nAwEHoUQDQgAEy5aO298rJCVw2Qp6AmLdGJSwuDA8LM10bOm4aaSY3+U1kDVnaLIR\nOqsl4eAQlvk6yaPT+449etaSkRIe5/VzoQ==\n-----END EC PRIVATE KEY-----")

	invalidLeafKeyPem = []byte("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEILCeAiFZCRKjjcaqvs7tpRxcObBJ7BxD8wdPUmK4hVHKoAoGCCqGSM49\nAwEHoUQDQgAEnaUv5jCF6nnq1Gp7UNaZ8V+u1MJ+PLMqkGvFsz8O9k4tZOivFNiI\nK2+9PA4MkgbL5Maoz1FUV1t6pBuS9nZCtg==\n-----END EC PRIVATE KEY-----\n")
)
