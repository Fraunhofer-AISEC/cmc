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
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
)

type SwDriver struct {
	certChain []*x509.Certificate
	priv      crypto.PrivateKey
}

func (s *SwDriver) Name() string {
	return "SW Driver"
}

func (s *SwDriver) Init(c *DriverConfig) error {
	return nil
}

func (s *SwDriver) Measure(nonce []byte) (Measurement, error) {
	return Measurement{}, nil
}

func (s *SwDriver) Lock() error {
	return nil
}

func (s *SwDriver) Unlock() error {
	return nil
}

func (s *SwDriver) GetKeyHandles(sel KeySelection) (crypto.PrivateKey, crypto.PublicKey, error) {
	return s.priv, &s.priv.(*ecdsa.PrivateKey).PublicKey, nil
}

func (s *SwDriver) GetCertChain(sel KeySelection) ([]*x509.Certificate, error) {
	return s.certChain, nil
}

func TestSign(t *testing.T) {
	type args struct {
		ar     AttestationReport
		driver Driver
		sel    KeySelection
	}
	tests := []struct {
		name    string
		s       Serializer
		args    args
		wantErr bool
	}{
		{
			name: "Success Sign JSON Cert Chain",
			s:    JsonSerializer{},
			args: args{
				ar: AttestationReport{
					Type: "Attestation Report",
				},
				driver: &SwDriver{
					certChain: getCertchain(validCertChain),
					priv:      getPrivateKey(leafKeyPem),
				},
				sel: IK,
			},
			wantErr: false,
		},
		{
			name: "Success Sign JSON Self-Signed Cert",
			s:    JsonSerializer{},
			args: args{
				ar: AttestationReport{
					Type: "Attestation Report",
				},
				driver: &SwDriver{
					certChain: getCertchain([][]byte{selfSignedCert}),
					priv:      getPrivateKey(selfSignedKey),
				},
				sel: IK,
			},
			wantErr: false,
		},
		{
			name: "Success Sign JSON Public Key",
			s:    JsonSerializer{},
			args: args{
				ar: AttestationReport{
					Type: "Attestation Report",
				},
				driver: &SwDriver{
					priv: getPrivateKey(leafKeyPem),
				},
				sel: IK,
			},
			wantErr: false,
		},
		{
			name: "Success Sign JSON Cert Chain Invalid Key",
			s:    JsonSerializer{},
			args: args{
				ar: AttestationReport{
					Type: "Attestation Report",
				},
				driver: &SwDriver{
					certChain: getCertchain(validCertChain),
					priv:      getPrivateKey(selfSignedKey), // Wrong key
				},
				sel: IK,
			},
			wantErr: false,
		},
		{
			name: "Success Sign JSON Self-Signed Invalid Cert",
			s:    JsonSerializer{},
			args: args{
				ar: AttestationReport{
					Type: "Attestation Report",
				},
				driver: &SwDriver{
					certChain: getCertchain([][]byte{leafPem}), // Not a self-signed cert
					priv:      getPrivateKey(leafKeyPem),
				},
				sel: IK,
			},
			wantErr: false,
		},
		{
			name: "Success Sign CBOR Cert Chain",
			s:    CborSerializer{},
			args: args{
				ar: AttestationReport{
					Type: "Attestation Report",
				},
				driver: &SwDriver{
					certChain: getCertchain(validCertChain),
					priv:      getPrivateKey(leafKeyPem),
				},
				sel: IK,
			},
			wantErr: false,
		},
		{
			name: "Success Sign CBOR Self-Signed Cert",
			s:    CborSerializer{},
			args: args{
				ar: AttestationReport{
					Type: "Attestation Report",
				},
				driver: &SwDriver{
					certChain: getCertchain([][]byte{selfSignedCert}),
					priv:      getPrivateKey(selfSignedKey),
				},
				sel: IK,
			},
			wantErr: false,
		},
		{
			name: "Success Sign CBOR Public Key",
			s:    CborSerializer{},
			args: args{
				ar: AttestationReport{
					Type: "Attestation Report",
				},
				driver: &SwDriver{
					priv: getPrivateKey(leafKeyPem),
				},
				sel: IK,
			},
			wantErr: false,
		},
		{
			name: "Success Sign CBOR Cert Chain Invalid Key",
			s:    CborSerializer{},
			args: args{
				ar: AttestationReport{
					Type: "Attestation Report",
				},
				driver: &SwDriver{
					certChain: getCertchain(validCertChain),
					priv:      getPrivateKey(selfSignedKey), // Wrong key
				},
				sel: IK,
			},
			wantErr: false,
		},
		{
			name: "Success Sign CBOR Self-Signed Invalid Cert",
			s:    CborSerializer{},
			args: args{
				ar: AttestationReport{
					Type: "Attestation Report",
				},
				driver: &SwDriver{
					certChain: getCertchain([][]byte{leafPem}), // Not a self-signed cert
					priv:      getPrivateKey(leafKeyPem),
				},
				sel: IK,
			},
			wantErr: false,
		},
	}

	// Setup logger
	logrus.SetLevel(logrus.TraceLevel)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			report, err := tt.s.Marshal(tt.args.ar)
			if err != nil {
				t.Errorf("Failed to setup test. Marshal failed")
			}

			raw, err := tt.s.Sign(report, tt.args.driver, tt.args.sel)
			if (err != nil) != tt.wantErr {
				t.Errorf("Serializer.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Optionally print output
			switch tt.s.(type) {
			case JsonSerializer:
				log.Tracef("signed JSON report: %v", string(raw))
			case CborSerializer:
				log.Tracef("signed CBOR report: %v", hex.EncodeToString(raw))
			}

		})
	}
}

func TestVerify(t *testing.T) {
	type args struct {
		data     []byte
		verifier interface{}
		s        Serializer
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Success Verify Cert Chain JSON",
			args: args{
				data:     jwsDataCertChain,
				verifier: []*x509.Certificate{getCert(caPem)},
				s:        JsonSerializer{},
			},
			want: true,
		},
		{
			name: "Success Verify Key JSON",
			args: args{
				data:     jwsDataPubKey,
				verifier: getPublicKey(leafKeyPem),
				s:        JsonSerializer{},
			},
			want: true,
		},
		{
			name: "Fail Invalid Cert Chain Invalid CA JSON",
			args: args{
				data:     jwsDataCertChain,
				verifier: []*x509.Certificate{getCert(invalidCaPem)},
				s:        JsonSerializer{},
			},
			want: false,
		},
		{
			name: "Fail Verify Key JSON",
			args: args{
				data:     jwsDataPubKey,
				verifier: getPublicKey(invalidLeafKeyPem),
				s:        JsonSerializer{},
			},
			want: false,
		},
		{
			name: "Fail Verify Cert Chain Invalid Key JSON",
			args: args{
				data:     jwsDataCertChainInvalidKey,
				verifier: []*x509.Certificate{getCert(caPem)},
				s:        JsonSerializer{},
			},
			want: false,
		},
		{
			name: "Success Verify Cert Chain CBOR",
			args: args{
				data:     coseDataCertChain,
				verifier: []*x509.Certificate{getCert(caPem)},
				s:        CborSerializer{},
			},
			want: true,
		},
		{
			name: "Success Verify Key CBOR",
			args: args{
				data:     coseDataPubKey,
				verifier: getPublicKey(leafKeyPem),
				s:        CborSerializer{},
			},
			want: true,
		},
		{
			name: "Fail Invalid Cert Chain Invalid CA CBOR",
			args: args{
				data:     coseDataCertChain,
				verifier: []*x509.Certificate{getCert(invalidCaPem)},
				s:        CborSerializer{},
			},
			want: false,
		},
		{
			name: "Fail Verify Key CBOR",
			args: args{
				data:     coseDataPubKey,
				verifier: getPublicKey(invalidLeafKeyPem),
				s:        CborSerializer{},
			},
			want: false,
		},
		{
			name: "Fail Verify Cert Chain Invalid Key CBOR",
			args: args{
				data:     coseDataCertChainInvalidKey,
				verifier: []*x509.Certificate{getCert(caPem)},
				s:        CborSerializer{},
			},
			want: false,
		},
	}

	// Setup logger
	logrus.SetLevel(logrus.TraceLevel)

	// Perform unit tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// FUT: Verify
			_, _, got := tt.args.s.Verify(tt.args.data, tt.args.verifier)
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

func dec(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("Failed to decode: %v", err)
	}
	return b
}

var (
	caPem = []byte("-----BEGIN CERTIFICATE-----\nMIICCDCCAa6gAwIBAgIUHlBy6FprYzqjMvh/LTIgljJU7qAwCgYIKoZIzj0EAwIw\nYTELMAkGA1UEBhMCREUxEjAQBgNVBAcTCVRlc3QgQ2l0eTEVMBMGA1UEChMMVGVz\ndCBDb21wYW55MRAwDgYDVQQLEwdSb290IENBMRUwEwYDVQQDEwxUZXN0IFJvb3Qg\nQ0EwIBcNMjMxMDE3MTMxMzAwWhgPMjEyMzA5MjMxMzEzMDBaMGExCzAJBgNVBAYT\nAkRFMRIwEAYDVQQHEwlUZXN0IENpdHkxFTATBgNVBAoTDFRlc3QgQ29tcGFueTEQ\nMA4GA1UECxMHUm9vdCBDQTEVMBMGA1UEAxMMVGVzdCBSb290IENBMFkwEwYHKoZI\nzj0CAQYIKoZIzj0DAQcDQgAE+o+oQY6CsBJWvUlKgyjYo/4TeZhSTtNkshKyM1m8\neBfwC2uimBN/48Tf3c5vd1j0AfDYoCiXTGNNkAAeaLuilKNCMEAwDgYDVR0PAQH/\nBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFIgDf9NsuRHtvE8loiif\nJSW/Dss/MAoGCCqGSM49BAMCA0gAMEUCIQDmUvdPMueI9AfKnCu/xMxCCRgc5QBd\nDJMJB2960zTM0wIgcD+6ln+vc4pEfore6nEi4PRU9LUzDWoR6p3RTMjYqBs=\n-----END CERTIFICATE-----")

	invalidCaPem = []byte("-----BEGIN CERTIFICATE-----\nMIICBjCCAaygAwIBAgIUbzIW+iUiIFmCWbOL4rW4UBQfj7AwCgYIKoZIzj0EAwIw\nYTELMAkGA1UEBhMCREUxEjAQBgNVBAcTCVRlc3QgQ2l0eTEVMBMGA1UEChMMVGVz\ndCBDb21wYW55MRAwDgYDVQQLEwdSb290IENBMRUwEwYDVQQDEwxUZXN0IFJvb3Qg\nQ0EwHhcNMjIxMDIzMTcwMTAwWhcNMjcxMDIyMTcwMTAwWjBhMQswCQYDVQQGEwJE\nRTESMBAGA1UEBxMJVGVzdCBDaXR5MRUwEwYDVQQKEwxUZXN0IENvbXBhbnkxEDAO\nBgNVBAsTB1Jvb3QgQ0ExFTATBgNVBAMTDFRlc3QgUm9vdCBDQTBZMBMGByqGSM49\nAgEGCCqGSM49AwEHA0IABEqaNo91iTSSbc9BL1iIQIVpZLd88RL5LfH15SVugJy4\n3d0jeE+KHtpQA8FpAvxXQHJm31z5V6+oLG4MQfVHN/GjQjBAMA4GA1UdDwEB/wQE\nAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQ/hcnLtyQF97DU0kTLwAQ0\nQ3jiAjAKBggqhkjOPQQDAgNIADBFAiAFsmaZDBu+cfOqX9a5YAOgSeYB4Sb+r18m\nBIcuxwthhgIhALRHfA32ZcOA6piTKtWLZsdsG6CH50KGImHlkj4TwfXw\n-----END CERTIFICATE-----")

	leafPem = []byte("-----BEGIN CERTIFICATE-----\nMIICiDCCAi2gAwIBAgIUSJGafmo7MmWngNWHH6K4eK4eUjQwCgYIKoZIzj0EAwIw\nYTELMAkGA1UEBhMCREUxEjAQBgNVBAcTCVRlc3QgQ2l0eTEVMBMGA1UEChMMVGVz\ndCBDb21wYW55MRAwDgYDVQQLEwdSb290IENBMRUwEwYDVQQDEwxUZXN0IFJvb3Qg\nQ0EwIBcNMjMxMDE3MTMxMzAwWhgPMjEyMzA5MjMxMzEzMDBaMH8xCzAJBgNVBAYT\nAkRFMRIwEAYDVQQHEwlUZXN0IENpdHkxFTATBgNVBAoTDFRlc3QgQ29tcGFueTEh\nMB8GA1UECxMYVGVzdCBPcmdhbml6YXRpb25hbCBVbml0MSIwIAYDVQQDExlDTUMg\nVGVzdCBMZWFmIENlcnRpZmljYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\ny5aO298rJCVw2Qp6AmLdGJSwuDA8LM10bOm4aaSY3+U1kDVnaLIROqsl4eAQlvk6\nyaPT+449etaSkRIe5/VzoaOBojCBnzAOBgNVHQ8BAf8EBAMCBsAwEwYDVR0lBAww\nCgYIKwYBBQUHAwMwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUOd5fh6j3ti0YEAhL\n+WA2ybmQmjowHwYDVR0jBBgwFoAUiAN/02y5Ee28TyWiKJ8lJb8Oyz8wKgYIKwYB\nBQUHAQEEHjAcMBoGCCsGAQUFBzABhg4xMjcuMC4wLjE6ODg4ODAKBggqhkjOPQQD\nAgNJADBGAiEAwai3YHcyIhkhOwI/4EKkEzg8qF4oECTEuKUCABx7B/QCIQDJ5/Lz\nTRWEeWFgiFNajwtjcb7Zw8GpVCMvmOHXIiyVCg==\n-----END CERTIFICATE-----")

	validCertChain = [][]byte{leafPem, caPem}

	leafKeyPem = []byte("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBtfuuByqsTuEltJwLiOqwOwq6xbxAs7+/ULS9woePsDoAoGCCqGSM49\nAwEHoUQDQgAEy5aO298rJCVw2Qp6AmLdGJSwuDA8LM10bOm4aaSY3+U1kDVnaLIR\nOqsl4eAQlvk6yaPT+449etaSkRIe5/VzoQ==\n-----END EC PRIVATE KEY-----")

	invalidLeafKeyPem = []byte("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEILCeAiFZCRKjjcaqvs7tpRxcObBJ7BxD8wdPUmK4hVHKoAoGCCqGSM49\nAwEHoUQDQgAEnaUv5jCF6nnq1Gp7UNaZ8V+u1MJ+PLMqkGvFsz8O9k4tZOivFNiI\nK2+9PA4MkgbL5Maoz1FUV1t6pBuS9nZCtg==\n-----END EC PRIVATE KEY-----\n")

	selfSignedKey = []byte("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIHlaMSc+eGAcftVZPJqHQISvb8MdxeWagc5WNjtJux1soAoGCCqGSM49\nAwEHoUQDQgAEYWv7VLnXBgyBomY1AR061kMihVFziMrXKnBSbaBWFXCg8mbI8/57\nYN1nEFHLunoPWqIt7I+ZDP79omD95yzp1g==\n-----END EC PRIVATE KEY-----")

	selfSignedCert = []byte("-----BEGIN CERTIFICATE-----\nMIIB9jCCAZugAwIBAgIUEzwVI6QmZSfd1WhLDkiLSm0zSPswCgYIKoZIzj0EAwIw\nUDELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkJZMREwDwYDVQQHDAhUZXN0Q2l0eTEO\nMAwGA1UECgwFTXlPcmcxETAPBgNVBAMMCFRlc3RDZXJ0MB4XDTI1MDcwMzEzMzE1\nNFoXDTM1MDcwMTEzMzE1NFowUDELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkJZMREw\nDwYDVQQHDAhUZXN0Q2l0eTEOMAwGA1UECgwFTXlPcmcxETAPBgNVBAMMCFRlc3RD\nZXJ0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYWv7VLnXBgyBomY1AR061kMi\nhVFziMrXKnBSbaBWFXCg8mbI8/57YN1nEFHLunoPWqIt7I+ZDP79omD95yzp1qNT\nMFEwHQYDVR0OBBYEFLVI7tjOFi72cmF16NPmbIAh/cnxMB8GA1UdIwQYMBaAFLVI\n7tjOFi72cmF16NPmbIAh/cnxMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwID\nSQAwRgIhAIjh2jVXSNv4HmeMQmRiYqXM8mrTNXCyH+oOcssKFOKoAiEApIpAUe3x\nvaIVauUAWuEUEedKsSF1diGMTAPlv1OhzGM=\n-----END CERTIFICATE-----")

	jwsDataCertChain = []byte(`{"payload":"eyJ2ZXJzaW9uIjoiIiwidHlwZSI6IkF0dGVzdGF0aW9uIFJlcG9ydCJ9","protected":"eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDaURDQ0FpMmdBd0lCQWdJVVNKR2FmbW83TW1XbmdOV0hINks0ZUs0ZVVqUXdDZ1lJS29aSXpqMEVBd0l3WVRFTE1Ba0dBMVVFQmhNQ1JFVXhFakFRQmdOVkJBY1RDVlJsYzNRZ1EybDBlVEVWTUJNR0ExVUVDaE1NVkdWemRDQkRiMjF3WVc1NU1SQXdEZ1lEVlFRTEV3ZFNiMjkwSUVOQk1SVXdFd1lEVlFRREV3eFVaWE4wSUZKdmIzUWdRMEV3SUJjTk1qTXhNREUzTVRNeE16QXdXaGdQTWpFeU16QTVNak14TXpFek1EQmFNSDh4Q3pBSkJnTlZCQVlUQWtSRk1SSXdFQVlEVlFRSEV3bFVaWE4wSUVOcGRIa3hGVEFUQmdOVkJBb1RERlJsYzNRZ1EyOXRjR0Z1ZVRFaE1COEdBMVVFQ3hNWVZHVnpkQ0JQY21kaGJtbDZZWFJwYjI1aGJDQlZibWwwTVNJd0lBWURWUVFERXhsRFRVTWdWR1Z6ZENCTVpXRm1JRU5sY25ScFptbGpZWFJsTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFeTVhTzI5OHJKQ1Z3MlFwNkFtTGRHSlN3dURBOExNMTBiT200YWFTWTMrVTFrRFZuYUxJUk9xc2w0ZUFRbHZrNnlhUFQrNDQ5ZXRhU2tSSWU1L1Z6b2FPQm9qQ0JuekFPQmdOVkhROEJBZjhFQkFNQ0JzQXdFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUhBd013REFZRFZSMFRBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVVPZDVmaDZqM3RpMFlFQWhMK1dBMnlibVFtam93SHdZRFZSMGpCQmd3Rm9BVWlBTi8wMnk1RWUyOFR5V2lLSjhsSmI4T3l6OHdLZ1lJS3dZQkJRVUhBUUVFSGpBY01Cb0dDQ3NHQVFVRkJ6QUJoZzR4TWpjdU1DNHdMakU2T0RnNE9EQUtCZ2dxaGtqT1BRUURBZ05KQURCR0FpRUF3YWkzWUhjeUloa2hPd0kvNEVLa0V6ZzhxRjRvRUNURXVLVUNBQng3Qi9RQ0lRREo1L0x6VFJXRWVXRmdpRk5hand0amNiN1p3OEdwVkNNdm1PSFhJaXlWQ2c9PSIsIk1JSUNDRENDQWE2Z0F3SUJBZ0lVSGxCeTZGcHJZenFqTXZoL0xUSWdsakpVN3FBd0NnWUlLb1pJemowRUF3SXdZVEVMTUFrR0ExVUVCaE1DUkVVeEVqQVFCZ05WQkFjVENWUmxjM1FnUTJsMGVURVZNQk1HQTFVRUNoTU1WR1Z6ZENCRGIyMXdZVzU1TVJBd0RnWURWUVFMRXdkU2IyOTBJRU5CTVJVd0V3WURWUVFERXd4VVpYTjBJRkp2YjNRZ1EwRXdJQmNOTWpNeE1ERTNNVE14TXpBd1doZ1BNakV5TXpBNU1qTXhNekV6TURCYU1HRXhDekFKQmdOVkJBWVRBa1JGTVJJd0VBWURWUVFIRXdsVVpYTjBJRU5wZEhreEZUQVRCZ05WQkFvVERGUmxjM1FnUTI5dGNHRnVlVEVRTUE0R0ExVUVDeE1IVW05dmRDQkRRVEVWTUJNR0ExVUVBeE1NVkdWemRDQlNiMjkwSUVOQk1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRStvK29RWTZDc0JKV3ZVbEtneWpZby80VGVaaFNUdE5rc2hLeU0xbThlQmZ3QzJ1aW1CTi80OFRmM2M1dmQxajBBZkRZb0NpWFRHTk5rQUFlYUx1aWxLTkNNRUF3RGdZRFZSMFBBUUgvQkFRREFnRUdNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdIUVlEVlIwT0JCWUVGSWdEZjlOc3VSSHR2RThsb2lpZkpTVy9Ec3MvTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSVFEbVV2ZFBNdWVJOUFmS25DdS94TXhDQ1JnYzVRQmRESk1KQjI5NjB6VE0wd0lnY0QrNmxuK3ZjNHBFZm9yZTZuRWk0UFJVOUxVekRXb1I2cDNSVE1qWXFCcz0iXX0","signature":"X5fqkwGD_Ik9QNBy3KmVE0iEy22VYVgoad49xORvudSyzDZ0nuR8gRFKKMimd0j1GDqmGWx7Mpe_Agg2f2SA_Q"}`)

	jwsDataPubKey = []byte(`{"payload":"eyJ2ZXJzaW9uIjoiIiwidHlwZSI6IkF0dGVzdGF0aW9uIFJlcG9ydCJ9","protected":"eyJhbGciOiJFUzI1NiJ9","signature":"myV1dIj5BkVkm5DNvdDI9Nys4XxCvy5GihD5PYWb4AKIp1gJGli0MlhxyXstUa6eKH3Q3wPZj6KZv0z1sh4pkA"}`)

	jwsDataCertChainInvalidKey = []byte(`{"payload":"eyJ2ZXJzaW9uIjoiIiwidHlwZSI6IkF0dGVzdGF0aW9uIFJlcG9ydCJ9","protected":"eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDaURDQ0FpMmdBd0lCQWdJVVNKR2FmbW83TW1XbmdOV0hINks0ZUs0ZVVqUXdDZ1lJS29aSXpqMEVBd0l3WVRFTE1Ba0dBMVVFQmhNQ1JFVXhFakFRQmdOVkJBY1RDVlJsYzNRZ1EybDBlVEVWTUJNR0ExVUVDaE1NVkdWemRDQkRiMjF3WVc1NU1SQXdEZ1lEVlFRTEV3ZFNiMjkwSUVOQk1SVXdFd1lEVlFRREV3eFVaWE4wSUZKdmIzUWdRMEV3SUJjTk1qTXhNREUzTVRNeE16QXdXaGdQTWpFeU16QTVNak14TXpFek1EQmFNSDh4Q3pBSkJnTlZCQVlUQWtSRk1SSXdFQVlEVlFRSEV3bFVaWE4wSUVOcGRIa3hGVEFUQmdOVkJBb1RERlJsYzNRZ1EyOXRjR0Z1ZVRFaE1COEdBMVVFQ3hNWVZHVnpkQ0JQY21kaGJtbDZZWFJwYjI1aGJDQlZibWwwTVNJd0lBWURWUVFERXhsRFRVTWdWR1Z6ZENCTVpXRm1JRU5sY25ScFptbGpZWFJsTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFeTVhTzI5OHJKQ1Z3MlFwNkFtTGRHSlN3dURBOExNMTBiT200YWFTWTMrVTFrRFZuYUxJUk9xc2w0ZUFRbHZrNnlhUFQrNDQ5ZXRhU2tSSWU1L1Z6b2FPQm9qQ0JuekFPQmdOVkhROEJBZjhFQkFNQ0JzQXdFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUhBd013REFZRFZSMFRBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVVPZDVmaDZqM3RpMFlFQWhMK1dBMnlibVFtam93SHdZRFZSMGpCQmd3Rm9BVWlBTi8wMnk1RWUyOFR5V2lLSjhsSmI4T3l6OHdLZ1lJS3dZQkJRVUhBUUVFSGpBY01Cb0dDQ3NHQVFVRkJ6QUJoZzR4TWpjdU1DNHdMakU2T0RnNE9EQUtCZ2dxaGtqT1BRUURBZ05KQURCR0FpRUF3YWkzWUhjeUloa2hPd0kvNEVLa0V6ZzhxRjRvRUNURXVLVUNBQng3Qi9RQ0lRREo1L0x6VFJXRWVXRmdpRk5hand0amNiN1p3OEdwVkNNdm1PSFhJaXlWQ2c9PSIsIk1JSUNDRENDQWE2Z0F3SUJBZ0lVSGxCeTZGcHJZenFqTXZoL0xUSWdsakpVN3FBd0NnWUlLb1pJemowRUF3SXdZVEVMTUFrR0ExVUVCaE1DUkVVeEVqQVFCZ05WQkFjVENWUmxjM1FnUTJsMGVURVZNQk1HQTFVRUNoTU1WR1Z6ZENCRGIyMXdZVzU1TVJBd0RnWURWUVFMRXdkU2IyOTBJRU5CTVJVd0V3WURWUVFERXd4VVpYTjBJRkp2YjNRZ1EwRXdJQmNOTWpNeE1ERTNNVE14TXpBd1doZ1BNakV5TXpBNU1qTXhNekV6TURCYU1HRXhDekFKQmdOVkJBWVRBa1JGTVJJd0VBWURWUVFIRXdsVVpYTjBJRU5wZEhreEZUQVRCZ05WQkFvVERGUmxjM1FnUTI5dGNHRnVlVEVRTUE0R0ExVUVDeE1IVW05dmRDQkRRVEVWTUJNR0ExVUVBeE1NVkdWemRDQlNiMjkwSUVOQk1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRStvK29RWTZDc0JKV3ZVbEtneWpZby80VGVaaFNUdE5rc2hLeU0xbThlQmZ3QzJ1aW1CTi80OFRmM2M1dmQxajBBZkRZb0NpWFRHTk5rQUFlYUx1aWxLTkNNRUF3RGdZRFZSMFBBUUgvQkFRREFnRUdNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdIUVlEVlIwT0JCWUVGSWdEZjlOc3VSSHR2RThsb2lpZkpTVy9Ec3MvTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSVFEbVV2ZFBNdWVJOUFmS25DdS94TXhDQ1JnYzVRQmRESk1KQjI5NjB6VE0wd0lnY0QrNmxuK3ZjNHBFZm9yZTZuRWk0UFJVOUxVekRXb1I2cDNSVE1qWXFCcz0iXX0","signature":"5SY2i2odqzGBStJZPzVAuXtPKU9WNH2KT8rvdgVx22fmVDL95vg0n8sRwjZCSvfAEUnUHQMefzuBDCixQfNITw"}`)

	coseDataCertChain = dec("d8628440a057a2006001724174746573746174696f6e205265706f7274818343a10126a118218259028c308202883082022da003020102021448919a7e6a3b3265a780d5871fa2b878ae1e5234300a06082a8648ce3d0403023061310b3009060355040613024445311230100603550407130954657374204369747931153013060355040a130c5465737420436f6d70616e793110300e060355040b1307526f6f74204341311530130603550403130c5465737420526f6f742043413020170d3233313031373133313330305a180f32313233303932333133313330305a307f310b3009060355040613024445311230100603550407130954657374204369747931153013060355040a130c5465737420436f6d70616e793121301f060355040b131854657374204f7267616e697a6174696f6e616c20556e69743122302006035504031319434d432054657374204c6561662043657274696669636174653059301306072a8648ce3d020106082a8648ce3d03010703420004cb968edbdf2b242570d90a7a0262dd1894b0b8303c2ccd746ce9b869a498dfe53590356768b2113aab25e1e01096f93ac9a3d3fb8e3d7ad69291121ee7f573a1a381a230819f300e0603551d0f0101ff0404030206c030130603551d25040c300a06082b06010505070303300c0603551d130101ff04023000301d0603551d0e0416041439de5f87a8f7b62d1810084bf96036c9b9909a3a301f0603551d2304183016801488037fd36cb911edbc4f25a2289f2525bf0ecb3f302a06082b06010505070101041e301c301a06082b06010505073001860e3132372e302e302e313a38383838300a06082a8648ce3d0403020349003046022100c1a8b76077322219213b023fe042a413383ca85e281024c4b8a502001c7b07f4022100c9e7f2f34d158479616088535a8f0b6371bed9c3c1a954232f98e1d7222c950a59020c30820208308201aea00302010202141e5072e85a6b633aa332f87f2d3220963254eea0300a06082a8648ce3d0403023061310b3009060355040613024445311230100603550407130954657374204369747931153013060355040a130c5465737420436f6d70616e793110300e060355040b1307526f6f74204341311530130603550403130c5465737420526f6f742043413020170d3233313031373133313330305a180f32313233303932333133313330305a3061310b3009060355040613024445311230100603550407130954657374204369747931153013060355040a130c5465737420436f6d70616e793110300e060355040b1307526f6f74204341311530130603550403130c5465737420526f6f742043413059301306072a8648ce3d020106082a8648ce3d03010703420004fa8fa8418e82b01256bd494a8328d8a3fe137998524ed364b212b23359bc7817f00b6ba298137fe3c4dfddce6f7758f401f0d8a028974c634d90001e68bba294a3423040300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e0416041488037fd36cb911edbc4f25a2289f2525bf0ecb3f300a06082a8648ce3d0403020348003045022100e652f74f32e788f407ca9c2bbfc4cc4209181ce5005d0c9309076f7ad334ccd30220703fba967faf738a447e8adeea7122e0f454f4b5330d6a11ea9dd14cc8d8a81b58405ade6b64d1aeaf4e0803e6ec6ee7a086d49298d803aabf4bd603064c6d118280b6d8e6b80d17841d4ce5d30dcd9620b2e96ab1f380cabc387a6d2a7cf5956b67")

	coseDataPubKey = dec("d8628440a057a2006001724174746573746174696f6e205265706f7274818343a10126a118218058402dbad3480ec89afad0d5963a4912dcc17efa3be397d273b2bf8eba4c2bca99223b5d99a6ed6b67b93c7e0b607845436d51450d4fe7bc0396433e3acd7977083e")

	coseDataCertChainInvalidKey = dec("d8628440a057a2006001724174746573746174696f6e205265706f7274818343a10126a118218259028c308202883082022da003020102021448919a7e6a3b3265a780d5871fa2b878ae1e5234300a06082a8648ce3d0403023061310b3009060355040613024445311230100603550407130954657374204369747931153013060355040a130c5465737420436f6d70616e793110300e060355040b1307526f6f74204341311530130603550403130c5465737420526f6f742043413020170d3233313031373133313330305a180f32313233303932333133313330305a307f310b3009060355040613024445311230100603550407130954657374204369747931153013060355040a130c5465737420436f6d70616e793121301f060355040b131854657374204f7267616e697a6174696f6e616c20556e69743122302006035504031319434d432054657374204c6561662043657274696669636174653059301306072a8648ce3d020106082a8648ce3d03010703420004cb968edbdf2b242570d90a7a0262dd1894b0b8303c2ccd746ce9b869a498dfe53590356768b2113aab25e1e01096f93ac9a3d3fb8e3d7ad69291121ee7f573a1a381a230819f300e0603551d0f0101ff0404030206c030130603551d25040c300a06082b06010505070303300c0603551d130101ff04023000301d0603551d0e0416041439de5f87a8f7b62d1810084bf96036c9b9909a3a301f0603551d2304183016801488037fd36cb911edbc4f25a2289f2525bf0ecb3f302a06082b06010505070101041e301c301a06082b06010505073001860e3132372e302e302e313a38383838300a06082a8648ce3d0403020349003046022100c1a8b76077322219213b023fe042a413383ca85e281024c4b8a502001c7b07f4022100c9e7f2f34d158479616088535a8f0b6371bed9c3c1a954232f98e1d7222c950a59020c30820208308201aea00302010202141e5072e85a6b633aa332f87f2d3220963254eea0300a06082a8648ce3d0403023061310b3009060355040613024445311230100603550407130954657374204369747931153013060355040a130c5465737420436f6d70616e793110300e060355040b1307526f6f74204341311530130603550403130c5465737420526f6f742043413020170d3233313031373133313330305a180f32313233303932333133313330305a3061310b3009060355040613024445311230100603550407130954657374204369747931153013060355040a130c5465737420436f6d70616e793110300e060355040b1307526f6f74204341311530130603550403130c5465737420526f6f742043413059301306072a8648ce3d020106082a8648ce3d03010703420004fa8fa8418e82b01256bd494a8328d8a3fe137998524ed364b212b23359bc7817f00b6ba298137fe3c4dfddce6f7758f401f0d8a028974c634d90001e68bba294a3423040300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e0416041488037fd36cb911edbc4f25a2289f2525bf0ecb3f300a06082a8648ce3d0403020348003045022100e652f74f32e788f407ca9c2bbfc4cc4209181ce5005d0c9309076f7ad334ccd30220703fba967faf738a447e8adeea7122e0f454f4b5330d6a11ea9dd14cc8d8a81b5840530d40c226c2e44a65fe9f51d06eb2771f46a2a008c6a3094a6084a744c2207093a44cfbbc5f8876813ec742f994b9856dcab23c0f8da5541d5c577b219da4e8")
)
