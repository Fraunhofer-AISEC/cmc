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
	"crypto/x509"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/sirupsen/logrus"
)

func Test_verifyIasMeasurements(t *testing.T) {
	type args struct {
		IasM            *Measurement
		nonce           []byte
		referenceValues []ReferenceValue
		ca              *x509.Certificate
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Invalid IAT",
			args: args{
				IasM: &Measurement{
					Type:     "IAS Measurement",
					Evidence: invalidIat,
					Certs:    [][]byte{validIasCert.Raw, validIasCa.Raw},
				},
				nonce: validIasNonce,
				referenceValues: []ReferenceValue{
					validSpeReferenceValue,
					validNspeReferenceValue,
				},
				ca: validIasCa,
			},
			want: false,
		},
		{
			name: "Invalid Cert",
			args: args{
				IasM: &Measurement{
					Type:     "IAS Measurement",
					Evidence: validIat,
					Certs:    [][]byte{invalidIasCert.Raw, validIasCa.Raw},
				},
				nonce: validIasNonce,
				referenceValues: []ReferenceValue{
					validSpeReferenceValue,
					validNspeReferenceValue,
				},
				ca: validIasCa,
			},
			want: false,
		},
		{
			name: "Invalid CA",
			args: args{
				IasM: &Measurement{
					Type:     "IAS Measurement",
					Evidence: validIat,
					Certs:    [][]byte{validIasCert.Raw, validIasCa.Raw},
				},
				nonce: validIasNonce,
				referenceValues: []ReferenceValue{
					validSpeReferenceValue,
					validNspeReferenceValue,
				},
				ca: invalidIasCa,
			},
			want: false,
		},
		{
			name: "Invalid Nonce",
			args: args{
				IasM: &Measurement{
					Type:     "IAS Measurement",
					Evidence: validIat,
					Certs:    [][]byte{validIasCert.Raw, validIasCa.Raw},
				},
				nonce: invalidIasNonce,
				referenceValues: []ReferenceValue{
					validSpeReferenceValue,
					validNspeReferenceValue,
				},
				ca: validIasCa,
			},
			want: false,
		},
		{
			name: "Invalid Reference Value",
			args: args{
				IasM: &Measurement{
					Type:     "IAS Measurement",
					Evidence: validIat,
					Certs:    [][]byte{validIasCert.Raw, validIasCa.Raw},
				},
				nonce: validIasNonce,
				referenceValues: []ReferenceValue{
					invalidSpeReferenceValue,
					validNspeReferenceValue,
				},
				ca: validIasCa,
			},
			want: false,
		},
		{
			name: "Invalid Measurement",
			args: args{
				IasM: &Measurement{
					Type:     "SNP Measurement",
					Evidence: validIat,
					Certs:    [][]byte{validIasCert.Raw, validIasCa.Raw},
				},
				nonce: validIasNonce,
				referenceValues: []ReferenceValue{
					invalidSpeReferenceValue,
					validNspeReferenceValue,
				},
				ca: validIasCa,
			},
			want: false,
		},
	}
	logrus.SetLevel(logrus.TraceLevel)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got := verifyIasMeasurements(*tt.args.IasM, tt.args.nonce, tt.args.referenceValues, []*x509.Certificate{tt.args.ca})
			if got != tt.want {
				t.Errorf("verifyIasMeasurements() error = %v, wantErr %v", got, tt.want)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("verifyIasMeasurements() = %v, want %v", got, tt.want)
			}
		})
	}
}

var (
	validIat, _ = hex.DecodeString("D28443A10126A05901D3AA3A000124FF584000112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF3A000124FB5820A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF3A00012500582101FA58755F658627CE5460F29B75296713248CAE7AD9E2984B90280EFCBCB502483A000124FA5820AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD3A000124F8203A000124F91930003A000124FD82A501635350450465302E302E30055820BFE6D86F8826F4FF97FB96C4E6FBC4993E4619FC565DA26ADF34C329489ADC380666534841323536025820C6C06836E8CD07DEAD305C01EC46A3E264858C47D661E5A257AB81AED87E34F0A501644E5350450465302E302E30055820B360CAF5C98C6B942A4882FA9D4823EFB166A9EF6A6E4AA37C1919ED1FCCC049066653484132353602582073DEB833155C9C317D838B5368B6A63BD38706FA874E874C1B5AFFE4571B348B3A00012501777777772E747275737465646669726D776172652E6F72673A000124F7715053415F494F545F50524F46494C455F313A000124FC7030363034353635323732383239313030584059233E805EE09FFAE3F41462D315A5B095B5E5CB7992F8F1A0FE140C6C842A41EFD211E57F35F182B87E6AB2B0CE1A514C3729D0ACA403C91237568DB77F0B5B")

	invalidIat, _ = hex.DecodeString("D28443A10126A05901D3AA3A000124FF584000112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF3A000124FB5820A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF3A00012500582101FA58755F658627CE5460F29B75296713248CAE7AD9E2984B90280EFCBCB502483A000124FA5820AAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD3A000124F8203A000124F91930003A000124FD82A501635350450465302E302E30055820BFE6D86F8826F4FF97FB96C4E6FBC4993E4619FC565DA26ADF34C329489ADC380666534841323536025820C6C06836E8CD07DEAD305C01EC46A3E264858C47D661E5A257AB81AED87E34F0A501644E5350450465302E302E30055820B360CAF5C98C6B942A4882FA9D4823EFB166A9EF6A6E4AA37C1919ED1FCCC049066653484132353602582073DEB833155C9C317D838B5368B6A63BD38706FA874E874C1B5AFFE4571B348B3A00012501777777772E747275737465646669726D776172652E6F72673A000124F7715053415F494F545F50524F46494C455F313A000124FC7030363034353635323732383239313030584059233E805EE09FFAE3F41462D315A5B095B5E5CB7992F8F1A0FE140C6C842A41EFD211E57F35F182B87E6AB2B0CE1A514C3729D0ACA403C91237568DB77F0B5B")

	validIasNonce, _ = hex.DecodeString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	invalidIasNonce, _ = hex.DecodeString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddee00")

	validIasCert = conv([]byte("-----BEGIN CERTIFICATE-----\nMIICDzCCAbagAwIBAgIUCVN2jieJodotvnOcp2EITdQyCrIwCgYIKoZIzj0EAwIw\nYTELMAkGA1UEBhMCREUxEjAQBgNVBAcTCVRlc3QgQ2l0eTEVMBMGA1UEChMMVGVz\ndCBDb21wYW55MRAwDgYDVQQLEwdSb290IENBMRUwEwYDVQQDEwxUZXN0IFJvb3Qg\nQ0EwHhcNMjIxMTA2MTYwMTAwWhcNMjMxMTA2MTYwMTAwWjAuMQ8wDQYDVQQKEwZM\naW5hcm8xGzAZBgNVBAMTEkRldmljZSBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEG\nCCqGSM49AwEHA0IABHnrqQ6L9FCmdRV2rUWZsHrfk42juwvRfQA27Umi0Pw/v836\niVa1aL/bhnPmSNi1jZKZVbFKJsMIDzQRfZcdaGSjfzB9MA4GA1UdDwEB/wQEAwIF\noDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAd\nBgNVHQ4EFgQUBbkwzYUWT/LvCMVh5dtZP0AycN0wHwYDVR0jBBgwFoAUP4XJy7ck\nBfew1NJEy8AENEN44gIwCgYIKoZIzj0EAwIDRwAwRAIgNPTUtvZ42YaWBSWmNGjA\nijLYO8ncUPjdgNQ0fOGAgzkCIG/OiC5pTdMZkCEGSM+t2lE+LnQ/Az4h4oo1fpPf\nhwsx\n-----END CERTIFICATE-----"))

	invalidIasCert = conv([]byte("-----BEGIN CERTIFICATE-----\nMIIDVDCCAtqgAwIBAgIBATAKBggqhkjOPQQDAzBpMQswCQYDVQQGEwJERTERMA8G\nA1UEBxMIR2FyY2hpbmcxGTAXBgNVBAoTEEZyYXVuaG9mZXIgQUlTRUMxFTATBgNV\nBAsTDERldmljZSBTdWJDQTEVMBMGA1UEAxMMRGV2aWNlIFN1YkNBMB4XDTIyMDUw\nNDE3NDE0NFoXDTIyMTAzMTE3NDE0NFowgbAxCzAJBgNVBAYTAkRFMQswCQYDVQQI\nEwJCWTEPMA0GA1UEBxMGTXVuaWNoMR4wHAYDVQQJExVMaWNodGVuYmVyZ3N0cmFz\nc2UgMTExDjAMBgNVBBETBTg1NzQ4MRkwFwYDVQQKExBGcmF1bmhvZmVyIEFJU0VD\nMQ8wDQYDVQQLEwZkZXZpY2UxJzAlBgNVBAMTHmRlLmZoZy5haXNlYy5pZHMuYWsu\nY29ubmVjdG9yMDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALLkGMKG\nTwN5l8STOeoaEppeyQrkBMnkd+z5292EatVKRcHc4YZ/2ymTVsN9wnufcyqVXTH9\nGZNU3FG2+BQ0WzWIOZoh++f2FyVW6pfkCmYaOhtfzJDnL5tOhAi9tSb9KADn0gXi\ntIQJ4LTTimK8diEQEMO36kc7V2rnIbAp6XsldhdfzDq/x21SdDzz7tgmGqRKfW6J\n0WnU4lsswOXsaA1nfpntkqBAEetIPyWHNTCiuR8nsTodO2iB4kFFRpq8uy0vRjv3\nFUdmw4t9hLj89SjVLYOQtPu7HE+GBA0/MMj2PS0iUP9qgROjbl660RjZzcGP8jwm\nEtKOJKIMCV9dpPECAwEAAaNgMF4wDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQC\nMAAwHQYDVR0OBBYEFICgXN+UT2N8E8sKBTpW1HL8lP4xMB8GA1UdIwQYMBaAFKL4\neCZP53Ov1EG4/cSt3w6unKVLMAoGCCqGSM49BAMDA2gAMGUCMQCjYNPMbOWUuXjj\nFVeTjX8R9oBlnDs+vib7jRxXxKsP6YXugz1ljPBmH0UJYl4AJSUCMA+amGNqs2b0\n84xW/a/CbCzpIbfO+c7iclWaWv+y//CQzS9XncOBQZyG54/wFmKxJw==\n-----END CERTIFICATE-----\n"))

	validIasCa = conv([]byte("-----BEGIN CERTIFICATE-----\nMIICBjCCAaygAwIBAgIUbzIW+iUiIFmCWbOL4rW4UBQfj7AwCgYIKoZIzj0EAwIw\nYTELMAkGA1UEBhMCREUxEjAQBgNVBAcTCVRlc3QgQ2l0eTEVMBMGA1UEChMMVGVz\ndCBDb21wYW55MRAwDgYDVQQLEwdSb290IENBMRUwEwYDVQQDEwxUZXN0IFJvb3Qg\nQ0EwHhcNMjIxMDIzMTcwMTAwWhcNMjcxMDIyMTcwMTAwWjBhMQswCQYDVQQGEwJE\nRTESMBAGA1UEBxMJVGVzdCBDaXR5MRUwEwYDVQQKEwxUZXN0IENvbXBhbnkxEDAO\nBgNVBAsTB1Jvb3QgQ0ExFTATBgNVBAMTDFRlc3QgUm9vdCBDQTBZMBMGByqGSM49\nAgEGCCqGSM49AwEHA0IABEqaNo91iTSSbc9BL1iIQIVpZLd88RL5LfH15SVugJy4\n3d0jeE+KHtpQA8FpAvxXQHJm31z5V6+oLG4MQfVHN/GjQjBAMA4GA1UdDwEB/wQE\nAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQ/hcnLtyQF97DU0kTLwAQ0\nQ3jiAjAKBggqhkjOPQQDAgNIADBFAiAFsmaZDBu+cfOqX9a5YAOgSeYB4Sb+r18m\nBIcuxwthhgIhALRHfA32ZcOA6piTKtWLZsdsG6CH50KGImHlkj4TwfXw\n-----END CERTIFICATE-----"))

	invalidIasCa = conv([]byte("-----BEGIN CERTIFICATE-----\nMIICSDCCAc2gAwIBAgIUHxAyr1Y3QlrYutGU317Uy5FhdpQwCgYIKoZIzj0EAwMw\nYzELMAkGA1UEBhMCREUxETAPBgNVBAcTCEdhcmNoaW5nMRkwFwYDVQQKExBGcmF1\nbmhvZmVyIEFJU0VDMRAwDgYDVQQLEwdSb290IENBMRQwEgYDVQQDEwtJRFMgUm9v\ndCBDQTAeFw0yMjA0MDQxNTE3MDBaFw0yNzA0MDMxNTE3MDBaMGMxCzAJBgNVBAYT\nAkRFMREwDwYDVQQHEwhHYXJjaGluZzEZMBcGA1UEChMQRnJhdW5ob2ZlciBBSVNF\nQzEQMA4GA1UECxMHUm9vdCBDQTEUMBIGA1UEAxMLSURTIFJvb3QgQ0EwdjAQBgcq\nhkjOPQIBBgUrgQQAIgNiAAQSneAVxZRShdfwEu3HtCcwRnV5b4UtOnxJaVZ/bILS\n4dThZVWpXNm+ikvp6Sk0RlI30mKl2X7fX8aRew+HvvFT08xJw9dGAkm2Fsp+4/c7\nM3rMhiHXyCpu/Xg4OlxAYOajQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E\nBTADAQH/MB0GA1UdDgQWBBTyFTqqlt0/YxJBiCB3WM7lkpqWVjAKBggqhkjOPQQD\nAwNpADBmAjEAizrjlmYQmrMbsEaGaFzouMT02iMu0NLILhm1wkfAl3UUWymcliy8\nf1IAI1nO4448AjEAkd74w4WEaTqvslmkPktxNhDA1cVL55LDLbUNXLcSdzr2UBhp\nK8Vv1j4nATtg1Vkf\n-----END CERTIFICATE-----\n"))

	validSpeMeasurement, _ = hex.DecodeString("c6c06836e8cd07dead305c01ec46a3e264858c47d661e5a257ab81aed87e34f0")

	invalidSpeMeasurement, _ = hex.DecodeString("00c06836e8cd07dead305c01ec46a3e264858c47d661e5a257ab81aed87e34f0")

	validNspeMeasurement, _ = hex.DecodeString("73deb833155c9c317d838b5368b6a63bd38706fa874e874c1b5affe4571b348b")

	validSpeReferenceValue = ReferenceValue{
		Type:   "IAS Reference Value",
		Name:   "SPE Measurement",
		Sha256: validSpeMeasurement,
	}

	invalidSpeReferenceValue = ReferenceValue{
		Type:   "IAS Reference Value",
		Name:   "SPE Measurement",
		Sha256: invalidSpeMeasurement,
	}

	validNspeReferenceValue = ReferenceValue{
		Type:   "IAS Reference Value",
		Name:   "NSPE Measurement",
		Sha256: validNspeMeasurement,
	}
)
