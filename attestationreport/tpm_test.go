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
	"reflect"
	"testing"
)

var (
	validQuote = "ff54434780180022000bf340a1bdf8e802edef4d9a61f2b001d53def584a5b49b5d186e5cc5655445fd600085db48f3e33c9792a0000000004433c1bdbb7488e58a0415901ac24e803dae6440600000001000b030000060020a27bd934bc103d872e21df8329ef76a9cb7050b59c8762395de1f0a0385bfd79"

	validSignature = "0014000b0100740e077a77ff6ac21754d036f751f5f8ec5ec59448aab05bb5fd2b5d81df58bde3550d855ecf16cd25e36b5688122cfaac1a86ab94954b81d49a1b7fc7648ad26b8b808ce846fe7fd49355d2461d049904e97aa687749d55510f09b7c8610b95b6d557ebdaa25a19bfa1663f236419a1a8d974dd05b14de7f28fbce0a54c3ac428a9cf7f0752cc290580ff8d63e33050c0f53582ae24fe4d30792da71d5ef93581e3371147ed4732a0c0c0461489b1b64b1f28dd5153dbc674f04a21e279833433eabec1642cd386fdca6e52b583b2c914ebcd3c7a334214dc5e7c02880b033e321cb261ed6044785e70599d269511f83a20ee45034f0803d623763d461ce763"

	invalidSignature = "0014000b0100740e077a77ff6ac21754d036f751f5f8ec5ec59448aab05bb5fd2b5d81df58bde3550d855ecf16cd25e36b5688122cfaac1a86ab94954b81d49a1b7fc7648ad26b8b808ce846fe7fd49355d2461d049904e97aa687749d55510f09b7c8610b95b6d557ebdaa25a19bfa1663f236419a1a8da74dd05b14de7f28fbce0a54c3ac428a9cf7f0752cc290580ff8d63e33050c0f53582ae24fe4d30792da71d5ef93581e3371147ed4732a0c0c0461489b1b64b1f28dd5153dbc674f04a21e279833433eabec1642cd386fdca6e52b583b2c914ebcd3c7a334214dc5e7c02880b033e321cb261ed6044785e70599d269511f83a20ee45034f0803d623763d461ce763"

	validHashChain = []*HashChainElem{
		{
			Type:   "Hash Chain",
			Pcr:    17,
			Sha256: []string{"1a814d03d22568e2d669595dd8be199fd7b3df2acb8caae38e24e92605e15c80"},
		},
		{
			Type:   "Hash Chain",
			Pcr:    18,
			Sha256: []string{"1fe8f1a49cf178748a6f6167473bca3cf882ff70b4b4e458e2421c871c9c5bb9"},
		},
	}

	invalidHashChain = []*HashChainElem{
		{
			Type:   "Hash Chain",
			Pcr:    17,
			Sha256: []string{"2a814d03d22568e2d669595dd8be199fd7b3df2acb8caae38e24e92605e15c80"},
		},
		{
			Type:   "Hash Chain",
			Pcr:    18,
			Sha256: []string{"1fe8f1a49cf178748a6f6167473bca3cf882ff70b4b4e458e2421c871c9c5bb9"},
		},
	}

	validTpmNonce = []byte{0x5d, 0xb4, 0x8f, 0x3e, 0x33, 0xc9, 0x79, 0x2a}

	invalidTpmNonce = []byte{0x6d, 0xb4, 0x8f, 0x3e, 0x33, 0xc9, 0x79, 0x2a}

	validAk = "-----BEGIN CERTIFICATE-----\nMIIDVDCCAtqgAwIBAgIBATAKBggqhkjOPQQDAzBpMQswCQYDVQQGEwJERTERMA8G\nA1UEBxMIR2FyY2hpbmcxGTAXBgNVBAoTEEZyYXVuaG9mZXIgQUlTRUMxFTATBgNV\nBAsTDERldmljZSBTdWJDQTEVMBMGA1UEAxMMRGV2aWNlIFN1YkNBMB4XDTIyMDUw\nNDE3NDE0NFoXDTIyMTAzMTE3NDE0NFowgbAxCzAJBgNVBAYTAkRFMQswCQYDVQQI\nEwJCWTEPMA0GA1UEBxMGTXVuaWNoMR4wHAYDVQQJExVMaWNodGVuYmVyZ3N0cmFz\nc2UgMTExDjAMBgNVBBETBTg1NzQ4MRkwFwYDVQQKExBGcmF1bmhvZmVyIEFJU0VD\nMQ8wDQYDVQQLEwZkZXZpY2UxJzAlBgNVBAMTHmRlLmZoZy5haXNlYy5pZHMuYWsu\nY29ubmVjdG9yMDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALLkGMKG\nTwN5l8STOeoaEppeyQrkBMnkd+z5292EatVKRcHc4YZ/2ymTVsN9wnufcyqVXTH9\nGZNU3FG2+BQ0WzWIOZoh++f2FyVW6pfkCmYaOhtfzJDnL5tOhAi9tSb9KADn0gXi\ntIQJ4LTTimK8diEQEMO36kc7V2rnIbAp6XsldhdfzDq/x21SdDzz7tgmGqRKfW6J\n0WnU4lsswOXsaA1nfpntkqBAEetIPyWHNTCiuR8nsTodO2iB4kFFRpq8uy0vRjv3\nFUdmw4t9hLj89SjVLYOQtPu7HE+GBA0/MMj2PS0iUP9qgROjbl660RjZzcGP8jwm\nEtKOJKIMCV9dpPECAwEAAaNgMF4wDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQC\nMAAwHQYDVR0OBBYEFICgXN+UT2N8E8sKBTpW1HL8lP4xMB8GA1UdIwQYMBaAFKL4\neCZP53Ov1EG4/cSt3w6unKVLMAoGCCqGSM49BAMDA2gAMGUCMQCjYNPMbOWUuXjj\nFVeTjX8R9oBlnDs+vib7jRxXxKsP6YXugz1ljPBmH0UJYl4AJSUCMA+amGNqs2b0\n84xW/a/CbCzpIbfO+c7iclWaWv+y//CQzS9XncOBQZyG54/wFmKxJw==\n-----END CERTIFICATE-----\n"

	validIntermediate = "-----BEGIN CERTIFICATE-----\nMIICxzCCAk6gAwIBAgIUKJ3Q4qFWJxg082iXRpworGDyGiswCgYIKoZIzj0EAwMw\nYzELMAkGA1UEBhMCREUxETAPBgNVBAcTCEdhcmNoaW5nMRkwFwYDVQQKExBGcmF1\nbmhvZmVyIEFJU0VDMRAwDgYDVQQLEwdSb290IENBMRQwEgYDVQQDEwtJRFMgUm9v\ndCBDQTAeFw0yMjA0MDQxNTE3MDBaFw0yNzA0MDQyMTE3MDBaMGkxCzAJBgNVBAYT\nAkRFMREwDwYDVQQHEwhHYXJjaGluZzEZMBcGA1UEChMQRnJhdW5ob2ZlciBBSVNF\nQzEVMBMGA1UECxMMRGV2aWNlIFN1YkNBMRUwEwYDVQQDEwxEZXZpY2UgU3ViQ0Ew\ndjAQBgcqhkjOPQIBBgUrgQQAIgNiAASKwF7CxuBrmrOgWbDEU86t8/V3GPPNWkJ/\nt7uKO958kWXJ+CPMsco+X5aay5mWaYvYDd+GlAuP/sbPaRzy5c/CWvCVTOQ1kryk\nk7PwvLsxsQUoL7RPb9UUmrCFtjX37xSjgbwwgbkwDgYDVR0PAQH/BAQDAgGGMCcG\nA1UdJQQgMB4GCCsGAQUFBwMJBggrBgEFBQcDAgYIKwYBBQUHAwEwEgYDVR0TAQH/\nBAgwBgEB/wIBADAdBgNVHQ4EFgQUovh4Jk/nc6/UQbj9xK3fDq6cpUswHwYDVR0j\nBBgwFoAU8hU6qpbdP2MSQYggd1jO5ZKallYwKgYIKwYBBQUHAQEEHjAcMBoGCCsG\nAQUFBzABhg4xMjcuMC4wLjE6ODg4NzAKBggqhkjOPQQDAwNnADBkAjBV8xyxk9N6\nzEK4fdOsGtgIgFUeIAh26DdMEhEiB+oosbAqRGjvZfLbgBX8qQXWZdYCMFgtTChU\nxZn6cplAJma23FAkHu1AZNu9snmXc25PvjVrGBJQWwETNVwdtvkal+Fq0g==\n-----END CERTIFICATE-----\n"

	validCa = "-----BEGIN CERTIFICATE-----\nMIICSDCCAc2gAwIBAgIUHxAyr1Y3QlrYutGU317Uy5FhdpQwCgYIKoZIzj0EAwMw\nYzELMAkGA1UEBhMCREUxETAPBgNVBAcTCEdhcmNoaW5nMRkwFwYDVQQKExBGcmF1\nbmhvZmVyIEFJU0VDMRAwDgYDVQQLEwdSb290IENBMRQwEgYDVQQDEwtJRFMgUm9v\ndCBDQTAeFw0yMjA0MDQxNTE3MDBaFw0yNzA0MDMxNTE3MDBaMGMxCzAJBgNVBAYT\nAkRFMREwDwYDVQQHEwhHYXJjaGluZzEZMBcGA1UEChMQRnJhdW5ob2ZlciBBSVNF\nQzEQMA4GA1UECxMHUm9vdCBDQTEUMBIGA1UEAxMLSURTIFJvb3QgQ0EwdjAQBgcq\nhkjOPQIBBgUrgQQAIgNiAAQSneAVxZRShdfwEu3HtCcwRnV5b4UtOnxJaVZ/bILS\n4dThZVWpXNm+ikvp6Sk0RlI30mKl2X7fX8aRew+HvvFT08xJw9dGAkm2Fsp+4/c7\nM3rMhiHXyCpu/Xg4OlxAYOajQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E\nBTADAQH/MB0GA1UdDgQWBBTyFTqqlt0/YxJBiCB3WM7lkpqWVjAKBggqhkjOPQQD\nAwNpADBmAjEAizrjlmYQmrMbsEaGaFzouMT02iMu0NLILhm1wkfAl3UUWymcliy8\nf1IAI1nO4448AjEAkd74w4WEaTqvslmkPktxNhDA1cVL55LDLbUNXLcSdzr2UBhp\nK8Vv1j4nATtg1Vkf\n-----END CERTIFICATE-----\n"

	validTpmCertChain = CertChain{
		Leaf:          []byte(validAk),
		Intermediates: [][]byte{[]byte(validIntermediate)},
		Ca:            []byte(validCa),
	}

	pcrs = [23]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}

	validVerifications = []Verification{
		{
			Type:   "TPM Verification",
			Sha256: "0310b2b63dc1222516e5c12cedc1cc48e338f85430849b5a5b5256467e2cd0f0",
			Name:   "SINIT ACM Digest",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "b1a7fdf8c2bc04902c73104dbd362cbe45fe41d7110d0ef209bbbb94bef2f243",
			Name:   "BIOS ACM Registration Data",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
			Name:   "SRTM Status",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "fb5e512425fc9449316ec95969ebe71e2d576dbab833d61e2a5b9330fd70ee02",
			Name:   "Launch Control Policy Control Digest",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
			Name:   "LCP Details Digest",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
			Name:   "STM Digest",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "5a3e80a37915b1601c363acd1601df7ef257d5d32c664004a2ec0484a4f60628",
			Name:   "OS SINIT Data Capabilities Field Digest",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "e21a507b6e8831ddef5db74a130d6b2e943cae55e0c9a5471d15d41976e0418f",
			Name:   "MLE Hash",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "a2b69438999767b0c3479a9fcc28ce2442b8d0357d95dca3ad1f74a887622497",
			Name:   "TPM NV Index Digest",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "3b5f9781c4347f5d3af1daf7019654dc05d1af857a598c18f3bc77e7b042b37f",
			Name:   "SINIT Public Key Hash",
			Pcr:    &pcrs[18],
		},
		{
			Type:   "TPM Verification",
			Sha256: "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
			Name:   "SRTM Status",
			Pcr:    &pcrs[18],
		},
		{
			Type:   "TPM Verification",
			Sha256: "5a3e80a37915b1601c363acd1601df7ef257d5d32c664004a2ec0484a4f60628",
			Name:   "OS SINIT Data Capabilities Field Digest",
			Pcr:    &pcrs[18],
		},
		{
			Type:   "TPM Verification",
			Sha256: "fb5e512425fc9449316ec95969ebe71e2d576dbab833d61e2a5b9330fd70ee02",
			Name:   "Launch Control Policy Control Digest",
			Pcr:    &pcrs[18],
		},
		{
			Type:   "TPM Verification",
			Sha256: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
			Name:   "LCP Authorities Digest",
			Pcr:    &pcrs[18],
		},
		{
			Type:   "TPM Verification",
			Sha256: "a2b69438999767b0c3479a9fcc28ce2442b8d0357d95dca3ad1f74a887622497",
			Name:   "TPM NV Index Digest",
			Pcr:    &pcrs[18],
		},
		{
			Type:   "TPM Verification",
			Sha256: "71be5852a14eabefebf0df0e1acc5da291883b6d4c5ab20914ed987c1daf3f91",
			Name:   "TBOOT Unknown",
			Pcr:    &pcrs[18],
		},
		{
			Type:   "TPM Verification",
			Sha256: "71be5852a14eabefebf0df0e1acc5da291883b6d4c5ab20914ed987c1daf3f91",
			Name:   "TBOOT",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "69a26345f8089c7ddf04b3103ddf301ffb45d5a889259b2d0036cc34d826307a",
			Name:   "Kernel Hash",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "32fa96b898e9b5374ac53a05372389d3f432c32338260c52f8d518325ea4797b",
			Name:   "TBOOT",
			Pcr:    &pcrs[17],
		},
	}

	invalidVerifications = []Verification{
		{
			Type:   "TPM Verification",
			Sha256: "1310b2b63dc1222516e5c12cedc1cc48e338f85430849b5a5b5256467e2cd0f0",
			Name:   "SINIT ACM Digest",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "b1a7fdf8c2bc04902c73104dbd362cbe45fe41d7110d0ef209bbbb94bef2f243",
			Name:   "BIOS ACM Registration Data",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
			Name:   "SRTM Status",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "fb5e512425fc9449316ec95969ebe71e2d576dbab833d61e2a5b9330fd70ee02",
			Name:   "Launch Control Policy Control Digest",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
			Name:   "LCP Details Digest",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
			Name:   "STM Digest",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "5a3e80a37915b1601c363acd1601df7ef257d5d32c664004a2ec0484a4f60628",
			Name:   "OS SINIT Data Capabilities Field Digest",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "e21a507b6e8831ddef5db74a130d6b2e943cae55e0c9a5471d15d41976e0418f",
			Name:   "MLE Hash",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "a2b69438999767b0c3479a9fcc28ce2442b8d0357d95dca3ad1f74a887622497",
			Name:   "TPM NV Index Digest",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "3b5f9781c4347f5d3af1daf7019654dc05d1af857a598c18f3bc77e7b042b37f",
			Name:   "SINIT Public Key Hash",
			Pcr:    &pcrs[18],
		},
		{
			Type:   "TPM Verification",
			Sha256: "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
			Name:   "SRTM Status",
			Pcr:    &pcrs[18],
		},
		{
			Type:   "TPM Verification",
			Sha256: "5a3e80a37915b1601c363acd1601df7ef257d5d32c664004a2ec0484a4f60628",
			Name:   "OS SINIT Data Capabilities Field Digest",
			Pcr:    &pcrs[18],
		},
		{
			Type:   "TPM Verification",
			Sha256: "fb5e512425fc9449316ec95969ebe71e2d576dbab833d61e2a5b9330fd70ee02",
			Name:   "Launch Control Policy Control Digest",
			Pcr:    &pcrs[18],
		},
		{
			Type:   "TPM Verification",
			Sha256: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
			Name:   "LCP Authorities Digest",
			Pcr:    &pcrs[18],
		},
		{
			Type:   "TPM Verification",
			Sha256: "a2b69438999767b0c3479a9fcc28ce2442b8d0357d95dca3ad1f74a887622497",
			Name:   "TPM NV Index Digest",
			Pcr:    &pcrs[18],
		},
		{
			Type:   "TPM Verification",
			Sha256: "71be5852a14eabefebf0df0e1acc5da291883b6d4c5ab20914ed987c1daf3f91",
			Name:   "TBOOT Unknown",
			Pcr:    &pcrs[18],
		},
		{
			Type:   "TPM Verification",
			Sha256: "71be5852a14eabefebf0df0e1acc5da291883b6d4c5ab20914ed987c1daf3f91",
			Name:   "TBOOT",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "69a26345f8089c7ddf04b3103ddf301ffb45d5a889259b2d0036cc34d826307a",
			Name:   "Kernel Hash",
			Pcr:    &pcrs[17],
		},
		{
			Type:   "TPM Verification",
			Sha256: "32fa96b898e9b5374ac53a05372389d3f432c32338260c52f8d518325ea4797b",
			Name:   "TBOOT",
			Pcr:    &pcrs[17],
		},
	}

	validResult = Result{
		Success: true,
	}

	validResultMulti = ResultMulti{
		Success: true,
	}

	validSignatureResult = SignatureResult{
		Name:            "de.fhg.aisec.ids.ak.connector0",
		Organization:    []string{"Fraunhofer AISEC"},
		SubjectKeyId:    "80a05cdf944f637c13cb0a053a56d472fc94fe31",
		AuthorityKeyId:  "a2f878264fe773afd441b8fdc4addf0eae9ca54b",
		Signature:       validResult,
		CertCheck:       validResult,
		RoleCheck:       nil,
		ExtensionsCheck: nil,
	}

	validTpmMeasurementResult = TpmMeasurementResult{
		Summary: validResult,
		PcrRecalculation: []PcrResult{
			{
				Pcr:        17,
				Validation: validResultMulti,
			},
			{
				Pcr:        18,
				Validation: validResultMulti,
			},
		},
		AggPcrQuoteMatch:   validResult,
		QuoteFreshness:     validResult,
		QuoteSignature:     validSignatureResult,
		VerificationsCheck: validResultMulti,
	}
)

func Test_verifyTpmMeasurements(t *testing.T) {
	type args struct {
		tpmM          *TpmMeasurement
		nonce         []byte
		verifications []Verification
	}
	tests := []struct {
		name  string
		args  args
		want  *TpmMeasurementResult
		want1 bool
	}{
		{
			name: "Valid TPM Measurement",
			args: args{
				tpmM: &TpmMeasurement{
					Type:      "TPM Measurement",
					Message:   validQuote,
					Signature: validSignature,
					Certs:     validTpmCertChain,
					HashChain: validHashChain,
				},
				nonce:         validTpmNonce,
				verifications: validVerifications,
			},
			want:  &validTpmMeasurementResult,
			want1: true,
		},
		{
			name: "Invalid Nonce",
			args: args{
				tpmM: &TpmMeasurement{
					Type:      "TPM Measurement",
					Message:   validQuote,
					Signature: validSignature,
					Certs:     validTpmCertChain,
					HashChain: validHashChain,
				},
				nonce:         invalidTpmNonce,
				verifications: validVerifications,
			},
			want:  nil,
			want1: false,
		},
		{
			name: "Invalid Signature",
			args: args{
				tpmM: &TpmMeasurement{
					Type:      "TPM Measurement",
					Message:   validQuote,
					Signature: invalidSignature,
					Certs:     validTpmCertChain,
					HashChain: validHashChain,
				},
				nonce:         validTpmNonce,
				verifications: validVerifications,
			},
			want:  nil,
			want1: false,
		},
		{
			name: "Invalid HashChain",
			args: args{
				tpmM: &TpmMeasurement{
					Type:      "TPM Measurement",
					Message:   validQuote,
					Signature: invalidSignature,
					Certs:     validTpmCertChain,
					HashChain: invalidHashChain,
				},
				nonce:         validTpmNonce,
				verifications: validVerifications,
			},
			want:  nil,
			want1: false,
		},
		{
			name: "Invalid Verifications",
			args: args{
				tpmM: &TpmMeasurement{
					Type:      "TPM Measurement",
					Message:   validQuote,
					Signature: invalidSignature,
					Certs:     validTpmCertChain,
					HashChain: validHashChain,
				},
				nonce:         validTpmNonce,
				verifications: invalidVerifications,
			},
			want:  nil,
			want1: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := verifyTpmMeasurements(tt.args.tpmM, tt.args.nonce, tt.args.verifications)
			if got1 != tt.want1 {
				t.Errorf("verifyTpmMeasurements() --GOT1-- = %v, --WANT1-- %v", got1, tt.want1)
			}
			if tt.want != nil && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("verifyTpmMeasurements() \n---GOT = %v\n--WANT = %v", got, tt.want)
			}
		})
	}
}
