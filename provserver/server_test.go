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

package main

import (
	"encoding/pem"
	"testing"

	"go-attestation/attest"

	"github.com/google/certificate-transparency-go/x509"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
)

func GetValidEkCert() (*x509.Certificate, error) {
	ekpem := []byte("-----BEGIN CERTIFICATE-----\nMIIEjTCCA3WgAwIBAgIUNG2IxQGPQzHhRdRiiRHD7YDLrWgwDQYJKoZIhvcNAQEL\nBQAwVTELMAkGA1UEBhMCQ0gxHjAcBgNVBAoTFVNUTWljcm9lbGVjdHJvbmljcyBO\nVjEmMCQGA1UEAxMdU1RNIFRQTSBFSyBJbnRlcm1lZGlhdGUgQ0EgMDUwHhcNMTcw\nMjE1MDAwMDAwWhcNMjcwMjE1MDAwMDAwWjAAMIIBIjANBgkqhkiG9w0BAQEFAAOC\nAQ8AMIIBCgKCAQEAxYcw4oWf8kBliXwly0g9zvSO2pOBc+/mqLJQcNvwl1mqd8be\nl3zcclCfg4vdAxxtkczO/J1V4HhYnzjzmq73yIlL+DaZlJ83C03uLuqurNvDi8wA\n6h88aFK7QkWmrJBXHpVBfGcQYiEEKEjSRXsBnDk6Rkkm+S1JDIQmW+PtuUMoDMjw\nLGAdmhVKJ2wjgUqU4lhZFah+tRfqdI2BQvVZ8J45KAbypomk2Ah1WIbwr1jQwT2U\nUmPfo0X1JSn5wjDlgQeZw8fOZ672Xa1YcW4NnWqqFBltTszZAfx3GHPELMP9COlm\nJ9cNAN2vnPr+9aLu6zu5KxoHor4c0oqJ0Ez+OwIDAQABo4IBqDCCAaQwHwYDVR0j\nBBgwFoAUGtuZSrWL5XoMybkA54UeGkPAhmAwQgYDVR0gBDswOTA3BgRVHSAAMC8w\nLQYIKwYBBQUHAgEWIWh0dHA6Ly93d3cuc3QuY29tL1RQTS9yZXBvc2l0b3J5LzBZ\nBgNVHREBAf8ETzBNpEswSTEWMBQGBWeBBQIBDAtpZDo1MzU0NEQyMDEXMBUGBWeB\nBQICDAxTVDMzSFRQeEFIQjYxFjAUBgVngQUCAwwLaWQ6MDA0NzAwMEMwZgYDVR0J\nBF8wXTAWBgVngQUCEDENMAsMAzIuMAIBAAIBdDBDBgVngQUCEjE6MDgCAQABAf+g\nAwoBAaEDCgEAogMKAQCjEDAOFgMzLjEKAQQKAQIBAf+kDzANFgUxNDAtMgoBAQEB\nADAOBgNVHQ8BAf8EBAMCBSAwDAYDVR0TAQH/BAIwADAQBgNVHSUECTAHBgVngQUI\nATBKBggrBgEFBQcBAQQ+MDwwOgYIKwYBBQUHMAKGLmh0dHA6Ly9zZWN1cmUuZ2xv\nYmFsc2lnbi5jb20vc3RtdHBtZWtpbnQwNS5jcnQwDQYJKoZIhvcNAQELBQADggEB\nABUgyYwYHVlqaGAB6GFs70x5jRfSK0UBWGc3prQRGzQEXi0vW5HjgjspJU0N2kD0\nNPygN1HDAXJzPXKV27vBRVf7g+qNXabGYIXFDDW3pDUZB3fH+YoDHK7ktBZCWvVd\nSdJ1LzSdaPYW0NxOavssw3/JtZxNMJd354THWrCsOSL2dqLLgK4vRfG3AeEFSCic\nIJC57xDwEegt8oXDQjqZPKcBCMQyV8j3s6/kCZ8LlO1YrKdBJpnEqJFB+Ih39XTh\naKmptRgctQTdV9BsKoXO0hd0j20acsArpt9OlfRolvIPnFJW24nfHSRVoiAi3eEo\nErNZNleOGz3dzBgcleweEvQ=\n-----END CERTIFICATE-----")
	block, _ := pem.Decode(ekpem)
	ek, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return ek, nil
}

func GetInvalidEkCert() (*x509.Certificate, error) {
	ekpem := []byte("-----BEGIN CERTIFICATE-----\nMIICkjCCAfOgAwIBAgIUCwuA4QQicNpR1kFkWY9G431EBREwCgYIKoZIzj0EAwQw\nYzELMAkGA1UEBhMCREUxETAPBgNVBAcTCEdhcmNoaW5nMRkwFwYDVQQKExBGcmF1\nbmhvZmVyIEFJU0VDMRAwDgYDVQQLEwdSb290IENBMRQwEgYDVQQDEwtJRFMgUm9v\ndCBDQTAeFw0yMTA5MjcxMjAxMDBaFw0yNjA5MjYxMjAxMDBaMGMxCzAJBgNVBAYT\nAkRFMREwDwYDVQQHEwhHYXJjaGluZzEZMBcGA1UEChMQRnJhdW5ob2ZlciBBSVNF\nQzEQMA4GA1UECxMHUm9vdCBDQTEUMBIGA1UEAxMLSURTIFJvb3QgQ0EwgZswEAYH\nKoZIzj0CAQYFK4EEACMDgYYABAD96DF4zgfBGLnuT/QGITPQ0ULl19rv91K7wXbi\nSwnCTZumaxg6uXa7FQHoJ2v4DfSJ9SYdGcIQ/dn5iO54OlzmWQHVGvKRMljjpbjs\nTmm+MRopmjmd2mJThDsBBrPscVQrZRY8P+QeUvS5N388mwXLwYgbTjURD7009kPr\nZkOjmb40ZqNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYD\nVR0OBBYEFFgjQAIzBC69ccSfBdgQM09cvSN+MAoGCCqGSM49BAMEA4GMADCBiAJC\nAPJMDIx/O4Y15d4s59mrKIXksfGv2V7q6NlX2dYY7jazk/NTSc58UG7x3Y45HSqq\ntmdvDTPUOrGGzKMUPKk217CIAkIA0D2PCYKwerxK0XFRhha1IDZIaHu3ohUi+a/D\npj4SSNcD5NemTzdfVUJXzozaoo/HViutPNgD9DrOtILXrdaCZKo=\n-----END CERTIFICATE-----")
	block, _ := pem.Decode(ekpem)
	ek, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return ek, nil
}

func TestVerifyEkCert(t *testing.T) {

	// Preparations: Parse test certificates
	ek, err := GetValidEkCert()
	if err != nil {
		t.Errorf("Preparation Error: ParseCertificate error = %v", err)
		return
	}
	ekInvalid, err := GetInvalidEkCert()
	if err != nil {
		t.Errorf("Preparation Error: ParseCertificate error = %v", err)
		return
	}

	type args struct {
		dbpath  string
		ek      *x509.Certificate
		tpmInfo *attest.TPMInfo
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "Verify EK Cert",
			args: args{
				dbpath: "tpm-ek-certs.db",
				ek:     ek,
				tpmInfo: &attest.TPMInfo{
					Manufacturer:         attest.TCGVendorID(1398033696),
					FirmwareVersionMajor: 71,
				},
			},
			wantErr: false,
		},
		{name: "Verify EK Cert Fail: Invalid EK Cert",
			args: args{
				dbpath: "tpm-ek-certs.db",
				ek:     ekInvalid,
				tpmInfo: &attest.TPMInfo{
					Manufacturer:         attest.TCGVendorID(1398033696),
					FirmwareVersionMajor: 71,
				},
			},
			wantErr: true,
		},
		{name: "Verify EK Cert Fail: Unknown Firmware Major",
			args: args{
				dbpath: "tpm-ek-certs.db",
				ek:     ek,
				tpmInfo: &attest.TPMInfo{
					Manufacturer:         attest.TCGVendorID(1398033696),
					FirmwareVersionMajor: 81,
				},
			},
			wantErr: true,
		},
	}

	log.SetLevel(log.InfoLevel)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyEkCert(tt.args.dbpath, tt.args.ek, tt.args.tpmInfo)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyEkCert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
