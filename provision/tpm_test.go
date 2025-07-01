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

package provision

import (
	"testing"
)

func Test_parseIntelEkCert(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"Success", args{data}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseIntelEkCert(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseIntelEkCert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

var (
	data = []byte(`{"pubhash":"J6GJXWBKxtcujC63BintQ7CO0Xrd52jOyJgOYWCiDeU%3D","certificate":"MIID_jCCA6OgAwIBAgIURBxd_Z9W-PRYdfqWflLmgBIG0QwwCgYIKoZIzj0EAwIwgZoxCzAJBgNVBAYMAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTQwMgYDVQQLDCtUUE0gRUsgaW50ZXJtZWRpYXRlIGZvciBHTEtfRVBJRF9QUk9EIHBpZDo3MRYwFAYDVQQDDA13d3cuaW50ZWwuY29tMB4XDTE5MDMxNDAwMDAwMFoXDTQ5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCMm9yLNegGlE6BftbFFJsbjGDS8yGhnRrm1FH2yjinNSl0xVZ8YjkSdgwUgJBjxjKZ7Jv_1jZP_3XvvgJ97WhmjggJeMIICWjAPBgNVHRMBAf8EBTADAQEAMA4GA1UdDwEB_wQEAwIFIDAQBgNVHSUECTAHBgVngQUIATAkBgNVHQkBAQAEGjAYMBYGBWeBBQIQMQ0wCwwDMi4wAgEAAgFnMFAGA1UdEQEB_wRGMESkQjBAMRYwFAYFZ4EFAgEMC2lkOjQ5NEU1NDQzMQ4wDAYFZ4EFAgIMA0dMSzEWMBQGBWeBBQIDDAtpZDowMDAyMDAwMDAfBgNVHSMEGDAWgBRRxzy838mQqmd0F81feLo31KjXMTBfBgNVHR8EWDBWMFSgUqBQhk5odHRwczovL3RydXN0ZWRzZXJ2aWNlcy5pbnRlbC5jb20vY29udGVudC9DUkwvZWtjZXJ0L0dMS0VQSURQUk9EX0VLX0RldmljZS5jcmwwdwYIKwYBBQUHAQEEazBpMGcGCCsGAQUFBzAChltodHRwczovL3RydXN0ZWRzZXJ2aWNlcy5pbnRlbC5jb20vY29udGVudC9DUkwvZWtjZXJ0L0dMS0VQSURQUk9EX0VLX1BsYXRmb3JtX1B1YmxpY19LZXkuY2VyMIGxBgNVHSAEgakwgaYwgaMGCiqGSIb4TQEFAgEwgZQwWgYIKwYBBQUHAgEWTmh0dHBzOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50L0NSTC9la2NlcnQvRUtjZXJ0UG9saWN5U3RhdGVtZW50LnBkZjA2BggrBgEFBQcCAjAqDChUQ1BBIFRydXN0ZWQgUGxhdGZvcm0gTW9kdWxlIEVuZG9yc2VtZW50MAoGCCqGSM49BAMCA0kAMEYCIQDCh21dXWaB2SyoLPmQsm3b2_RyrOKV2_v9SCHSp4auNgIhAI117kgiqfBgkaueqPZ28_XsbsjYkU3_OGRNOfJOv3cM"}`)
)
