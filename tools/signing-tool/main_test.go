// Copyright(c) 2021 Fraunhofer AISEC
// Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the License); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an AS IS BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"testing"
)

func Test_sign(t *testing.T) {
	type args struct {
		data      []byte
		keysPem   [][]byte
		chainsPem [][][]byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"Valid CBOR", args{inputCbor, keys, chains}, false},
		{"Valid JSON", args{inputJson, keys, chains}, false},
		{"Invalid Input", args{inputInvalid, keys, chains}, true},
		{"Invalid Keys", args{inputCbor, keysInvalid, chains}, true},
		{"Invalid Chains", args{inputCbor, keys, chainsInvalid}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sign(tt.args.data, tt.args.keysPem, tt.args.chainsPem)
			if (err != nil) != tt.wantErr {
				t.Errorf("sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

var (
	keys = [][]byte{[]byte("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIJA5wqPq4h11Cr4bIiTbtNlOuYEwDZY0pyewo6hhlTcVoAoGCCqGSM49\nAwEHoUQDQgAE4F/nZUjkntGyH8UoxDi1qFve7KiL3qS2VcqoCDO3cZ6MRGkdhu7l\nJEYifqGTa8CAGKbNRCmL++5jetWP5/5L9Q==\n-----END EC PRIVATE KEY-----")}

	keysInvalid = [][]byte{[]byte("-----BEGIN INVALID-----")}

	chains = [][][]byte{[][]byte{[]byte("-----BEGIN CERTIFICATE-----\nMIICcDCCAfWgAwIBAgIUAyk5VPFa9mbAGlNrf8qpHYcW8SowCgYIKoZIzj0EAwMw\naTELMAkGA1UEBhMCREUxETAPBgNVBAcTCEdhcmNoaW5nMRkwFwYDVQQKExBGcmF1\nbmhvZmVyIEFJU0VDMRMwEQYDVQQLEwpVc2VyIFN1YkNBMRcwFQYDVQQDEw5JRFMg\nVXNlciBTdWJDQTAeFw0yMzAyMTUxNzMxMDBaFw0yNDAyMTUxNzMxMDBaMGUxCzAJ\nBgNVBAYTAkRFMREwDwYDVQQHEwhHYXJjaGluZzEZMBcGA1UEChMQRnJhdW5ob2Zl\nciBBSVNFQzESMBAGA1UECxMJY2VydGlmaWVyMRQwEgYDVQQDDAtjZXJ0aWZpZXJf\nQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOBf52VI5J7Rsh/FKMQ4tahb3uyo\ni96ktlXKqAgzt3GejERpHYbu5SRGIn6hk2vAgBimzUQpi/vuY3rVj+f+S/WjfzB9\nMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw\nDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU5GEr3AuQsISewas0GK0obgCT2a0wHwYD\nVR0jBBgwFoAUkteinNRi4oZGIYV5jyn+br2mbz0wCgYIKoZIzj0EAwMDaQAwZgIx\nAM5lwY+5oTNkYm8Qps79RATe3W4PxyTXhJJjody8XQszP9NyduaGsDfiXtqgSpqT\n+QIxAKc8pNGFpyeJYBFdIdzlPPFHLbaFe916zZWZiId1eZbxzGf0Z/IQ/j+TYNSO\ngmcoLg==\n-----END CERTIFICATE-----")}}

	chainsInvalid = [][][]byte{[][]byte{[]byte("-----BEGIN INVALID-----")}}

	inputJson = []byte(`{"type":"RTM Manifest","name":"test.data.input"}`)

	inputCbor = []byte{
		0xa9, 0x00, 0x72, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x20, 0x44, 0x65,
		0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x01, 0x73, 0x74,
		0x65, 0x73, 0x74, 0x2d, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x74,
		0x65, 0x73, 0x74, 0x2e, 0x64, 0x65, 0x02, 0x78, 0x23, 0x50, 0x6f, 0x43,
		0x20, 0x44, 0x65, 0x6d, 0x6f, 0x6e, 0x73, 0x74, 0x72, 0x61, 0x74, 0x6f,
		0x72, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x20, 0x44, 0x65, 0x73,
		0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x03, 0x6f, 0x4d, 0x75,
		0x6e, 0x69, 0x63, 0x68, 0x2c, 0x20, 0x47, 0x65, 0x72, 0x6d, 0x61, 0x6e,
		0x79, 0x04, 0x6b, 0x64, 0x65, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x72,
		0x74, 0x6d, 0x05, 0x6a, 0x64, 0x65, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x2e,
		0x6f, 0x73, 0x06, 0x80, 0x07, 0xf6, 0x08, 0xf6,
	}

	inputInvalid = []byte{0xde, 0xad, 0xbe, 0xef}
)
