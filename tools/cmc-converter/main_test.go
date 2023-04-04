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
	"encoding/hex"
	"reflect"
	"testing"

	log "github.com/sirupsen/logrus"
)

func Test_convert(t *testing.T) {
	type args struct {
		data    []byte
		outform string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"Valid JSON to CBOR", args{jsonData, "cbor"}, cborData, false},
		{"Valid JSON to JSON", args{jsonData, "json"}, jsonData, false},
		{"Valid CBOR to JSON", args{cborData, "json"}, jsonData, false},
		{"Valid CBOR to CBOR", args{cborData, "cbor"}, cborData, false},
		{"Invalid to CBOR", args{invalidData, "cbor"}, nil, true},
		{"Invalid to JSON", args{invalidData, "json"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.Infof("INDATA: %v", string(tt.args.data))
			got, err := convert(tt.args.data, tt.args.outform)
			if (err != nil) != tt.wantErr {
				t.Errorf("convert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			log.Infof("OUTDATA: %v", hex.EncodeToString(got))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convert() = %v, want %v", got, tt.want)
			}
		})
	}
}

var (
	jsonData = []byte(`{"type":"RTM Manifest","name":"test.data.input","developerCommonName":"","version":"","description":"","certificationLevel":0,"validity":{"notBefore":"","notAfter":""},"referenceValues":null}`)

	cborData = []byte{
		0xa8, 0x00, 0x6c, 0x52, 0x54, 0x4d, 0x20, 0x4d, 0x61, 0x6e, 0x69, 0x66,
		0x65, 0x73, 0x74, 0x01, 0x6f, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x64, 0x61,
		0x74, 0x61, 0x2e, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x02, 0x60, 0x03, 0x60,
		0x04, 0x60, 0x05, 0x00, 0x06, 0xa2, 0x00, 0x60, 0x01, 0x60, 0x07, 0xf6,
	}

	invalidData = []byte{0xde, 0xad, 0xbe, 0xef}
)
