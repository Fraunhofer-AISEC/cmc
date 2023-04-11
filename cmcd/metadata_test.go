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
	"crypto/x509"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sirupsen/logrus"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

func Test_isNewer(t *testing.T) {
	type args struct {
		t   string
		ref string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{"Newer", args{"2023-03-15T23:59:14Z", "2022-12-11T15:19:00Z"}, true, false},
		{"Older", args{"2022-12-11T15:19:00Z", "2023-03-15T23:59:14Z"}, false, false},
		{"Error", args{"xxxxxxxxxxxxxxxxxxx", "2022-12-11T15:19:00Z"}, false, true},
	}
	logrus.SetLevel(logrus.TraceLevel)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := isNewer(tt.args.t, tt.args.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("isNewer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("isNewer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_filterMetadata(t *testing.T) {
	type args struct {
		inlist [][]byte
		s      ar.Serializer
	}
	tests := []struct {
		name    string
		args    args
		want    [][]byte
		wantErr bool
	}{
		{"Filter", args{inlist, MockSerializer{}}, outlist, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := filterMetadata(tt.args.inlist, tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("filterMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filterMetadata() = %v, want %v", got, tt.want)
			}
		})
	}
}

type MockSerializer struct{}

func (s MockSerializer) GetPayload(raw []byte) ([]byte, error) {
	return raw, nil
}
func (s MockSerializer) Marshal(v any) ([]byte, error) {
	return nil, nil
}
func (s MockSerializer) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
func (s MockSerializer) Sign(report []byte, signer ar.Driver) ([]byte, error) {
	return nil, nil
}
func (s MockSerializer) VerifyToken(data []byte, roots []*x509.Certificate) (ar.TokenResult, []byte, bool) {
	return ar.TokenResult{}, nil, false
}

var (
	os1 = []byte(`{"type":"OS Manifest","name":"os1.test","version":"2023-02-02T14:00:00Z"}`)
	os2 = []byte(`{"type":"OS Manifest","name":"os2.test","version":"1999-02-02T14:00:00Z"}`)

	rtm1 = []byte(`{"type":"RTM Manifest","name":"rtm1.test","version":"2023-02-02T14:00:00Z"}`)
	rtm2 = []byte(`{"type":"RTM Manifest","name":"rtm1.test","version":"2023-02-02T15:00:00Z"}`)
	rtm3 = []byte(`{"type":"RTM Manifest","name":"rtm2.test","version":"2023-02-02T16:00:00Z"}`)

	app1 = []byte(`{"type":"App Manifest","name":"app1.test","version":"2023-03-02T14:00:00Z"}`)
	app2 = []byte(`{"type":"App Manifest","name":"app1.test","version":"1999-02-02T14:00:00Z"}`)
	app3 = []byte(`{"type":"App Manifest","name":"app2.test","version":"2023-02-02T16:00:00Z"}`)

	inlist = [][]byte{os1, os2, rtm1, rtm2, rtm3, app1, app2, app3}

	outlist = [][]byte{os1, rtm3, app1, app3}
)
