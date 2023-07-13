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

package cmc

import (
	"testing"

	"github.com/sirupsen/logrus"
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
