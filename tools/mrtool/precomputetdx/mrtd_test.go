// Copyright (c) 2025 Fraunhofer AISEC
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

package precomputetdx

import "testing"

func Test_getQemuVersionMajor(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		version string
		want    int
		wantErr bool
	}{
		{
			name:    "Success",
			version: "8.2.2",
			want:    8,
			wantErr: false,
		},
		{
			name:    "Fail",
			version: "x.2.2",
			want:    0,
			wantErr: true,
		},
		{
			name:    "Fail Empty",
			version: "",
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := getQemuVersionMajor(tt.version)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("getQemuVersionMajor() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("getQemuVersionMajor() succeeded unexpectedly")
			}
			if got != tt.want {
				t.Errorf("getQemuVersionMajor() = %v, want %v", got, tt.want)
			}
		})
	}
}
