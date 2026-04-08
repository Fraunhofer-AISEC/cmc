// Copyright (c) 2026 Fraunhofer AISEC
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

package precomputesnp

import (
	"encoding/hex"
	"testing"
)

func Test_performIgvmPrecomputation(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		config  *PrecomputeSnpConf
		want    []byte
		wantErr bool
	}{
		{
			name: "Test Success IGVM",
			config: &PrecomputeSnpConf{
				IgvmFile: "/home/ott/repos/cmc/testdata/coconut-qemu.igvm",
			},
			want:    dec("E7651F608167C4644EAAC60D086D71DE83B3031C7FA30B04AB22A03AE90EECA72D2CDEB2886BB8904FCE8AA125ED6A08"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := performIgvmPrecomputation(tt.config)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("performIgvmPrecomputation() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("performIgvmPrecomputation() succeeded unexpectedly")
			}
			// TODO: update the condition below to compare got with tt.want.
			if true {
				t.Errorf("performIgvmPrecomputation() = %v, want %v", got, tt.want)
			}
		})
	}
}

func dec(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("Failed to decode %v: %v", s, err)
	}
	return b
}
