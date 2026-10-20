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

package tcg

import (
	"testing"
)

func TestChainloaded(t *testing.T) {
	bootloaders := []string{"systemd-bootx64.efi"}

	tests := []struct {
		name string
		conf Conf
		want bool
	}{
		{"Chainloaded", Conf{Kernel: "linux", Bootloaders: bootloaders}, true},
		{"Direct Kernel Boot", Conf{Kernel: "bzImage"}, false},
		{"Unified Kernel Image", Conf{Bootloaders: bootloaders}, false},
		{"Nothing Specified", Conf{}, false},
		{
			"Override Direct",
			Conf{Kernel: "linux", Bootloaders: bootloaders, LoadOptions: LoadOptionsDirect},
			false,
		},
		{
			"Override Chainloaded",
			Conf{Kernel: "bzImage", LoadOptions: LoadOptionsChainloaded},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.conf.Chainloaded(); got != tt.want {
				t.Errorf("Chainloaded() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseHexUint64(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		s       string
		want    uint64
		wantErr bool
	}{
		{"Success Upper Case", "0X5a7", 0x5a7, false},
		{"Success Lower Case", "0x5a7", 0x5a7, false},
		{"Success No 0x", "5a7", 0x5a7, false},
		{"Fail Invalid Input", "0z5a7", 0, true},
		{"Fail Input Too Large", "0x0123456789abcdef0123", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := parseHexUint64(tt.s)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("parseHexUint64() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("parseHexUint64() succeeded unexpectedly")
			}
			if got != tt.want {
				t.Errorf("parseHexUint64() = %v, want %v", got, tt.want)
			}
		})
	}
}
