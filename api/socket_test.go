// Copyright (c) 2024 Fraunhofer AISEC
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

package api_test

import (
	"testing"

	"github.com/Fraunhofer-AISEC/cmc/api"
)

func TestGetNetworkAndAddr(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		addr  string
		want  string
		want2 string
	}{
		{"TCP ipv4", "127.0.0.1:8080", "tcp", "127.0.0.1:8080"},
		{"TCP ipv6", "[::1]:443", "tcp", "[::1]:443"},
		{"TCP hostname", "localhost:9090", "tcp", "localhost:9090"},
		{"TCP with prefix", "tcp://localhost:9090", "tcp", "localhost:9090"},
		{"Unix socket absolute", "/tmp/cmc.sock", "unix", "/tmp/cmc.sock"},
		{"Unix socket relative", "tmp/cmc.sock", "unix", "tmp/cmc.sock"},
		{"Unix socket absolute with prefix", "unix:///tmp/cmc.sock", "unix", "/tmp/cmc.sock"},
		{"Unix socket relative with prefix", "unix://tmp/cmc.sock", "unix", "tmp/cmc.sock"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got2 := api.GetNetworkAndAddr(tt.addr)
			if got != tt.want {
				t.Errorf("GetNetworkAndAddr() = %v, want %v", got, tt.want)
			}
			if got2 != tt.want2 {
				t.Errorf("GetNetworkAndAddr() = %v, want %v", got2, tt.want2)
			}
		})
	}
}
