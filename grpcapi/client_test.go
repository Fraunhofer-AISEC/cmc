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

package grpcapi

import "testing"

func TestTarget(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"127.0.0.1:9955", "127.0.0.1:9955"},
		{"tcp://localhost:9955", "localhost:9955"},
		{"/run/cmc/cmc.sock", "unix:/run/cmc/cmc.sock"},
		{"unix:///run/cmc/cmc.sock", "unix:/run/cmc/cmc.sock"},
		{"cmc.sock", "unix:cmc.sock"},
	}
	for _, tt := range tests {
		if got := Target(tt.addr); got != tt.want {
			t.Errorf("Target(%q) = %q, want %q", tt.addr, got, tt.want)
		}
	}
}
