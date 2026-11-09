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

package internal

import "testing"

func TestParseApiEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		wantApi  string
		wantAddr string
		wantErr  bool
	}{
		{"unix socket", "socket:///run/cmc/cmc.sock", "socket", "/run/cmc/cmc.sock", false},
		{"tcp socket", "socket://127.0.0.1:9955", "socket", "127.0.0.1:9955", false},
		{"grpc", "grpc://127.0.0.1:9955", "grpc", "127.0.0.1:9955", false},
		{"uppercase api", "GRPC://127.0.0.1:9955", "grpc", "127.0.0.1:9955", false},
		{"explicit network", "socket://unix:///run/cmc.sock", "socket", "unix:///run/cmc.sock", false},
		{"libapi", "libapi", "libapi", "", false},
		{"libapi with separator", "libapi://", "libapi", "", false},
		{"surrounding spaces", " grpc://127.0.0.1:9955 ", "grpc", "127.0.0.1:9955", false},
		{"empty", "", "", "", true},
		{"missing api", "://127.0.0.1:9955", "", "", true},
		{"address only", "127.0.0.1:9955", "", "", true},
		{"path only", "/run/cmc/cmc.sock", "", "", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api, addr, err := ParseApiEndpoint(test.endpoint)
			if (err != nil) != test.wantErr {
				t.Fatalf("ParseApiEndpoint(%q) error = %v, wantErr %v", test.endpoint, err,
					test.wantErr)
			}
			if err != nil {
				return
			}
			if api != test.wantApi || addr != test.wantAddr {
				t.Errorf("ParseApiEndpoint(%q) = (%q, %q), want (%q, %q)", test.endpoint, api,
					addr, test.wantApi, test.wantAddr)
			}
		})
	}
}

func TestParseModeAddr(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantMode string
		wantAddr string
	}{
		{"mode only", "direct", "direct", ""},
		{"est with url", "est:https://localhost:9000", "est", "https://localhost:9000"},
		{"cps with host and port", "cps:localhost:8081", "cps", "localhost:8081"},
		{"uppercase mode", "EST:https://localhost:9000", "est", "https://localhost:9000"},
		{"trailing colon", "est:", "est", ""},
		{"empty", "", "", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mode, addr := ParseModeAddr(test.input)
			if mode != test.wantMode || addr != test.wantAddr {
				t.Errorf("ParseModeAddr(%q) = (%q, %q), want (%q, %q)", test.input, mode, addr,
					test.wantMode, test.wantAddr)
			}
		})
	}
}
