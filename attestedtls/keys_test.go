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

package attestedtls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"

	"github.com/Fraunhofer-AISEC/cmc/api"
)

func TestMatchesKeyConfig(t *testing.T) {
	cert := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "host"},
		DNSNames:    []string{"a.example", "b.example"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("::1")},
	}

	tests := []struct {
		name    string
		kc      api.TLSKeyConfig
		wantErr bool
	}{
		{"match", api.TLSKeyConfig{Cn: "host", DNSNames: []string{"a.example", "b.example"},
			IPAddresses: []string{"10.0.0.1", "::1"}}, false},
		{"match unordered", api.TLSKeyConfig{Cn: "host", DNSNames: []string{"b.example", "a.example"},
			IPAddresses: []string{"0:0:0:0:0:0:0:1", "10.0.0.1"}}, false},
		{"cn changed", api.TLSKeyConfig{Cn: "other", DNSNames: []string{"a.example", "b.example"},
			IPAddresses: []string{"10.0.0.1", "::1"}}, true},
		{"dns changed", api.TLSKeyConfig{Cn: "host", DNSNames: []string{"a.example"},
			IPAddresses: []string{"10.0.0.1", "::1"}}, true},
		{"ip changed", api.TLSKeyConfig{Cn: "host", DNSNames: []string{"a.example", "b.example"},
			IPAddresses: []string{"10.0.0.2", "::1"}}, true},
		{"ip removed", api.TLSKeyConfig{Cn: "host", DNSNames: []string{"a.example", "b.example"}}, true},
		{"invalid ip", api.TLSKeyConfig{Cn: "host", DNSNames: []string{"a.example", "b.example"},
			IPAddresses: []string{"invalid"}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := matchesKeyConfig(cert, tt.kc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("matchesKeyConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
