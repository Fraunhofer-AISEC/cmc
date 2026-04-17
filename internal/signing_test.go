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

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestAlgFromKeyType(t *testing.T) {
	// Generate test keys
	ecP256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecP521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsa4096, _ := rsa.GenerateKey(rand.Reader, 4096)

	tests := []struct {
		name    string
		key     interface{}
		want    jose.SignatureAlgorithm
		wantErr bool
	}{
		{"ECDSA P-256 pointer", ecP256, jose.ES256, false},
		{"ECDSA P-384 pointer", ecP384, jose.ES384, false},
		{"ECDSA P-521 pointer", ecP521, jose.ES512, false},
		{"ECDSA P-256 value", *ecP256, jose.ES256, false},
		{"ECDSA P-384 value", *ecP384, jose.ES384, false},
		{"ECDSA P-521 value", *ecP521, jose.ES512, false},
		{"RSA-2048 pointer", rsa2048, jose.RS256, false},
		{"RSA-4096 pointer", rsa4096, jose.RS512, false},
		{"RSA-2048 value", *rsa2048, jose.RS256, false},
		{"RSA-4096 value", *rsa4096, jose.RS512, false},
		{"unknown type", "not a key", jose.RS256, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := algFromKeyType(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("algFromKeyType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("algFromKeyType() = %v, want %v", got, tt.want)
			}
		})
	}
}
