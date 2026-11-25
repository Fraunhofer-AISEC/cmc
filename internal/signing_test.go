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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/veraison/go-cose"
)

func TestAlgFromPublicKey(t *testing.T) {
	ecP224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	ecP256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecP521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsa3072, _ := rsa.GenerateKey(rand.Reader, 3072)
	rsa4096, _ := rsa.GenerateKey(rand.Reader, 4096)
	ed, _, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name    string
		key     crypto.PublicKey
		jws     jose.SignatureAlgorithm
		jwsErr  bool
		cose    cose.Algorithm
		coseErr bool
	}{
		{"ECDSA P-224", &ecP224.PublicKey, "", true, 0, true},
		{"ECDSA P-256", &ecP256.PublicKey, jose.ES256, false, cose.AlgorithmES256, false},
		{"ECDSA P-384", &ecP384.PublicKey, jose.ES384, false, cose.AlgorithmES384, false},
		{"ECDSA P-521", &ecP521.PublicKey, jose.ES512, false, cose.AlgorithmES512, false},
		{"RSA-1024", &rsa1024.PublicKey, "", true, 0, true},
		{"RSA-2048", &rsa2048.PublicKey, jose.PS256, false, cose.AlgorithmPS256, false},
		{"RSA-3072", &rsa3072.PublicKey, jose.PS384, false, cose.AlgorithmPS384, false},
		{"RSA-4096", &rsa4096.PublicKey, jose.PS512, false, cose.AlgorithmPS512, false},
		{"Ed25519", ed, jose.EdDSA, false, cose.AlgorithmEdDSA, false},
		{"private key", ecP256, "", true, 0, true},
		{"unknown type", "not a key", "", true, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jws, err := JwsAlgFromPublicKey(tt.key)
			if (err != nil) != tt.jwsErr {
				t.Errorf("JwsAlgFromPublicKey() error = %v, wantErr %v", err, tt.jwsErr)
			} else if !tt.jwsErr && jws != tt.jws {
				t.Errorf("JwsAlgFromPublicKey() = %v, want %v", jws, tt.jws)
			}
			c, err := CoseAlgFromPublicKey(tt.key)
			if (err != nil) != tt.coseErr {
				t.Errorf("CoseAlgFromPublicKey() error = %v, wantErr %v", err, tt.coseErr)
			} else if !tt.coseErr && c != tt.cose {
				t.Errorf("CoseAlgFromPublicKey() = %v, want %v", c, tt.cose)
			}
		})
	}
}
