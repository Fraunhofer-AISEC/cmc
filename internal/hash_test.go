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
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

func TestHashFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    crypto.Hash
		wantErr bool
	}{
		{"SHA256 no dash", "SHA256", crypto.SHA256, false},
		{"SHA-256 with dash", "SHA-256", crypto.SHA256, false},
		{"sha256 lowercase", "sha256", crypto.SHA256, false},
		{"SHA384 no dash", "SHA384", crypto.SHA384, false},
		{"SHA-384 with dash", "SHA-384", crypto.SHA384, false},
		{"SHA512 no dash", "SHA512", crypto.SHA512, false},
		{"SHA-512 with dash", "SHA-512", crypto.SHA512, false},
		{"SHA1", "SHA1", crypto.SHA1, false},
		{"SHA-1", "SHA-1", crypto.SHA1, false},
		{"SHA3-256", "SHA3-256", crypto.SHA3_256, false},
		{"SHA3-384", "SHA3-384", crypto.SHA3_384, false},
		{"SHA3-512", "SHA3-512", crypto.SHA3_512, false},
		{"SHA-512/224", "SHA-512/224", crypto.SHA512_224, false},
		{"SHA-512/256", "SHA-512/256", crypto.SHA512_256, false},
		{"BLAKE2s-256", "BLAKE2s-256", crypto.BLAKE2s_256, false},
		{"BLAKE2b-256", "BLAKE2b-256", crypto.BLAKE2b_256, false},
		{"MD5", "MD5", crypto.MD5, false},
		{"RIPEMD-160", "RIPEMD-160", crypto.RIPEMD160, false},
		{"empty string", "", 0, true},
		{"unknown", "UNKNOWN", 0, true},
		{"AES not a hash", "AES", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HashFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashFromString(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("HashFromString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestHash(t *testing.T) {
	data := []byte("hello world")
	expected := sha256.Sum256(data)

	got, err := Hash(crypto.SHA256, data)
	if err != nil {
		t.Fatalf("Hash(SHA256) unexpected error: %v", err)
	}
	if !bytes.Equal(got, expected[:]) {
		t.Errorf("Hash(SHA256) = %x, want %x", got, expected[:])
	}

	// Empty data should still hash successfully
	emptyExpected := sha256.Sum256(nil)
	got, err = Hash(crypto.SHA256, nil)
	if err != nil {
		t.Fatalf("Hash(SHA256, nil) unexpected error: %v", err)
	}
	if !bytes.Equal(got, emptyExpected[:]) {
		t.Errorf("Hash(SHA256, nil) = %x, want %x", got, emptyExpected[:])
	}

	// Unavailable algorithm
	_, err = Hash(crypto.Hash(0), data)
	if err == nil {
		t.Error("Hash with unavailable algorithm should return error")
	}
}

func TestExtend(t *testing.T) {
	digest := make([]byte, 32)
	data := []byte("test data")

	got, err := Extend(crypto.SHA256, digest, data)
	if err != nil {
		t.Fatalf("Extend(SHA256) unexpected error: %v", err)
	}

	// Verify consistency with ExtendSha256
	want := ExtendSha256(digest, data)
	if !bytes.Equal(got, want) {
		t.Errorf("Extend(SHA256) = %x, want %x (from ExtendSha256)", got, want)
	}

	// Unavailable algorithm
	_, err = Extend(crypto.Hash(0), digest, data)
	if err == nil {
		t.Error("Extend with unavailable algorithm should return error")
	}
}

func TestExtendSha256(t *testing.T) {
	zeroes := make([]byte, 32)
	data := []byte("extend me")

	result := ExtendSha256(zeroes, data)
	if len(result) != 32 {
		t.Fatalf("ExtendSha256 returned %d bytes, want 32", len(result))
	}

	// Manually verify: SHA256(zeroes || data)
	concat := append(zeroes, data...)
	expected := sha256.Sum256(concat)
	if !bytes.Equal(result, expected[:]) {
		t.Errorf("ExtendSha256 = %x, want %x", result, expected[:])
	}

	// Extending with different data should produce different result
	result2 := ExtendSha256(zeroes, []byte("different"))
	if bytes.Equal(result, result2) {
		t.Error("ExtendSha256 with different data should produce different results")
	}
}

func TestExtendSha384(t *testing.T) {
	zeroes := make([]byte, 48)
	data := []byte("extend me")

	result := ExtendSha384(zeroes, data)
	if len(result) != 48 {
		t.Fatalf("ExtendSha384 returned %d bytes, want 48", len(result))
	}

	// Manually verify: SHA384(zeroes || data)
	concat := append(zeroes, data...)
	expected := sha512.Sum384(concat)
	if !bytes.Equal(result, expected[:]) {
		t.Errorf("ExtendSha384 = %x, want %x", result, expected[:])
	}
}
