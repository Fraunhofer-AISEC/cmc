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

package internal

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strings"
)

// HashFromString retrieves the hash algorithm from the specified
// string as defined in https://pkg.go.dev/crypto#Hash.String
func HashFromString(s string) (crypto.Hash, error) {
	switch strings.ToUpper(s) {
	case "MD4":
		return crypto.MD4, nil
	case "MD5":
		return crypto.MD5, nil
	case "SHA1":
		return crypto.SHA1, nil
	case "SHA-1":
		return crypto.SHA1, nil
	case "SHA224":
		return crypto.SHA224, nil
	case "SHA-224":
		return crypto.SHA224, nil
	case "SHA256":
		return crypto.SHA256, nil
	case "SHA-256":
		return crypto.SHA256, nil
	case "SHA384":
		return crypto.SHA384, nil
	case "SHA-384":
		return crypto.SHA384, nil
	case "SHA512":
		return crypto.SHA512, nil
	case "SHA-512":
		return crypto.SHA512, nil
	case "MD5+SHA1":
		return crypto.MD5SHA1, nil
	case "RIPEMD-160":
		return crypto.RIPEMD160, nil
	case "SHA3-224":
		return crypto.SHA3_224, nil
	case "SHA3-256":
		return crypto.SHA3_256, nil
	case "SHA3-384":
		return crypto.SHA3_384, nil
	case "SHA3-512":
		return crypto.SHA3_512, nil
	case "SHA-512/224":
		return crypto.SHA512_224, nil
	case "SHA-512/256":
		return crypto.SHA512_256, nil
	case "BLAKE2s-256":
		return crypto.BLAKE2s_256, nil
	case "BLAKE2b-256":
		return crypto.BLAKE2b_256, nil
	case "BLAKE2b-384":
		return crypto.BLAKE2b_384, nil
	case "BLAKE2b-512":
		return crypto.BLAKE2b_512, nil
	default:
		return 0, fmt.Errorf("unsupported hash %q", s)
	}
}

// Extend performs the extend operation Digest = HASH(Digest | Data) using the
// specified hash algorithm
func Extend(alg crypto.Hash, digest, data []byte) ([]byte, error) {
	if !alg.Available() {
		return nil, fmt.Errorf("hash algorithm not available: %v", alg)
	}

	var h hash.Hash = alg.New()
	if _, err := h.Write(digest); err != nil {
		return nil, fmt.Errorf("hashing failed: %w", err)
	}
	if _, err := h.Write(data); err != nil {
		return nil, fmt.Errorf("hashing failed: %w", err)
	}
	return h.Sum(nil), nil
}

// Hash performs the hash operation using the specified hash algorithm
func Hash(alg crypto.Hash, data []byte) ([]byte, error) {
	if !alg.Available() {
		return nil, fmt.Errorf("hash algorithm not available: %v", alg)
	}

	var h hash.Hash = alg.New()
	if _, err := h.Write(data); err != nil {
		return nil, fmt.Errorf("hashing failed: %w", err)
	}
	return h.Sum(nil), nil
}

// ExtendSha256 performs the extend operation Digest = HASH(Digest | Data) using the
// SHA256 hash algorithm
func ExtendSha256(hash []byte, data []byte) []byte {
	concat := append(hash, data...)
	h := sha256.Sum256(concat)
	ret := make([]byte, 32)
	copy(ret, h[:])
	return ret
}

// ExtendSha384 performs the extend operation Digest = HASH(Digest | Data) using the
// SHA384 hash algorithm
func ExtendSha384(hash []byte, data []byte) []byte {
	concat := append(hash, data...)
	h := sha512.Sum384(concat)
	ret := make([]byte, 48)
	copy(ret, h[:])
	return ret
}
