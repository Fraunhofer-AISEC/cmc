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
)

// ExtendSha256 performs the extend operation Digest = HASH(Digest | Data) using the
// SHA256 hashing algorithm, as performed e.g. by Trusted Platform Modules (TPMs)
func ExtendSha256(hash []byte, data []byte) []byte {
	concat := append(hash, data...)
	h := sha256.Sum256(concat)
	ret := make([]byte, 32)
	copy(ret, h[:])
	return ret
}

// ExtendSha384 performs the extend operation Digest = HASH(Digest | Data) using the
// SHA384 hashing algorithm, as performed e.g. by Trusted Platform Modules (TPMs)
func ExtendSha384(hash []byte, data []byte) []byte {
	concat := append(hash, data...)
	h := sha512.Sum384(concat)
	ret := make([]byte, 48)
	copy(ret, h[:])
	return ret
}

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
