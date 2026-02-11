// Copyright (c) 2021 Fraunhofer AISEC
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

//go:build !nodefaults || socket

package main

import (
	"crypto/rand"
	"fmt"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/keymgr"
)

func Sign(mgr *keymgr.KeyMgr, keyId, hashAlg string, digest []byte) ([]byte, error) {

	key, err := mgr.GetKey(keyId)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	hash, err := internal.HashFromString(hashAlg)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	signature, err := key.Sign(rand.Reader, digest, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, err
}
