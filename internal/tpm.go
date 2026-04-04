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
	"fmt"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/legacy/tpm2"
)

func CryptoToAttestHash(in crypto.Hash) (attest.HashAlg, error) {
	switch in {
	case crypto.SHA1:
		return attest.HashSHA1, nil
	case crypto.SHA256:
		return attest.HashSHA256, nil
	case crypto.SHA384:
		return attest.HashSHA384, nil
	default:
		return 0, fmt.Errorf("unsupported tpm hash algorithm %v", in.String())
	}
}

func Tpm2ToCryptoHash(in tpm2.Algorithm) (crypto.Hash, error) {
	switch in {
	case tpm2.AlgSHA1:
		return crypto.SHA1, nil
	case tpm2.AlgSHA256:
		return crypto.SHA256, nil
	case tpm2.AlgSHA384:
		return crypto.SHA384, nil
	default:
		return 0, fmt.Errorf("unsupported tpm hash algorithm 0x%x", in)
	}
}

func CryptoToTpm2Hash(in crypto.Hash) (tpm2.Algorithm, error) {
	switch in {
	case crypto.SHA1:
		return tpm2.AlgSHA1, nil
	case crypto.SHA256:
		return tpm2.AlgSHA256, nil
	case crypto.SHA384:
		return tpm2.AlgSHA384, nil
	default:
		return 0, fmt.Errorf("unsupported tpm hash algorithm %s", in.String())
	}
}
