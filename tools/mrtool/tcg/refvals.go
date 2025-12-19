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

package tcg

import (
	"crypto"
	"fmt"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

func CreateExtendRefval(alg crypto.Hash, ta TrustAnchor, idx int, mrDigest, data []byte, subtype, desc string,
) (*ar.ReferenceValue, []byte, error) {

	hash, err := internal.Hash(alg, data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash: %w", err)
	}

	mrDigestNew, err := internal.Extend(alg, mrDigest, hash)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extend: %w", err)
	}

	refval := &ar.ReferenceValue{
		Type:        ta.RefvalString(),
		SubType:     subtype,
		Index:       idx,
		Description: fmt.Sprintf("%v: %v", IndexToMr(ta, idx), desc),
	}

	switch alg {
	case crypto.SHA256:
		refval.Sha256 = hash
	case crypto.SHA384:
		refval.Sha384 = hash
	case crypto.SHA512:
		refval.Sha512 = hash
	default:
		return nil, nil, fmt.Errorf("unsupported hash algorithm %v", alg.String())
	}

	return refval, mrDigestNew, nil
}
