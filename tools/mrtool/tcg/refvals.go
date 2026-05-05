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

func CreateExtendRefval(alg crypto.Hash, ta TrustAnchor, idx int, mrDigest, data []byte, name, desc string,
) (*ar.Component, []byte, error) {

	hash, err := internal.Hash(alg, data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash: %w", err)
	}

	mrDigestNew, err := internal.Extend(alg, mrDigest, hash)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extend: %w", err)
	}

	component := &ar.Component{
		Type: ar.CycloneDxType(ta.PropertyValue(), idx),
		Name: name,
		Hashes: []ar.ReferenceHash{
			{
				Alg:     alg.String(),
				Content: hash,
			},
		},
		Description: fmt.Sprintf("%v: %v", IndexToMr(ta, idx), desc),
	}
	component.SetTrustAnchor(ta.PropertyValue())
	component.SetIndex(idx)

	return component, mrDigestNew, nil
}
