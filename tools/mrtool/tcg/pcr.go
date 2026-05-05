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
	"crypto/sha256"
	"fmt"
	"sort"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

func PrecomputeFinalPcrValues(refvals []*ar.Component) ([]*ar.Component, error) {

	summaryMap := make(map[int][]byte)

	for _, rv := range refvals {

		hash := rv.GetHash(crypto.SHA256)
		idx, err := rv.GetIndex()
		if err != nil {
			return nil, fmt.Errorf("failed to get index: %w", err)
		}

		old, ok := summaryMap[idx]
		if !ok {
			summaryMap[idx] = hash
			continue
		}
		log.Tracef("extending hash: %x", old)
		summaryMap[idx] = internal.ExtendSha256(old, hash)
		log.Tracef("data          : %x", hash)
		log.Tracef("extended hash : %x", summaryMap[idx])
	}

	// Convert map back to slice
	var summaries []*ar.Component
	for idx, val := range summaryMap {
		c := &ar.Component{
			Type: ar.CycloneDxType(ar.TRUST_ANCHOR_TPM, idx),
			Name: ar.TYPE_PCR_SUMMARY,
			Hashes: []ar.ReferenceHash{
				{
					Alg:     "SHA-256",
					Content: val[:],
				},
			},
		}
		c.SetTrustAnchor(ar.TRUST_ANCHOR_TPM)
		c.SetIndex(idx)
		summaries = append(summaries, c)
	}

	// Sort summaries by index
	sort.Slice(summaries, func(i, j int) bool {
		i1, _ := summaries[i].GetIndex()
		i2, _ := summaries[j].GetIndex()
		return i1 < i2
	})

	return summaries, nil
}

func PrecomputeAggregatePcrValue(refvals []*ar.Component) (*ar.Component, error) {
	pcrValues, err := PrecomputeFinalPcrValues(refvals)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate final PCR values")
	}
	hash := sha256.New()

	for _, val := range pcrValues {
		hash.Write(val.GetHash(crypto.SHA256))
	}
	aggregateHash := hash.Sum(nil)
	aggregate := &ar.Component{
		Type: "TPM PCR Aggregate",
		Hashes: []ar.ReferenceHash{
			{
				Alg:     "SHA-256",
				Content: aggregateHash,
			},
		},
	}
	aggregate.SetTrustAnchor(ar.TRUST_ANCHOR_TPM)
	aggregate.SetIndex(0)

	return aggregate, nil
}
