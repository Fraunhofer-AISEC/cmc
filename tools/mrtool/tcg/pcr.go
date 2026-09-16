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
	"sort"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// PrecomputeFinalPcrValues calculates the final PCR values from the specified reference values
// of the individual measurements. alg is the hash algorithm of the PCR bank the measurements
// were extended into
func PrecomputeFinalPcrValues(refvals []*ar.Component, alg crypto.Hash) ([]*ar.Component, error) {

	summaryMap := make(map[int][]byte)

	for _, rv := range refvals {

		hash := rv.GetHash(alg)
		if len(hash) == 0 {
			return nil, fmt.Errorf("reference value %v does not contain a %v digest",
				rv.Name, alg.String())
		}
		idx, err := rv.GetIndex()
		if err != nil {
			return nil, fmt.Errorf("failed to get index: %w", err)
		}

		// The PCR initialization value and PCR summaries are not extended but represent the
		// PCR value itself
		if rv.Name == ar.NAME_PCR_INIT_VALUE || rv.Name == ar.TYPE_PCR_SUMMARY {
			summaryMap[idx] = hash
			continue
		}

		// All PCRs are initialized with zeroes unless an explicit initialization value is
		// present in the event log
		old, ok := summaryMap[idx]
		if !ok {
			old = make([]byte, alg.Size())
		}
		log.Tracef("extending hash: %x", old)
		summaryMap[idx], err = internal.Extend(alg, old, hash)
		if err != nil {
			return nil, fmt.Errorf("failed to extend PCR%v: %w", idx, err)
		}
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
					Alg:     alg.String(),
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

// PrecomputeAggregatePcrValue calculates the aggregated PCR value as it is contained in a TPM
// quote. alg is the hash algorithm of the quoted PCR bank, aggAlg the hash algorithm the TPM
// uses to calculate the aggregated PCR digest, which is the hash algorithm of the signature
// scheme of the attestation key and therefore independent of the PCR bank
func PrecomputeAggregatePcrValue(refvals []*ar.Component, alg, aggAlg crypto.Hash,
) (*ar.Component, error) {
	pcrValues, err := PrecomputeFinalPcrValues(refvals, alg)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate final PCR values")
	}
	if !aggAlg.Available() {
		return nil, fmt.Errorf("hash algorithm not available: %v", aggAlg)
	}
	hash := aggAlg.New()

	for _, val := range pcrValues {
		hash.Write(val.GetHash(alg))
	}
	aggregateHash := hash.Sum(nil)
	aggregate := &ar.Component{
		Type: "TPM PCR Aggregate",
		Hashes: []ar.ReferenceHash{
			{
				Alg:     aggAlg.String(),
				Content: aggregateHash,
			},
		},
	}
	aggregate.SetTrustAnchor(ar.TRUST_ANCHOR_TPM)
	aggregate.SetIndex(0)

	return aggregate, nil
}
