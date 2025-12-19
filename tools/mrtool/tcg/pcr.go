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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

func PrecomputeFinalPcrValues(refvals []*ar.ReferenceValue) ([]*ar.ReferenceValue, error) {

	summaryMap := make(map[int][]byte)

	for _, rv := range refvals {
		old, ok := summaryMap[rv.Index]
		if !ok {
			// Initialize old value with init value (can be different from zero in PCR0)
			summaryMap[rv.Index] = rv.Sha256
			continue
		}
		log.Tracef("extending hash: %v", hex.EncodeToString(old))
		summaryMap[rv.Index] = internal.ExtendSha256(old, rv.Sha256)
		log.Tracef("data          : %v", hex.EncodeToString(rv.Sha256))
		log.Tracef("extended hash : %v", hex.EncodeToString(summaryMap[rv.Index]))
	}

	// Convert map back to slice
	var summaries []*ar.ReferenceValue
	for idx, val := range summaryMap {
		summaries = append(summaries, &ar.ReferenceValue{
			Type:    "TPM Reference Value",
			SubType: "PCR Summary",
			Index:   idx,
			Sha256:  val,
		})
	}

	// Sort summaries by index
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Index < summaries[j].Index
	})

	return summaries, nil
}

func PrecomputeAggregatePcrValue(refvals []*ar.ReferenceValue) (*ar.ReferenceValue, error) {
	pcrValues, err := PrecomputeFinalPcrValues(refvals)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate final PCR values")
	}
	hash := sha256.New()

	for _, val := range pcrValues {
		hash.Write(val.Sha256)
	}
	aggregateHash := hash.Sum(nil)
	aggregate := &ar.ReferenceValue{
		Type:   "TPM PCR Aggregate",
		Index:  0,
		Sha256: aggregateHash,
	}

	return aggregate, nil
}
