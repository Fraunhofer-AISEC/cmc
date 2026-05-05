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

package precomputetdx

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/tcg"
)

/**
 * Calculates the measurement register for the TDX SEAM module (MRSEAM)
 *
 * The MRTD contains the digest of the TDX-module as measured by the SEAM loader
 */
func PrecomputeMrSeam(c *Config) (*ar.Component, []*ar.Component, error) {
	log.Debugf("Precomputing MRSEAM...")

	var mrseam []byte
	refvals := make([]*ar.Component, 0)

	if c.TdxModule != "" {
		data, err := os.ReadFile(c.TdxModule)
		if err != nil {
			return nil, nil, fmt.Errorf("faild to read tdx-module: %w", err)
		}
		hash := sha512.Sum384(data)

		comp := &ar.Component{
			Type: ar.CycloneDxType(ar.TRUST_ANCHOR_TDX, tcg.INDEX_MRSEAM),
			Name: "TDX-Module",
			Hashes: []ar.ReferenceHash{
				{
					Alg:     "SHA-384",
					Content: hash[:],
				},
			},
			Description: "MRSEAM: SEAMLDR Measurement: TDX-Module",
		}
		comp.SetTrustAnchor(ar.TRUST_ANCHOR_TDX)
		comp.SetIndex(tcg.INDEX_MRSEAM)
		refvals = append(refvals, comp)
		mrseam = hash[:]
	} else if c.MrSeam != "" {
		hash, err := hex.DecodeString(c.MrSeam)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode hash: %w", err)
		}
		if len(hash) != sha512.Size384 {
			return nil, nil, fmt.Errorf("malformed sha384 hash length: (is: %v, expected: %v)", len(hash), sha512.Size384)
		}

		comp := &ar.Component{
			Type: ar.CycloneDxType(ar.TRUST_ANCHOR_TDX, tcg.INDEX_MRSEAM),
			Name: "TDX-Module",
			Hashes: []ar.ReferenceHash{
				{
					Alg:     "SHA-384",
					Content: hash[:],
				},
			},
			Description: "MRSEAM: TDX Module Measurement: SEAMLDR Measurement: TDX-Module",
		}
		comp.SetTrustAnchor(ar.TRUST_ANCHOR_TDX)
		comp.SetIndex(tcg.INDEX_MRSEAM)
		refvals = append(refvals, comp)
		mrseam = hash[:]
	} else {
		return nil, nil, fmt.Errorf("tdx-module or mrseam must be specified for MRSEAM")
	}

	// Create MRSEAM final reference value
	mrseamSummary := &ar.Component{
		Type:        ar.CycloneDxType(ar.TRUST_ANCHOR_TDX, tcg.INDEX_MRSEAM),
		Name:        "MRSEAM Summary",
		Description: "MRSEAM",
		Hashes: []ar.ReferenceHash{
			{
				Alg:     "SHA-384",
				Content: mrseam,
			},
		},
	}
	mrseamSummary.SetTrustAnchor(ar.TRUST_ANCHOR_TDX)
	mrseamSummary.SetIndex(tcg.INDEX_MRSEAM)

	return mrseamSummary, refvals, nil
}
