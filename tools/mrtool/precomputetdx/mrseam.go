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
func PrecomputeMrSeam(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {
	log.Debugf("Precomputing MRSEAM...")

	var mrseam []byte
	refvals := make([]*ar.ReferenceValue, 0)

	if c.TdxModule != "" {
		data, err := os.ReadFile(c.TdxModule)
		if err != nil {
			return nil, nil, fmt.Errorf("faild to read tdx-module: %w", err)
		}
		hash := sha512.Sum384(data)

		refvals = append(refvals, &ar.ReferenceValue{
			Type:        "TDX Reference Value",
			SubType:     "TDX-Module",
			Index:       tcg.INDEX_MRSEAM,
			Sha384:      hash[:],
			Description: "MRSEAM: SEAMLDR Measurement: TDX-Module",
		})
		mrseam = hash[:]
	} else if c.MrSeam != "" {
		hash, err := hex.DecodeString(c.MrSeam)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode hash: %w", err)
		}
		if len(hash) != sha512.Size384 {
			return nil, nil, fmt.Errorf("malformed sha384 hash length: (is: %v, expected: %v)", len(hash), sha512.Size384)
		}

		refvals = append(refvals, &ar.ReferenceValue{
			Type:        "TDX Reference Value",
			SubType:     "TDX-Module",
			Index:       tcg.INDEX_MRSEAM,
			Sha384:      hash[:],
			Description: "MRSEAM: TDX Module Measurement: SEAMLDR Measurement: TDX-Module",
		})
		mrseam = hash[:]
	} else {
		return nil, nil, fmt.Errorf("tdx-module or mrseam must be specified for MRSEAM")
	}

	// Create MRSEAM final reference value
	mrseamSummary := &ar.ReferenceValue{
		Type:        "TDX Reference Value",
		SubType:     "MRSEAM Summary",
		Description: "MRSEAM",
		Index:       tcg.INDEX_MRSEAM,
		Sha384:      mrseam,
	}

	return mrseamSummary, refvals, nil
}
