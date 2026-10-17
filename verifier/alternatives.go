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

package verifier

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// matchDirectRefval selects the reference value a measurement register which directly holds a
// digest (AMD SEV-SNP measurement, Intel TDX MRTD and MRSEAM) must be compared against.
// Several reference values for such a register are only accepted if they all declare the same
// non-empty alternative group, in which case exactly one of them must match the measurement.
// Returns the matched reference value, if any, and the accepted alternatives which were not
// launched.
func matchDirectRefval(alg crypto.Hash, measured []byte, refs []ar.Component,
) (matched *ar.Component, alternatives []ar.Component, code ar.ErrorCode, err error) {

	if len(refs) == 0 {
		return nil, nil, ar.RefValNotPresent, fmt.Errorf("no reference value present")
	}

	// Validate the whole set before matching, so that a malformed manifest is rejected
	// independently of which alternative the attester happens to be running
	group := refs[0].AlternativeGroup
	for _, ref := range refs {
		if len(refs) > 1 {
			if group == "" {
				return nil, nil, ar.RefValMultiple, fmt.Errorf(
					"%v reference values for a single measurement, but none declares an alternative group",
					len(refs))
			}
			if ref.AlternativeGroup != group {
				return nil, nil, ar.RefValAltGroup, fmt.Errorf(
					"reference value %q declares alternative group %q, expected %q",
					ref.Name, ref.AlternativeGroup, group)
			}
		}
		if len(ref.GetHash(alg)) == 0 {
			return nil, nil, ar.RefValType, fmt.Errorf(
				"reference value %q does not contain a %v digest", ref.Name, alg.String())
		}
	}
	if len(refs) > 1 {
		log.Debugf("Matching measurement against %v alternatives of group %q", len(refs), group)
	}

	for i, ref := range refs {
		refHash := ref.GetHash(alg)
		if bytes.Equal(refHash, measured) {
			log.Debugf("Measurement matches reference value %q: %v", ref.Name,
				hex.EncodeToString(refHash))
			matched = &refs[i]
			alternatives = append(alternatives, refs[:i]...)
			alternatives = append(alternatives, refs[i+1:]...)
			return matched, alternatives, ar.NotSpecified, nil
		}
	}

	return nil, refs, ar.RefValNoMatch, fmt.Errorf(
		"measurement %v does not match any of the %v reference value(s)",
		hex.EncodeToString(measured), len(refs))
}

// alternativeResults reports the accepted alternatives which were not launched.
func alternativeResults(alg crypto.Hash, index int, alternatives []ar.Component) []ar.DigestResult {

	results := make([]ar.DigestResult, 0, len(alternatives))
	for _, alt := range alternatives {
		results = append(results, ar.DigestResult{
			Type:        ar.TYPE_DIGEST_ALTERNATIVE,
			Name:        alt.Name,
			Index:       index,
			Digest:      alt.GetHash(alg),
			Success:     true,
			Launched:    false,
			Description: alt.Description,
			Version:     alt.Version,
			PackageUrl:  alt.PackageUrl,
			HashAlg:     alg.String(),
		})
	}
	return results
}

// checkNoAlternatives rejects alternatives on measurement registers which are built by extending
// individual measurements.
func checkNoAlternatives(refs []ar.Component) error {
	for _, ref := range refs {
		if ref.AlternativeGroup != "" {
			return fmt.Errorf("reference value %q declares alternative group %q: alternatives are "+
				"only supported for measurement registers directly holding a digest",
				ref.Name, ref.AlternativeGroup)
		}
	}
	return nil
}
