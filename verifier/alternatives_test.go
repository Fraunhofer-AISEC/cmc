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
	"crypto"
	"slices"
	"testing"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

func refval(name, group string, digest byte) ar.Component {
	content := make([]byte, crypto.SHA384.Size())
	content[0] = digest
	return ar.Component{
		Name: name,
		Hashes: []ar.ReferenceHash{
			{Alg: crypto.SHA384.String(), Content: content},
		},
		AlternativeGroup: group,
	}
}

func measurement(digest byte) []byte {
	m := make([]byte, crypto.SHA384.Size())
	m[0] = digest
	return m
}

func TestMatchDirectRefval(t *testing.T) {

	tests := []struct {
		name         string
		measured     []byte
		refs         []ar.Component
		wantMatched  string
		wantAltCount int
		wantCode     ar.ErrorCode
	}{
		{
			name:        "Single reference value",
			measured:    measurement(0x01),
			refs:        []ar.Component{refval("a", "", 0x01)},
			wantMatched: "a",
			wantCode:    ar.NotSpecified,
		},
		{
			name:     "Single reference value no match",
			measured: measurement(0x99),
			refs:     []ar.Component{refval("a", "", 0x01)},
			wantCode: ar.RefValNoMatch,
		},
		{
			name:     "First alternative matches",
			measured: measurement(0x01),
			refs: []ar.Component{
				refval("a", "g", 0x01), refval("b", "g", 0x02), refval("c", "g", 0x03),
			},
			wantMatched:  "a",
			wantAltCount: 2,
			wantCode:     ar.NotSpecified,
		},
		{
			name:     "Middle alternative matches",
			measured: measurement(0x02),
			refs: []ar.Component{
				refval("a", "g", 0x01), refval("b", "g", 0x02), refval("c", "g", 0x03),
			},
			wantMatched:  "b",
			wantAltCount: 2,
			wantCode:     ar.NotSpecified,
		},
		{
			name:     "Last alternative matches",
			measured: measurement(0x03),
			refs: []ar.Component{
				refval("a", "g", 0x01), refval("b", "g", 0x02), refval("c", "g", 0x03),
			},
			wantMatched:  "c",
			wantAltCount: 2,
			wantCode:     ar.NotSpecified,
		},
		{
			name:     "No alternative matches",
			measured: measurement(0x99),
			refs: []ar.Component{
				refval("a", "g", 0x01), refval("b", "g", 0x02),
			},
			wantCode: ar.RefValNoMatch,
		},
		{
			name:     "Multiple reference values without group",
			measured: measurement(0x01),
			refs: []ar.Component{
				refval("a", "", 0x01), refval("b", "", 0x02),
			},
			wantCode: ar.RefValMultiple,
		},
		{
			name:     "Inconsistent groups",
			measured: measurement(0x01),
			refs: []ar.Component{
				refval("a", "g", 0x01), refval("b", "other", 0x02),
			},
			wantCode: ar.RefValAltGroup,
		},
		{
			name:     "Partially declared group",
			measured: measurement(0x01),
			refs: []ar.Component{
				refval("a", "g", 0x01), refval("b", "", 0x02),
			},
			wantCode: ar.RefValAltGroup,
		},
		{
			name:     "No reference value",
			measured: measurement(0x01),
			refs:     nil,
			wantCode: ar.RefValNotPresent,
		},
		{
			name:     "Alternative without matching hash algorithm",
			measured: measurement(0x01),
			refs: []ar.Component{
				refval("a", "g", 0x01),
				{Name: "b", Hashes: []ar.ReferenceHash{
					{Alg: crypto.SHA256.String(), Content: measurement(0x02)}},
					AlternativeGroup: "g"},
			},
			wantCode: ar.RefValType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, alternatives, code, err := matchDirectRefval(crypto.SHA384, tt.measured,
				tt.refs)

			if code != tt.wantCode {
				t.Errorf("matchDirectRefval() code = %v, want %v", code, tt.wantCode)
			}
			if tt.wantMatched == "" {
				if err == nil {
					t.Errorf("matchDirectRefval() unexpectedly succeeded with %v", matched.Name)
				}
				return
			}
			if err != nil {
				t.Fatalf("matchDirectRefval() failed: %v", err)
			}
			if matched.Name != tt.wantMatched {
				t.Errorf("matchDirectRefval() matched = %v, want %v", matched.Name,
					tt.wantMatched)
			}
			if len(alternatives) != tt.wantAltCount {
				t.Errorf("matchDirectRefval() returned %v alternatives, want %v",
					len(alternatives), tt.wantAltCount)
			}
			// The matched reference value must not be reported as an unlaunched alternative
			for _, alt := range alternatives {
				if alt.Name == tt.wantMatched {
					t.Errorf("matchDirectRefval() reported matched %v as alternative",
						alt.Name)
				}
			}
			for _, r := range alternativeResults(crypto.SHA384, 0, alternatives) {
				if r.Type != ar.TYPE_DIGEST_ALTERNATIVE || !r.Success || r.Launched {
					t.Errorf("alternativeResults() = %+v, want type %v, success, not launched",
						r, ar.TYPE_DIGEST_ALTERNATIVE)
				}
			}
		})
	}
}

// Trust anchors which recalculate a register by extending the individual measurements must
// reject alternatives instead of silently ignoring them
func TestAlternativesRejectedByUnsupportedVerifiers(t *testing.T) {

	refs := []ar.Component{refval("a", "group", 0x01)}

	verifiers := map[string]func() *ar.MeasurementResult{
		"tpm": func() *ar.MeasurementResult {
			r, _ := VerifyTpm(ar.Evidence{}, ar.Collateral{}, nil, nil, refs, nil)
			return r
		},
		"sgx": func() *ar.MeasurementResult {
			r, _ := VerifySgx(ar.Evidence{}, ar.Collateral{}, nil, nil, nil, refs)
			return r
		},
		"sw": func() *ar.MeasurementResult {
			r, _ := VerifySw(ar.Evidence{}, ar.Collateral{}, nil, refs)
			return r
		},
		"swima": func() *ar.MeasurementResult {
			r, _ := VerifySwima(ar.Evidence{}, ar.Collateral{}, nil, refs)
			return r
		},
	}

	for name, verify := range verifiers {
		t.Run(name, func(t *testing.T) {
			result := verify()
			if result.Summary.Status != ar.StatusFail {
				t.Fatalf("%v accepted an unsupported alternative group", name)
			}
			if !slices.Contains(result.Summary.ErrorCodes, ar.RefValAltUnsupported) {
				t.Errorf("%v failed with %v, want %v", name, result.Summary.ErrorCodes,
					ar.RefValAltUnsupported)
			}
		})
	}
}

func TestCheckNoAlternatives(t *testing.T) {
	if err := checkNoAlternatives([]ar.Component{
		refval("a", "", 0x01), refval("b", "", 0x02),
	}); err != nil {
		t.Errorf("checkNoAlternatives() unexpectedly failed: %v", err)
	}
	if err := checkNoAlternatives([]ar.Component{
		refval("a", "", 0x01), refval("b", "g", 0x02),
	}); err == nil {
		t.Error("checkNoAlternatives() accepted an alternative group on an extended register")
	}
}
