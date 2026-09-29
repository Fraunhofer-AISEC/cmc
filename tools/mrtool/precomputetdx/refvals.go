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

package precomputetdx

import (
	"crypto"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/tcg"
)

// extendDigest records an already computed SHA-384 digest as a reference value for the
// measurement register index and extends the running register value with it.
func extendDigest(rtmr []byte, refvals []*ar.Component, index int, name string, digest []byte,
	desc string,
) ([]byte, []*ar.Component, error) {

	rv, rtmr, err := tcg.ExtendRefval(crypto.SHA384, tcg.TDX, index, rtmr, digest, name, desc)
	if err != nil {
		return nil, nil, err
	}

	return rtmr, append(refvals, rv), nil
}

// hashExtend hashes data, records it as a reference value for the measurement register index and
// extends the running register value with it.
func hashExtend(rtmr []byte, refvals []*ar.Component, index int, name string, data []byte,
	desc string,
) ([]byte, []*ar.Component, error) {

	rv, rtmr, err := tcg.CreateExtendRefval(crypto.SHA384, tcg.TDX, index, rtmr, data, name, desc)
	if err != nil {
		return nil, nil, err
	}

	return rtmr, append(refvals, rv), nil
}

// rtmrSummary creates the reference value for the final measurement register value.
func rtmrSummary(index int, rtmr []byte) *ar.Component {

	comp := &ar.Component{
		Type:        ar.CycloneDxType(ar.TRUST_ANCHOR_TDX, index),
		Name:        "RTMR Summary",
		Description: tcg.IndexToMr(tcg.TDX, index),
		Hashes: []ar.ReferenceHash{
			{
				Alg:     "SHA-384",
				Content: rtmr,
			},
		},
	}
	comp.SetTrustAnchor(ar.TRUST_ANCHOR_TDX)
	comp.SetIndex(index)

	return comp
}
