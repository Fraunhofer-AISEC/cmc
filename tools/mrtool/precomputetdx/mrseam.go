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
	"path/filepath"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/tcg"
)

// alternativeGroup marks the generated MRSEAM reference values as mutually exclusive states of
// the register, of which exactly one must match
const alternativeGroup = "tdx-module"

// Calculates the measurement register for the TDX SEAM module (MRSEAM).
// Multiple TDX-modules or MRSEAM hashes can be specified, which are recorded as mutually
// exclusive alternative reference values.
func PrecomputeMrSeam(c *Config) ([]*ar.Component, []*ar.Component, error) {
	log.Debugf("Precomputing MRSEAM...")

	type module struct {
		hash []byte
		desc string
	}
	modules := make([]module, 0, len(c.TdxModules)+len(c.MrSeams))

	for _, path := range c.TdxModules {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("faild to read tdx-module: %w", err)
		}
		hash := sha512.Sum384(data)
		modules = append(modules, module{
			hash: hash[:],
			desc: fmt.Sprintf("MRSEAM: SEAMLDR Measurement: TDX-Module %v", filepath.Base(path)),
		})
	}

	for _, s := range c.MrSeams {
		hash, err := hex.DecodeString(s)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode hash: %w", err)
		}
		if len(hash) != sha512.Size384 {
			return nil, nil, fmt.Errorf("malformed sha384 hash length: (is: %v, expected: %v)",
				len(hash), sha512.Size384)
		}
		modules = append(modules, module{
			hash: hash,
			desc: "MRSEAM: TDX Module Measurement: SEAMLDR Measurement: TDX-Module",
		})
	}

	if len(modules) == 0 {
		return nil, nil, fmt.Errorf("tdx-module or mrseam must be specified for MRSEAM")
	}

	// Several TDX-modules are mutually exclusive states of the single MRSEAM register and must
	// be declared as alternatives for the verifier to accept any one of them
	group := ""
	if len(modules) > 1 {
		group = alternativeGroup
	}

	refvals := make([]*ar.Component, 0, len(modules))
	summaries := make([]*ar.Component, 0, len(modules))
	for _, m := range modules {
		refvals = append(refvals, mrSeamComponent("TDX-Module", m.desc, m.hash, group))
		summaries = append(summaries, mrSeamComponent("MRSEAM Summary", "MRSEAM", m.hash, group))
	}

	return summaries, refvals, nil
}

func mrSeamComponent(name, desc string, hash []byte, group string) *ar.Component {

	comp := &ar.Component{
		Type: ar.CycloneDxType(ar.TRUST_ANCHOR_TDX, tcg.INDEX_MRSEAM),
		Name: name,
		Hashes: []ar.ReferenceHash{
			{
				Alg:     "SHA-384",
				Content: hash,
			},
		},
		Description:      desc,
		AlternativeGroup: group,
	}
	comp.SetTrustAnchor(ar.TRUST_ANCHOR_TDX)
	comp.SetIndex(tcg.INDEX_MRSEAM)

	return comp
}
