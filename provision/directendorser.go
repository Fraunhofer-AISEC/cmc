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

package provision

import (
	"fmt"

	"github.com/Fraunhofer-AISEC/cmc/drivers"
)

const (
	PcsUrl = "https://api.trustedservices.intel.com"
)

type DirectEndorser struct {
	snp *SnpEndorser
	tdx *TdxEndorser
}

// NewDirectProvider builds an endorser that fetches collateral directly from the vendor
// services (AMD KDS, Intel PCS)
func NewDirectProvider(vendorCacheFolder string) (*DirectEndorser, error) {

	// Use the host system root store regardless of the CMC trust
	// pool as the Intel PCS is a production service under a global CA
	tdx, err := NewTdxEndorser(PcsUrl, vendorCacheFolder, nil, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create TDX endorser: %w", err)
	}
	return &DirectEndorser{
		snp: NewSnpEndorser(vendorCacheFolder),
		tdx: tdx,
	}, nil
}

func (p *DirectEndorser) Snp() (drivers.SnpEndorser, bool) {
	return p.snp, true
}

func (p *DirectEndorser) Tdx() (drivers.TdxEndorser, bool) {
	return p.tdx, true
}

func (p *DirectEndorser) Tpm() (drivers.TpmEndorser, bool) {
	return nil, false
}
