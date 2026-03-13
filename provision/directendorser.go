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
	"github.com/Fraunhofer-AISEC/cmc/drivers"
)

type DirectEndorser struct {
	snp *SnpEndorser
	tdx *TdxEndorser
}

func NewDirectProvider(vcekCacheFolder string) *DirectEndorser {
	return &DirectEndorser{
		snp: NewSnpEndorser(vcekCacheFolder),
		tdx: NewTdxEndorser(),
	}
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
