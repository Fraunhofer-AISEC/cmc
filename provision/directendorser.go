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
	"crypto/x509"
	"fmt"

	"github.com/Fraunhofer-AISEC/cmc/drivers"
)

const (
	PcsUrl    = "https://api.trustedservices.intel.com"
	AmdKdsUrl = "https://kdsintf.amd.com"
)

type DirectEndorser struct {
	snp *SnpEndorser
	tdx *TdxEndorser
}

func (p *DirectEndorser) Snp() (drivers.SnpEndorser, error) {
	return p.snp, nil
}

func (p *DirectEndorser) Tdx() (drivers.TdxEndorser, error) {
	return p.tdx, nil
}

func (p *DirectEndorser) Tpm() (drivers.TpmEndorser, error) {
	return nil, fmt.Errorf("director endorser does not support TPM")
}

// NewDirectProvider builds an endorser that fetches collateral directly from the vendor
// services (AMD KDS, Intel PCS)
func NewDirectProvider(vendorCacheFolder string) (*DirectEndorser, error) {

	// Use the host system root store regardless of the CMC trust
	// pool as the Intel PCS is a production service under a global CA
	tdx, err := NewTdxEndorser(PcsUrl, vendorCacheFolder, nil, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create TDX direct endorser: %w", err)
	}

	// Use the system CA root store regardless of the CMC trust
	// pool as the AMD KDS is a production service under a global ca
	snp, err := NewSnpEndorser(AmdKdsUrl, vendorCacheFolder, nil, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create SNP direct endorser: %w", err)
	}

	return &DirectEndorser{
		snp: snp,
		tdx: tdx,
	}, nil
}

// NewCpsProvider builds an endorser that fetches both SNP and TDX collateral
// from a single caching proxy server (Caching Proxy Service) at baseUrl. The
// proxy is expected to expose AMD-KDS-shaped /vcek + /vlek endpoints as well
// as Intel-PCS-shaped /sgx and /tdx endpoints.
func NewCpsProvider(
	vendorCacheFolder string,
	baseUrl string,
	rootCas []*x509.Certificate,
	allowSystemCerts bool,
) (*DirectEndorser, error) {

	// Use the provided root cas and optionally additionally the system root store
	// as we are using a custom PCCS service
	tdx, err := NewTdxEndorser(baseUrl, vendorCacheFolder, rootCas, allowSystemCerts)
	if err != nil {
		return nil, fmt.Errorf("failed to create TDX cps endorser: %w", err)
	}

	// Use the provided root cas and optionally additionally the system root store
	// as we are using a custom caching proxy service
	snp, err := NewSnpEndorser(baseUrl, vendorCacheFolder, rootCas, allowSystemCerts)
	if err != nil {
		return nil, fmt.Errorf("failed to create SNP cps endorser: %w", err)
	}

	return &DirectEndorser{
		snp: snp,
		tdx: tdx,
	}, nil
}
