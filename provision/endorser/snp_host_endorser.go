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

package endorser

import (
	"crypto/x509"
	"fmt"

	"github.com/Fraunhofer-AISEC/cmc/drivers"
	"github.com/Fraunhofer-AISEC/cmc/drivers/snpdriver"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

type SnpHostEndorser struct {
}

// Implement the EndorserProvider interface
func (endorser *SnpHostEndorser) Snp() (drivers.SnpEndorser, error) {
	return endorser, nil
}

func (endorser *SnpHostEndorser) Tdx() (drivers.TdxEndorser, error) {
	return nil, fmt.Errorf("internal error: requesting TDX from SNP endorser")
}

func (endorser *SnpHostEndorser) Tpm() (drivers.TpmEndorser, error) {
	return nil, fmt.Errorf("internal error: requesting TPM from SNP endorser")
}

// NewSnpHostEndorser initializes a new SNP host endorser. It fetches certificates
// via the SNP_GET_EXT_REPORT API
func NewSnpHostEndorser() (*SnpHostEndorser, error) {
	return &SnpHostEndorser{}, nil
}

// GetSnpVcek implements the drivers.SnpEndorser interface. It fetches the VCEK certificate via the
// SNP_GET_EXT_REPORT API
func (s *SnpHostEndorser) GetSnpVcek(codeName string, chipId []byte, tcb uint64) (*x509.Certificate, error) {
	// TODO support VMPLs other than 0 if required
	_, certTable, err := snpdriver.GetExtendedReport(0)
	if err != nil {
		return nil, fmt.Errorf("failed to get extended report: %w", err)
	}
	certs, err := snpdriver.GetCertsFromExtReport(certTable, [][]byte{snpdriver.VcekUuid})
	if err != nil {
		return nil, fmt.Errorf("failed to get certs from report: %w", err)
	}
	return certs[0], nil
}

// GetSnpCa implements the drivers.SnpEndorser interface. It fetches the CA certificate chain via the
// SNP_GET_EXT_REPORT API
func (s *SnpHostEndorser) GetSnpCa(codeName string, akType internal.AkType) ([]*x509.Certificate, error) {
	// TODO support VMPLs other than 0 if required
	_, certTable, err := snpdriver.GetExtendedReport(0)
	if err != nil {
		return nil, fmt.Errorf("failed to get extended report: %w", err)
	}
	certs, err := snpdriver.GetCertsFromExtReport(certTable, [][]byte{snpdriver.AskUuid, snpdriver.ArkUuid})
	if err != nil {
		return nil, fmt.Errorf("failed to get certs from report: %w", err)
	}
	return certs, nil
}
