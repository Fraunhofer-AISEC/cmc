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
	"net/http"

	"github.com/Fraunhofer-AISEC/cmc/drivers"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision/est"
	"github.com/google/go-attestation/attest"
)

type EstEndorser struct {
	Addr        string
	bearerToken []byte
	client      *http.Client
}

func NewEstEndorser(addr string, rootCas []*x509.Certificate, allowSystemCerts bool, token []byte,
) (*EstEndorser, error) {
	// The client does authenticate itself via attestation evidence and/or token as configured
	client, err := internal.NewHttpClient(rootCas, allowSystemCerts, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create EST client: %w", err)
	}

	return &EstEndorser{
		Addr:        addr,
		bearerToken: token,
		client:      client,
	}, nil
}

func (e *EstEndorser) Snp() (drivers.SnpEndorser, error) {
	return nil, fmt.Errorf("EST endorser does not support SNP")
}

func (e *EstEndorser) Tdx() (drivers.TdxEndorser, error) {
	return nil, fmt.Errorf("EST endorser does not support SNP")
}

func (e *EstEndorser) Tpm() (drivers.TpmEndorser, error) {
	return e, nil
}

func (e *EstEndorser) RequiresCredentialActivation() bool {
	return true
}

func (e *EstEndorser) CaCerts() ([]*x509.Certificate, error) {
	return est.CaCerts(e.client, e.Addr, e.bearerToken)
}

func (e *EstEndorser) TpmActivateEnroll(
	tpmManufacturer, ekCertUrl string,
	tpmMajor, tpmMinor int,
	csr *x509.CertificateRequest,
	akParams attest.AttestationParameters,
	ekPublic, ekCertDer []byte,
) ([]byte, []byte, []byte, error) {

	return est.TpmActivateEnroll(e.client, e.Addr, e.bearerToken,
		tpmManufacturer, ekCertUrl,
		tpmMajor, tpmMinor,
		csr, akParams, ekPublic, ekCertDer)
}
