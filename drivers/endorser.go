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

package drivers

import (
	"crypto/x509"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/google/go-attestation/attest"
)

type EndorserProvider interface {
	Snp() (SnpEndorser, bool)
	Tdx() (TdxEndorser, bool)
	Tpm() (TpmEndorser, bool)
}

// TpmEndorser provides the interface for performing TPM AK credential activation
type TpmEndorser interface {
	CaCerts() ([]*x509.Certificate, error)
	TpmActivateEnroll(
		tpmManufacturer, ekCertUrl string,
		tpmMajor, tpmMinor int,
		csr *x509.CertificateRequest,
		akParams attest.AttestationParameters,
		ekPublic, ekCertDer []byte,
	) ([]byte, []byte, []byte, error)
}

// SnpEndorser provides the interface to fetch AMD SEV-SNP root CA and VCEK certificates
type SnpEndorser interface {
	GetSnpCa(codeName string, akType internal.AkType) ([]*x509.Certificate, error)
	GetSnpVcek(codeName string, chipId []byte, tcb uint64) (*x509.Certificate, error)
}

// TdxEndorser provides the interface to fetch Intel SGX/TDX collaterals
type TdxEndorser interface {
	FetchCollateral(fmspc string, pckcert *x509.Certificate, quoteType ar.IntelQuoteType) (*ar.IntelCollateral, error)
}
