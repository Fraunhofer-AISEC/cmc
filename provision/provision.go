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

package provision

import (
	"crypto/x509"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/go-attestation/attest"
)

type Provisioner interface {
	CaCerts() ([]*x509.Certificate, error)
	SimpleEnroll(csr *x509.CertificateRequest) (*x509.Certificate, error)
	TpmActivateEnroll(
		tpmManufacturer, ekCertUrl string,
		tpmMajor, tpmMinor int,
		csr *x509.CertificateRequest,
		akParams attest.AttestationParameters,
		ekPublic, ekCertDer []byte,
	) ([]byte, []byte, []byte, error)
	TpmCertifyEnroll(
		csr *x509.CertificateRequest,
		ikParams attest.CertificationParameters,
		akPublic []byte,
		report []byte,
		metadata [][]byte,
	) (*x509.Certificate, error)
	CcEnroll(csr *x509.CertificateRequest, report []byte, metadata [][]byte) (*x509.Certificate, error)
	GetSnpCa(akType internal.AkType) ([]*x509.Certificate, error)
	GetSnpVcek(chipId [64]byte, tcb uint64) (*x509.Certificate, error)
}
