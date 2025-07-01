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

	"github.com/Fraunhofer-AISEC/cmc/verifier"
)

type Provisioner interface {
	Init(serverTlsCas []*x509.Certificate, allowSystemCerts bool, token []byte) error
	CaCerts(addr string) ([]*x509.Certificate, error)
	SimpleEnroll(addr string, csr *x509.CertificateRequest) (*x509.Certificate, error)
	TpmActivateEnroll(
		addr, tpmManufacturer, ekCertUrl string,
		tpmMajor, tpmMinor int,
		csr *x509.CertificateRequest,
		akPublic, akCreateData, akCreateAttestation, akCreateSignature []byte,
		ekPublic, ekCertDer []byte,
	) ([]byte, []byte, []byte, error)
	TpmCertifyEnroll(
		addr string,
		csr *x509.CertificateRequest,
		ikPublic, ikCreateData, ikCreateAttestation, ikCreateSignature []byte,
		akPublic []byte,
		report []byte,
		metadata [][]byte,
	) (*x509.Certificate, error)
	CcEnroll(addr string, csr *x509.CertificateRequest, report []byte, metadata [][]byte) (*x509.Certificate, error)
	GetSnpCa(addr string, akType verifier.AkType) ([]*x509.Certificate, error)
	GetSnpVcek(addr string, chipId [64]byte, tcb uint64) (*x509.Certificate, error)
}
