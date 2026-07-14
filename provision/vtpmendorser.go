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
	"errors"

	"github.com/google/go-attestation/attest"
)

// VtpmEndorser only signals that no credential activation is required.
// the TPM driver then provisions a self-signed AK certificate.
// This is only to be used for CVMs with Confidential Computing trust anchor,
// where the vTPM resides within the CVM and is bound to the hardware
// attestation report.
type VtpmEndorser struct{}

// CaCerts is just a noop for satisfying the endorser interface
func (n *VtpmEndorser) CaCerts() ([]*x509.Certificate, error) {
	return nil, nil
}

// RequiresCredentialActivation indicates whether TPM credential activation
// is required. This is not the case for vTPMs used as a secondary trust anchor
func (n *VtpmEndorser) RequiresCredentialActivation() bool {
	return false
}

// TpmActivateEnroll is just a noop for satisfying the endorser interface
func (n *VtpmEndorser) TpmActivateEnroll(
	tpmManufacturer, ekCertUrl string,
	tpmMajor, tpmMinor int,
	csr *x509.CertificateRequest,
	akParams attest.AttestationParameters,
	ekPublic, ekCertDer []byte,
) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, errors.New("credential activation is not supported for a vTPM endorser")
}
