// Copyright (c) 2021 Fraunhofer AISEC
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

package keymgr

import (
	"crypto/x509"
)

// CsrFunc creates the CSR. With attestation enabled, the CSR carries a report whose nonce is
// sha256(SPKI || nonce), binding it to the key and to the enroller's freshness value
type CsrFunc func(nonce []byte) (*x509.CertificateRequest, error)

// Enroller enrolls a key via a certificate enrollment protocol such as EST or ACME and returns
// its certificate chain, leaf first
type Enroller interface {
	Enroll(createCsr CsrFunc) ([]*x509.Certificate, error)
}
