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

package main

import (
	"crypto/x509"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// NamingPolicy determines the subject and SANs the CA will put into a certificate. The result can
// be nil for enrollment paths without attestation
type NamingPolicy interface {
	Assign(csr *x509.CertificateRequest, validity time.Duration, result *ar.AttestationResult) (internal.CertFields, error)
}

// CsrPassthrough copies subject and SANs verbatim from the CSR. This is the default policy
type CsrPassthrough struct{}

func (CsrPassthrough) Assign(csr *x509.CertificateRequest, validity time.Duration, _ *ar.AttestationResult,
) (internal.CertFields, error) {
	return internal.CertFields{
		RawSubject:  csr.RawSubject,
		DNSNames:    csr.DNSNames,
		IPAddresses: csr.IPAddresses,
		URIs:        csr.URIs,
		ValidFor:    validity,
	}, nil
}
