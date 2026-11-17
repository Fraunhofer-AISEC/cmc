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
	"bytes"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"slices"
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

// matchCertNames checks that subject and SANs of the CSR are identical to the certificate being
// renewed (RFC 7030 4.2.2)
func matchCertNames(csr *x509.CertificateRequest, cert *x509.Certificate) error {
	if !bytes.Equal(csr.RawSubject, cert.RawSubject) {
		return fmt.Errorf("subject %v does not match certificate subject %v", csr.Subject,
			cert.Subject)
	}
	if !slices.Equal(csr.DNSNames, cert.DNSNames) {
		return fmt.Errorf("DNS names %v do not match certificate %v", csr.DNSNames, cert.DNSNames)
	}
	if !slices.EqualFunc(csr.IPAddresses, cert.IPAddresses, net.IP.Equal) {
		return fmt.Errorf("IP addresses %v do not match certificate %v", csr.IPAddresses,
			cert.IPAddresses)
	}
	if !slices.EqualFunc(csr.URIs, cert.URIs, func(a, b *url.URL) bool {
		return a.String() == b.String()
	}) {
		return fmt.Errorf("URIs %v do not match certificate %v", csr.URIs, cert.URIs)
	}
	if !slices.Equal(csr.EmailAddresses, cert.EmailAddresses) {
		return fmt.Errorf("email addresses %v do not match certificate %v", csr.EmailAddresses,
			cert.EmailAddresses)
	}
	return nil
}
