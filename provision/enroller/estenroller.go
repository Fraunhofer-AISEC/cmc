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

package estenroller

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision/est"
	"github.com/google/go-attestation/attest"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "enroller")

type EstEnroller struct {
	Addr        string
	bearerToken []byte
	client      *http.Client
}

func New(addr string, rootCas []*x509.Certificate, allowSystemCerts bool, token []byte,
) (*EstEnroller, error) {

	log.Debugf("Creating new EST enroller for %v", addr)

	// The client does authenticate itself via attestation evidence and/or token as configured
	client, err := internal.NewHttpClient(rootCas, allowSystemCerts, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create EST client: %w", err)
	}

	return &EstEnroller{
		Addr:        addr,
		bearerToken: token,
		client:      client,
	}, nil
}

func (e *EstEnroller) CaCerts() ([]*x509.Certificate, error) {
	return est.CaCerts(e.client, e.Addr, e.bearerToken)
}

func (e *EstEnroller) SimpleEnroll(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	return est.SimpleEnroll(e.client, e.Addr, e.bearerToken, csr)
}

func (e *EstEnroller) TpmCertifyEnroll(
	csr *x509.CertificateRequest,
	ikParams attest.CertificationParameters,
	akPublic []byte,
	generateReport func(nonce []byte) ([]byte, error),
) (*x509.Certificate, error) {
	nonce, err := csrNonce(csr)
	if err != nil {
		return nil, err
	}

	report, err := generateReport(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation report: %w", err)
	}

	return est.TpmCertifyEnroll(e.client, e.Addr, e.bearerToken, csr, ikParams, akPublic, report)
}

func (e *EstEnroller) AttestEnroll(
	csr *x509.CertificateRequest,
	generateReport func(nonce []byte) ([]byte, error),
) (*x509.Certificate, error) {
	nonce, err := csrNonce(csr)
	if err != nil {
		return nil, err
	}

	report, err := generateReport(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation report: %w", err)
	}

	return est.AttestEnroll(e.client, e.Addr, e.bearerToken, csr, report)
}

// csrNonce derives the attestation report nonce from the CSR's public key as
// the EST protocol has no server-provided nonce. The EST server recomputes
// SHA-256 over the DER-encoded public key for verification.
func csrNonce(csr *x509.CertificateRequest) ([]byte, error) {
	pubKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CSR public key: %w", err)
	}
	nonce := sha256.Sum256(pubKey)
	return nonce[:], nil
}
