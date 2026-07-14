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
	report []byte,
) (*x509.Certificate, error) {
	return est.TpmCertifyEnroll(e.client, e.Addr, e.bearerToken, csr, ikParams, akPublic, report)
}

func (e *EstEnroller) AttestEnroll(
	csr *x509.CertificateRequest,
	report []byte,
) (*x509.Certificate, error) {
	return est.AttestEnroll(e.client, e.Addr, e.bearerToken, csr, report)
}
