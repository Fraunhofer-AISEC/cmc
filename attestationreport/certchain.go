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

package attestationreport

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/Fraunhofer-AISEC/cmc/internal"
)

func certChainToDer(certChain CertChain) ([][]byte, error) {

	certChainDer := make([][]byte, 0)

	leaf, _ := pem.Decode(certChain.Leaf)
	if leaf == nil {
		return nil, errors.New("failed to decode leaf certificate")
	}
	certChainDer = append(certChainDer, leaf.Bytes)

	for _, intermediate := range certChain.Intermediates {
		intermediateDer, _ := pem.Decode(intermediate)
		if intermediateDer == nil {
			return nil, errors.New("failed to decode intermediate certificate")
		}
		certChainDer = append(certChainDer, intermediateDer.Bytes)
	}

	ca, _ := pem.Decode(certChain.Ca)
	if ca == nil {
		return nil, errors.New("failed to decode ca certificate")
	}
	certChainDer = append(certChainDer, ca.Bytes)

	return certChainDer, nil
}

func verifyCertChainX509(certChain []*x509.Certificate, cas []*x509.Certificate) error {

	if len(certChain) < 2 {
		return fmt.Errorf("certificate chain must contain at least 2 certificates (contains %v)",
			len(certChain))
	}

	leafCert := certChain[0]
	rootCert := certChain[len(certChain)-1]

	rootsPool := x509.NewCertPool()
	rootsPool.AddCert(rootCert)

	intermediatesPool := x509.NewCertPool()
	for _, cert := range certChain[1 : len(certChain)-1] {
		intermediatesPool.AddCert(cert)
	}

	chain, err := leafCert.Verify(x509.VerifyOptions{Roots: rootsPool, Intermediates: intermediatesPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return fmt.Errorf("failed to validate certificate chain: %v", err)
	}

	if len(chain[0]) != len(certChain) {
		return fmt.Errorf("expected chain of length %v (got %v)", len(certChain), len(chain[0]))
	}

	// Match measurement CA against expected CAs
	found := false
	for _, cert := range cas {
		if bytes.Equal(cert.SubjectKeyId, rootCert.SubjectKeyId) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("ca Key ID %v does not match any of the expected CAs",
			rootCert.SubjectKeyId)
	}

	return nil
}

func verifyCertChainPem(certs *CertChain, caKeyIds [][]byte) error {

	intermediatesPool := x509.NewCertPool()
	for _, intermediate := range certs.Intermediates {
		ok := intermediatesPool.AppendCertsFromPEM(intermediate)
		if !ok {
			return errors.New("failed to append certificate to certificate pool")
		}
	}
	rootsPool := x509.NewCertPool()
	ok := rootsPool.AppendCertsFromPEM(certs.Ca)
	if !ok {
		return errors.New("failed to append certificate to certificate pool")
	}

	leafCert, err := internal.LoadCert(certs.Leaf)
	if err != nil {
		return fmt.Errorf("failed to parse leaf certificate public key: %v", err)
	}

	rootCert, err := internal.LoadCert(certs.Ca)
	if err != nil {
		return fmt.Errorf("failed to parse leaf certificate public key: %v", err)
	}

	chain, err := leafCert.Verify(x509.VerifyOptions{Roots: rootsPool, Intermediates: intermediatesPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return fmt.Errorf("failed to validate certificate chain: %v", err)
	}

	// Expected length is Leaf + Num(Intermediates) + CA
	expectedLen := len(certs.Intermediates) + 2
	if len(chain[0]) != expectedLen {
		return fmt.Errorf("expected chain of length %v (got %v)", expectedLen, len(chain[0]))
	}

	// Match measurement CA against expected CAs
	found := false
	for _, keyId := range caKeyIds {
		if bytes.Equal(keyId, rootCert.SubjectKeyId) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("ca Key ID %v does not match any of the expected CAs",
			rootCert.SubjectKeyId)
	}

	return nil
}
