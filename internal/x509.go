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

package internal

// Install github packages with "go get [url]"
import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// ParseCertsDer parses a list of DER encoded certificates
func ParseCertsDer(data [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0)
	for _, d := range data {
		cert, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, fmt.Errorf("failed to parse x509 Certificate: %v", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("data did not contain any certificates")
	}
	return certs, nil
}

// ParseCertPem parses a certificate from PEM encoded data into an X.509 certificate
func ParseCertPem(data []byte) (*x509.Certificate, error) {
	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	cert, err := x509.ParseCertificate(input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 Certificate: %v", err)
	}
	return cert, nil
}

// ParseCertsPem parses certificates in a single PEM encoded blob or a list of
// PEM encoded blobs into a list of X.509 certificates
func ParseCertsPem(data any) ([]*x509.Certificate, error) {
	switch d := data.(type) {
	case []byte:
		return parseCertBlobPem(d)
	case [][]byte:
		return parseCertsListPem(d)
	default:
		return nil, fmt.Errorf("not implemented for type %T", data)
	}
}

func WriteCertPem(cert *x509.Certificate) []byte {
	p := &bytes.Buffer{}
	pem.Encode(p, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return p.Bytes()
}

func WriteCertsPem(certs []*x509.Certificate) [][]byte {
	pems := make([][]byte, 0)
	for _, c := range certs {
		pems = append(pems, WriteCertPem(c))
	}
	return pems
}

func WriteCertsDer(certs []*x509.Certificate) [][]byte {
	raw := make([][]byte, 0)
	for _, c := range certs {
		raw = append(raw, c.Raw)
	}
	return raw
}

func WritePublicKeyPem(key crypto.PublicKey) ([]byte, error) {
	pk, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PKIX public key")
	}
	p := &bytes.Buffer{}
	pem.Encode(p, &pem.Block{Type: "PUBLIC KEY", Bytes: pk})
	return p.Bytes(), nil
}

// verifyCertChain tries to verify the certificate chain certs with leaf
// certificate first up to one of the root certificates in cas
func VerifyCertChain(certs []*x509.Certificate, cas []*x509.Certificate) ([][]*x509.Certificate, error) {

	if len(certs) == 0 {
		return nil, errors.New("no certificate chain provided")
	}
	if len(cas) == 0 {
		return nil, errors.New("no CA provided")
	}

	leafCert := certs[0]

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	roots := x509.NewCertPool()
	for _, ca := range cas {
		roots.AddCert(ca)
	}

	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := leafCert.Verify(opts)

	return chains, err
}

func PrintTlsConfig(conf *tls.Config, roots []byte) error {
	for i, certs := range conf.Certificates {
		for j, data := range certs.Certificate {
			c, err := ParseCertPem(data)
			if err != nil {
				return fmt.Errorf("failed to convert certificate: %w", err)
			}
			log.Tracef("Cert %v:%v: %v, SubjectKeyID %v, AuthorityKeyID %v",
				i, j, c.Subject.CommonName,
				hex.EncodeToString(c.SubjectKeyId),
				hex.EncodeToString(c.AuthorityKeyId))
		}
	}
	certs, err := ParseCertsPem(roots)
	if err != nil {
		return fmt.Errorf("failed to load certs: %w", err)
	}
	for i, c := range certs {
		log.Tracef("CA Cert%v: %v, SubjectKeyID %v",
			i, c.Subject.CommonName, hex.EncodeToString(c.SubjectKeyId))
	}
	return nil
}

func parseCertsListPem(data [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0)
	for _, d := range data {
		cert, err := ParseCertPem(d)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("did not find certs in provided data")
	}
	return certs, nil
}

func parseCertBlobPem(data []byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0)
	input := data

	for block, rest := pem.Decode(input); block != nil; block, rest = pem.Decode(rest) {

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse x509 Certificate: %v", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("did not find certs in provided data")
	}
	return certs, nil
}
