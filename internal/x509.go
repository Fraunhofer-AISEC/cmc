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

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// ParseCert parses a certificate from PEM or DER encoded data into an X.509 certificate
func ParseCert(data []byte) (*x509.Certificate, error) {
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

// ParseCertsDer parses DER encoded certificates
func ParseCertsDer(data any) ([]*x509.Certificate, error) {
	switch d := data.(type) {
	case []byte:
		return parseCertsDer(d)
	case [][]byte:
		return parseCertsListDer(d)
	default:
		return nil, fmt.Errorf("not implemented for type %T", data)
	}
}

func parseCertsDer(data []byte) ([]*x509.Certificate, error) {
	certs, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER certificates: %w", err)
	}
	if len(certs) == 0 {
		return nil, errors.New("data did not contain any DER certificates")
	}

	return certs, nil
}

func parseCertsListDer(data [][]byte) ([]*x509.Certificate, error) {
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

func CheckCert(cert *x509.Certificate, cn string, signatureAlgo x509.SignatureAlgorithm) error {
	if cert == nil {
		return errors.New("internal error: cert to check is nil")
	}

	if cn != cert.Subject.CommonName {
		return fmt.Errorf("unexpected CN=%v. Expected %v", cert.Subject.CommonName, cn)
	}
	log.Tracef("Certificate CN=%v matches expected CN", cn)

	if signatureAlgo != cert.SignatureAlgorithm {
		return fmt.Errorf("unsupported signature algorithm %v. Only supports %v",
			cert.SignatureAlgorithm.String(), signatureAlgo.String())
	}
	log.Tracef("Certificate signature algorithm %v matches expected algorithm", signatureAlgo.String())

	return nil
}

// CheckRevocation first validates the provided certificate revocation list against a CA and then
// checks if the provided certificate was revoked
func CheckRevocation(crl *x509.RevocationList, cert *x509.Certificate, ca *x509.Certificate) error {

	if cert == nil || crl == nil {
		return fmt.Errorf("certificate or revocation null pointer exception")
	}

	if crl.Issuer.String() != ca.Subject.String() {
		return fmt.Errorf("CRL issuer name %v does not match CA subject name %v",
			crl.Issuer.String(), ca.Subject.String())
	}
	log.Tracef("CRL issuer name %v matches expected name", crl.Issuer.String())

	// Check CRL signature
	err := crl.CheckSignatureFrom(ca)
	if err != nil {
		return fmt.Errorf("CRL signature is invalid: %v", err)
	}

	// Check if CRL is up to date
	now := time.Now()
	if now.After(crl.NextUpdate) {
		return fmt.Errorf("CRL has expired since: %v", crl.NextUpdate)
	}

	if !bytes.Equal(crl.RawIssuer, cert.RawIssuer) {
		return fmt.Errorf("CRL RawIssuer is invalid. got: %v, expected: %v ", crl.RawIssuer, cert.RawIssuer)
	}

	// Check if certificate has been revoked
	for _, revokedCert := range crl.RevokedCertificateEntries {
		if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
			return fmt.Errorf("certificate has been revoked since: %v", revokedCert.RevocationTime)
		}
	}

	return nil
}

func PrintTlsConfig(conf *tls.Config, roots []byte) error {
	log.Debug("Using the following TLS certificate configuration")
	for i, certs := range conf.Certificates {
		for j, data := range certs.Certificate {
			c, err := ParseCert(data)
			if err != nil {
				return fmt.Errorf("failed to convert certificate: %w", err)
			}
			log.Debugf("Cert %v:%v: %v, SubjectKeyID %v, AuthorityKeyID %v",
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
		log.Debugf("CA Cert%v: %v, SubjectKeyID %v",
			i, c.Subject.CommonName, hex.EncodeToString(c.SubjectKeyId))
	}
	return nil
}

func parseCertsListPem(data [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0)
	for _, d := range data {
		cert, err := ParseCert(d)
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
