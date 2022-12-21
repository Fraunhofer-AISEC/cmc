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
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "internal")

// Returns either the unmodified absolute path or the absolute path
// retrieved from a path relative to a base path
func GetFilePath(p, base string) string {
	if path.IsAbs(p) {
		return p
	}
	ret, _ := filepath.Abs(filepath.Join(base, p))
	return ret
}

func Contains(elem string, list []string) bool {
	for _, s := range list {
		if strings.EqualFold(s, elem) {
			return true
		}
	}
	return false
}

// LoadCert loads a certificate from PEM encoded data
func LoadCert(data []byte) (*x509.Certificate, error) {
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

// LoadCerts loads one or more certificates from PEM encoded data
func LoadCerts(data []byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0)
	input := data

	for block, rest := pem.Decode(input); block != nil; block, rest = pem.Decode(rest) {

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse x509 Certificate: %v", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func PrintTlsConfig(conf *tls.Config, roots []byte) error {
	for i, certs := range conf.Certificates {
		log.Tracef("TLS leaf certificate %v: %v, SubjectKeyID %v, AuthorityKeyID %v",
			i, certs.Leaf.Subject.CommonName,
			hex.EncodeToString(certs.Leaf.SubjectKeyId),
			hex.EncodeToString(certs.Leaf.AuthorityKeyId))
		for j, data := range certs.Certificate {
			c, err := LoadCert(data)
			if err != nil {
				return fmt.Errorf("failed to convert certificate: %w", err)
			}
			log.Tracef("Cert %v TLS Certificate Chain %v: %v, SubjectKeyID %v, AuthorityKeyID %v",
				i, j, c.Subject.CommonName,
				hex.EncodeToString(c.SubjectKeyId),
				hex.EncodeToString(c.AuthorityKeyId))
		}
	}
	certs, err := LoadCerts(roots)
	if err != nil {
		return fmt.Errorf("failed to load certs: %w", err)
	}
	for i, c := range certs {
		log.Tracef("Trusted Root Cert %v: %v, SubjectKeyID %v",
			i, c.Subject.CommonName, hex.EncodeToString(c.SubjectKeyId))
	}
	return nil
}
