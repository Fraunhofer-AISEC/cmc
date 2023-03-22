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
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "internal")

// Tries to retrieve a file from an absolute path, or path relative to
// the running binary or the optional base path
func GetFile(file string, base *string) ([]byte, error) {
	if file == "" {
		return nil, fmt.Errorf("empty filename passed")
	}
	f, err := GetFilePath(file, base)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %v: %v", f, err)
	}
	return data, nil
}

// Tries to retrieve a filepath from an absolute path, or path relative to
// the running binary or the optional base path
func GetFilePath(file string, base *string) (string, error) {

	if base != nil {
		log.Tracef("Searching for file '%v' with optional base path '%v'", file, *base)
	} else {
		log.Tracef("Searching for file '%v'", file)
	}

	// Search for the absolute path
	if path.IsAbs(file) && FileExists(file) {
		log.Tracef("Found: %v (absolute path)", file)
		return file, nil
	}

	// Search relative to the given base path
	var rf string
	var err error
	if base != nil {
		rf, err = filepath.Abs(filepath.Join(*base, file))
		if err == nil {
			if FileExists(rf) {
				log.Tracef("Found: %v (relative to base path)", rf)
				return rf, nil
			}
		}
	}

	// Search relative to the running binary
	bin, err := GetBinaryPath()
	if err != nil {
		return "", err
	}
	f, err := filepath.Abs(filepath.Join(bin, file))
	if err == nil {
		if FileExists(f) {
			log.Tracef("Found: %v (relative to binary)", f)
			return f, nil
		}
	}

	return "", fmt.Errorf("failed to find file. Places searched: %v, %v, %v", file, rf, f)
}

func Contains(elem string, list []string) bool {
	for _, s := range list {
		if strings.EqualFold(s, elem) {
			return true
		}
	}
	return false
}

// ParseCert parses a certificate from PEM encoded data into an X.509 certificate
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

// ParseCerts parses certificates in a single PEM encoded blob or a list of
// PEM encoded blobs into a list of X.509 certificates
func ParseCerts(data any) ([]*x509.Certificate, error) {
	switch d := data.(type) {
	case []byte:
		return parseCertBlob(d)
	case [][]byte:
		return parseCertsList(d)
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
			c, err := ParseCert(data)
			if err != nil {
				return fmt.Errorf("failed to convert certificate: %w", err)
			}
			log.Tracef("Cert %v:%v: %v, SubjectKeyID %v, AuthorityKeyID %v",
				i, j, c.Subject.CommonName,
				hex.EncodeToString(c.SubjectKeyId),
				hex.EncodeToString(c.AuthorityKeyId))
		}
	}
	certs, err := ParseCerts(roots)
	if err != nil {
		return fmt.Errorf("failed to load certs: %w", err)
	}
	for i, c := range certs {
		log.Tracef("CA Cert%v: %v, SubjectKeyID %v",
			i, c.Subject.CommonName, hex.EncodeToString(c.SubjectKeyId))
	}
	return nil
}

func parseCertsList(data [][]byte) ([]*x509.Certificate, error) {
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

func parseCertBlob(data []byte) ([]*x509.Certificate, error) {
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

func FileExists(f string) bool {
	if _, err := os.Stat(f); err == nil {
		return true
	}
	return false
}

func GetBinaryPath() (string, error) {
	bin, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get path of executable: %w", err)
	}
	d := filepath.Dir(bin)
	return d, nil
}

func FlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
