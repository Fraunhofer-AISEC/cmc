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

package swdriver

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"os"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/est/client"
	"github.com/sirupsen/logrus"
)

var (
	log = logrus.WithField("service", "swdriver")
)

type Config struct {
	StoragePath string
	Url         string
	Metadata    [][]byte
	Serializer  ar.Serializer
}

// Sw is a struct required for implementing the signer and measurer interfaces
// of the attestation report to perform software measurements and signing
type Sw struct {
	certChain []*x509.Certificate
	priv      crypto.PrivateKey
}

// Init a new object for software-based signing
func (s *Sw) Init(c Config) error {

	if s == nil {
		return errors.New("internal error: SW object is nil")
	}

	// Check if serializer is initialized
	switch c.Serializer.(type) {
	case ar.JsonSerializer:
	case ar.CborSerializer:
	default:
		return fmt.Errorf("serializer not initialized in driver config")
	}

	// Create storage folder for storage of internal data if not existing
	if _, err := os.Stat(c.StoragePath); err != nil {
		if err := os.MkdirAll(c.StoragePath, 0755); err != nil {
			return fmt.Errorf("failed to create directory for internal data '%v': %w",
				c.StoragePath, err)
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	csr, err := createCsr(&c, priv)
	if err != nil {
		return fmt.Errorf("failed to create CSRs: %w", err)
	}

	// Get CA certificates and enroll newly created CSR
	// TODO provision EST server certificate with a different mechanism,
	// otherwise this step has to happen in a secure environment. Allow
	// different CAs for metadata and the EST server authentication
	log.Warn("Creating new EST client without server authentication")
	estclient := client.NewClient(nil)

	log.Info("Retrieving CA certs")
	caCerts, err := estclient.CaCerts(c.Url)
	if err != nil {
		return fmt.Errorf("failed to retrieve certs: %w", err)
	}
	log.Debug("Received certs:")
	for _, c := range caCerts {
		log.Debugf("\t%v", c.Subject.CommonName)
	}
	if len(caCerts) == 0 {
		return fmt.Errorf("no certs provided")
	}

	log.Warn("Setting retrieved cert for future authentication")
	err = estclient.SetCAs([]*x509.Certificate{caCerts[len(caCerts)-1]})
	if err != nil {
		return fmt.Errorf("failed to set EST CA: %w", err)
	}

	cert, err := estclient.SimpleEnroll(c.Url, csr)
	if err != nil {
		return fmt.Errorf("failed to enroll cert: %w", err)
	}

	s.certChain = append([]*x509.Certificate{cert}, caCerts...)
	s.priv = priv

	return nil
}

// Lock implements the locking method for the attestation report signer interface
func (s *Sw) Lock() error {
	// No locking mechanism required for software key
	return nil
}

// Lock implements the unlocking method for the attestation report signer interface
func (s *Sw) Unlock() error {
	// No unlocking mechanism required for software key
	return nil
}

// GetSigningKeys returns the TLS private and public key as a generic
// crypto interface
func (s *Sw) GetSigningKeys() (crypto.PrivateKey, crypto.PublicKey, error) {
	if s == nil {
		return nil, nil, errors.New("internal error: SW object is nil")
	}
	return s.priv, &s.priv.(*ecdsa.PrivateKey).PublicKey, nil
}

func (s *Sw) GetCertChain() ([]*x509.Certificate, error) {
	if s == nil {
		return nil, errors.New("internal error: SW object is nil")
	}
	return s.certChain, nil
}

func createCsr(c *Config, priv crypto.PrivateKey) (*x509.CertificateRequest, error) {

	for i, m := range c.Metadata {

		// Extract plain payload (i.e. the manifest/description itself)
		payload, err := c.Serializer.GetPayload(m)
		if err != nil {
			log.Warnf("Failed to parse metadata object %v: %v", i, err)
			continue
		}

		// Unmarshal the Type field of the metadata file to determine the type
		t := new(ar.Type)
		err = c.Serializer.Unmarshal(payload, t)
		if err != nil {
			log.Warnf("Failed to unmarshal data from metadata object: %v", err)
			continue
		}

		if t.Type == "Device Config" {
			var deviceConfig ar.DeviceConfig
			err = c.Serializer.Unmarshal(payload, &deviceConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal DeviceConfig: %w", err)
			}
			csr, err := createCsrFromParams(priv, deviceConfig.IkCsr)
			if err != nil {
				return nil, fmt.Errorf("failed to create CSR: %w", err)
			}
			return csr, nil
		}
	}

	return nil, errors.New("failed to find device config for creating CSRs")
}

func createCsrFromParams(priv crypto.PrivateKey, params ar.CsrParams,
) (*x509.CertificateRequest, error) {

	tmpl := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         params.Subject.CommonName,
			Country:            []string{params.Subject.Country},
			Province:           []string{params.Subject.Province},
			Locality:           []string{params.Subject.Locality},
			Organization:       []string{params.Subject.Organization},
			OrganizationalUnit: []string{params.Subject.OrganizationalUnit},
			StreetAddress:      []string{params.Subject.StreetAddress},
			PostalCode:         []string{params.Subject.PostalCode},
		},
		DNSNames: params.SANs,
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created CSR: %v", err)
	}
	err = csr.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("failed to check signature of created CSR: %v", err)
	}

	return csr, nil
}
