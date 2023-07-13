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
	"errors"
	"fmt"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	est "github.com/Fraunhofer-AISEC/cmc/est/estclient"
	"github.com/sirupsen/logrus"
)

var (
	log = logrus.WithField("service", "swdriver")
)

// Sw is a struct required for implementing the signer and measurer interfaces
// of the attestation report to perform software measurements and signing
type Sw struct {
	certChain []*x509.Certificate
	priv      crypto.PrivateKey
}

// Init a new object for software-based signing
func (s *Sw) Init(c *ar.DriverConfig) error {

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

	// Create new private key for signing
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	s.priv = priv

	// Create CSR and fetch new certificate including its chain from EST server
	s.certChain, err = getSigningCertChain(priv, c.Serializer, c.Metadata, c.ServerAddr)
	if err != nil {
		return fmt.Errorf("failed to get signing cert chain: %w", err)
	}

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
	log.Tracef("Returning %v certificates", len(s.certChain))
	return s.certChain, nil
}

func (s *Sw) Measure(nonce []byte) (ar.Measurement, error) {
	return ar.SwMeasurement{}, errors.New("Measure method not implemented for SW driver")
}

func getSigningCertChain(priv crypto.PrivateKey, s ar.Serializer, metadata [][]byte,
	addr string,
) ([]*x509.Certificate, error) {

	csr, err := ar.CreateCsr(priv, s, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSRs: %w", err)
	}

	// Get CA certificates and enroll newly created CSR
	// TODO provision EST server certificate with a different mechanism,
	// otherwise this step has to happen in a secure environment. Allow
	// different CAs for metadata and the EST server authentication
	log.Warn("Creating new EST client without server authentication")
	client := est.NewClient(nil)

	log.Info("Retrieving CA certs")
	caCerts, err := client.CaCerts(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve certs: %w", err)
	}
	log.Debug("Received certs:")
	for _, c := range caCerts {
		log.Debugf("\t%v", c.Subject.CommonName)
	}
	if len(caCerts) == 0 {
		return nil, fmt.Errorf("no certs provided")
	}

	log.Warn("Setting retrieved cert for future authentication")
	err = client.SetCAs([]*x509.Certificate{caCerts[len(caCerts)-1]})
	if err != nil {
		return nil, fmt.Errorf("failed to set EST CA: %w", err)
	}

	cert, err := client.SimpleEnroll(addr, csr)
	if err != nil {
		return nil, fmt.Errorf("failed to enroll cert: %w", err)
	}

	return append([]*x509.Certificate{cert}, caCerts...), nil
}
