// Copyright (c) 2021 - 2024 Fraunhofer AISEC
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
	"os"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	est "github.com/Fraunhofer-AISEC/cmc/est/estclient"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
)

var (
	log = logrus.WithField("service", "swdriver")
)

// Sw is a struct required for implementing the signer and measurer interfaces
// of the attestation report to perform software measurements and signing
type Sw struct {
	akChain    []*x509.Certificate
	ikChain    []*x509.Certificate
	akPriv     crypto.PrivateKey
	ikPriv     crypto.PrivateKey
	ctr        bool
	ctrPcr     int
	ctrLog     string
	extCtrLog  bool
	serializer ar.Serializer
}

// Name returns the name of the driver
func (s *Sw) Name() string {
	return "SW driver"
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

	// Create new IK private key
	akPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate AK private key: %w", err)
	}
	s.akPriv = akPriv

	// Create new AK private key
	ikPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate IK private key: %w", err)
	}
	s.ikPriv = ikPriv

	// Create CSR and fetch new certificate including its chain from EST server
	s.akChain, s.ikChain, err = provisionSw(akPriv, ikPriv, c.DeviceConfig,
		c.ServerAddr, c.EstTlsCas, c.UseSystemRootCas)
	if err != nil {
		return fmt.Errorf("failed to provision sw driver: %w", err)
	}

	s.ctr = c.Ctr && strings.EqualFold(c.CtrDriver, "sw")
	s.ctrLog = c.CtrLog
	s.extCtrLog = c.ExtCtrLog
	s.ctrPcr = c.CtrPcr
	s.serializer = c.Serializer

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

// GetKeyHandles returns private and public key handles as a generic crypto interface
func (s *Sw) GetKeyHandles(sel ar.KeySelection) (crypto.PrivateKey, crypto.PublicKey, error) {
	if s == nil {
		return nil, nil, errors.New("internal error: SW object is nil")
	}
	if sel == ar.AK {
		return s.akPriv, &s.akPriv.(*ecdsa.PrivateKey).PublicKey, nil
	} else if sel == ar.IK {
		return s.ikPriv, &s.ikPriv.(*ecdsa.PrivateKey).PublicKey, nil
	}
	return nil, nil, fmt.Errorf("internal error: unknown key selection %v", sel)
}

// GetCertChain returns the certificate chain for the specified key
func (s *Sw) GetCertChain(sel ar.KeySelection) ([]*x509.Certificate, error) {
	if s == nil {
		return nil, errors.New("internal error: SW object is nil")
	}
	if sel == ar.AK {
		log.Debugf("Returning %v AK certificates", len(s.akChain))
		return s.akChain, nil
	} else if sel == ar.IK {
		log.Debugf("Returning %v IK certificates", len(s.ikChain))
		return s.ikChain, nil
	}
	return nil, fmt.Errorf("internal error: unknown key selection %v", sel)
}

func (s *Sw) Measure(nonce []byte) (ar.Measurement, error) {

	log.Debug("Collecting SW measurements")

	if !s.ctr {
		return ar.Measurement{}, errors.New("sw driver specified but use containers equals false")
	}

	artifacts := make([]ar.Artifact, 0)
	aggregatedHash := make([]byte, 32)
	if _, err := os.Stat(s.ctrLog); err == nil {

		log.Debugf("Reading container measurements")

		// If CMC container measurements are used, add the list of executed containers
		data, err := os.ReadFile(s.ctrLog)
		if err != nil {
			return ar.Measurement{}, fmt.Errorf("failed to read container measurements: %w", err)
		}

		var measureList []ar.MeasureEvent
		err = s.serializer.Unmarshal(data, &measureList)
		if err != nil {
			return ar.Measurement{}, fmt.Errorf("failed to unmarshal measurement list: %w", err)
		}

		artifact := ar.Artifact{
			Type:   "SW Eventlog",
			Events: measureList,
		}
		artifacts = append(artifacts, artifact)

		// Calculate the aggregated evidence hash through extending all container measurements
		for _, ml := range measureList {
			aggregatedHash = internal.ExtendSha256(aggregatedHash, ml.Sha256)
		}

	} else if errors.Is(err, os.ErrNotExist) {
		log.Trace("No container measurements to read")
	} else {
		return ar.Measurement{}, fmt.Errorf("failed to check container measurement file: %w", err)
	}

	// Generate Evidence = Nonce | Aggregated_Hash
	data, err := s.serializer.Marshal(&ar.SwEvidence{
		Nonce:  nonce,
		Sha256: aggregatedHash,
	})
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to marshal evidence: %w", err)
	}
	evidence, err := s.serializer.Sign(data, s, ar.AK)
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to sign sw evidence: %w", err)
	}

	measurement := ar.Measurement{
		Type:      "SW Measurement",
		Evidence:  evidence,
		Artifacts: artifacts,
		Certs:     internal.WriteCertsDer(s.akChain),
	}

	return measurement, nil
}

func provisionSw(ak, ik crypto.PrivateKey, devConf ar.DeviceConfig, addr string,
	estTlsCas []*x509.Certificate, useSystemRootCas bool,
) ([]*x509.Certificate, []*x509.Certificate, error) {

	log.Info("Performing SW provisioning")

	client, err := est.NewClient(estTlsCas, useSystemRootCas)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create EST client: %w", err)
	}

	log.Debug("Retrieving CA certs")
	caCerts, err := client.CaCerts(addr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve certs: %w", err)
	}
	log.Debug("Received certs:")
	for _, c := range caCerts {
		log.Debugf("\t%v", c.Subject.CommonName)
	}
	if len(caCerts) == 0 {
		return nil, nil, fmt.Errorf("no certs provided")
	}

	// Perform AK EST enrollment
	akCsr, err := ar.CreateCsr(ak, devConf.Sw.AkCsr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AK CSR: %w", err)
	}

	log.Debugf("Performing simple AK enroll for CN=%v", akCsr.Subject.CommonName)
	akCert, err := client.SimpleEnroll(addr, akCsr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to enroll AK cert: %w", err)
	}
	akChain := append([]*x509.Certificate{akCert}, caCerts...)

	log.Debugf("Received certificate CN=%v", akCert.Subject.CommonName)

	// Perform IK EST enrollment
	ikCsr, err := ar.CreateCsr(ik, devConf.Sw.IkCsr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create IK CSR: %w", err)
	}

	log.Debugf("Performing simple IK enroll for CN=%v", ikCsr.Subject.CommonName)
	ikCert, err := client.SimpleEnroll(addr, ikCsr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to enroll cert: %w", err)
	}
	ikChain := append([]*x509.Certificate{ikCert}, caCerts...)

	log.Debugf("Received certificate CN=%v", ikCert.Subject.CommonName)

	return akChain, ikChain, nil
}
