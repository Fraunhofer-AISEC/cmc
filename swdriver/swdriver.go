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
	"path"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
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

const (
	akchainFile = "sw_ak_chain.pem"
	ikchainFile = "sw_ik_chain.pem"
	akFile      = "sw_ak_private.key"
	ikFile      = "sw_ik_private.key"
)

// Name returns the name of the driver
func (s *Sw) Name() string {
	return "SW driver"
}

// Init a new object for software-based signing
func (sw *Sw) Init(c *ar.DriverConfig) error {
	var err error

	if sw == nil {
		return errors.New("internal error: SW object is nil")
	}

	// Check if serializer is initialized
	switch c.Serializer.(type) {
	case ar.JsonSerializer:
	case ar.CborSerializer:
	default:
		return fmt.Errorf("serializer not initialized in driver config")
	}

	if provisioningRequired(c.StoragePath) {
		log.Info("Performing SW provisioning")

		// Create CSR and fetch new certificate including its chain from EST server
		err = sw.provision(c)
		if err != nil {
			return fmt.Errorf("failed to provision sw driver: %w", err)
		}

		if c.StoragePath != "" {
			err = saveCredentials(c.StoragePath, sw)
			if err != nil {
				return fmt.Errorf("failed to save SNP credentials: %w", err)
			}
		}
	} else {
		sw.akChain, sw.ikChain, sw.akPriv, sw.ikPriv, err = loadCredentials(c.StoragePath)
		if err != nil {
			return fmt.Errorf("failed to load SW credentials: %w", err)
		}
	}

	sw.ctr = c.Ctr && strings.EqualFold(c.CtrDriver, "sw")
	sw.ctrLog = c.CtrLog
	sw.extCtrLog = c.ExtCtrLog
	sw.ctrPcr = c.CtrPcr
	sw.serializer = c.Serializer

	return nil
}

// Lock implements the locking method for the attestation report signer interface
func (sw *Sw) Lock() error {
	// No locking mechanism required for software key
	return nil
}

// Lock implements the unlocking method for the attestation report signer interface
func (sw *Sw) Unlock() error {
	// No unlocking mechanism required for software key
	return nil
}

// GetKeyHandles returns private and public key handles as a generic crypto interface
func (sw *Sw) GetKeyHandles(sel ar.KeySelection) (crypto.PrivateKey, crypto.PublicKey, error) {
	if sw == nil {
		return nil, nil, errors.New("internal error: SW object is nil")
	}
	if sel == ar.AK {
		return sw.akPriv, &sw.akPriv.(*ecdsa.PrivateKey).PublicKey, nil
	} else if sel == ar.IK {
		return sw.ikPriv, &sw.ikPriv.(*ecdsa.PrivateKey).PublicKey, nil
	}
	return nil, nil, fmt.Errorf("internal error: unknown key selection %v", sel)
}

// GetCertChain returns the certificate chain for the specified key
func (sw *Sw) GetCertChain(sel ar.KeySelection) ([]*x509.Certificate, error) {
	if sw == nil {
		return nil, errors.New("internal error: SW object is nil")
	}
	if sel == ar.AK {
		log.Debugf("Returning %v AK certificates", len(sw.akChain))
		return sw.akChain, nil
	} else if sel == ar.IK {
		log.Debugf("Returning %v IK certificates", len(sw.ikChain))
		return sw.ikChain, nil
	}
	return nil, fmt.Errorf("internal error: unknown key selection %v", sel)
}

func (sw *Sw) Measure(nonce []byte) ([]ar.Measurement, error) {

	log.Debug("Collecting SW measurements")

	if !sw.ctr {
		return nil, errors.New("sw driver specified but use containers equals false")
	}

	artifacts := make([]ar.Artifact, 0)
	aggregatedHash := make([]byte, 32)
	if _, err := os.Stat(sw.ctrLog); err == nil {

		log.Debugf("Reading container measurements")

		// If CMC container measurements are used, add the list of executed containers
		data, err := os.ReadFile(sw.ctrLog)
		if err != nil {
			return nil, fmt.Errorf("failed to read container measurements: %w", err)
		}

		var measureList []ar.MeasureEvent
		err = sw.serializer.Unmarshal(data, &measureList)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal measurement list: %w", err)
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
		return nil, fmt.Errorf("failed to check container measurement file: %w", err)
	}

	// Generate Evidence = Nonce | Aggregated_Hash
	data, err := sw.serializer.Marshal(&ar.SwEvidence{
		Nonce:  nonce,
		Sha256: aggregatedHash,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal evidence: %w", err)
	}
	evidence, err := sw.serializer.Sign(data, sw, ar.AK)
	if err != nil {
		return nil, fmt.Errorf("failed to sign sw evidence: %w", err)
	}

	measurement := ar.Measurement{
		Type:      "SW Measurement",
		Evidence:  evidence,
		Artifacts: artifacts,
		Certs:     internal.WriteCertsDer(sw.akChain),
	}

	return []ar.Measurement{measurement}, nil
}

func provisioningRequired(p string) bool {
	// Stateless operation always requires provisioning
	if p == "" {
		log.Info("SW Provisioning REQUIRED")
		return true
	}

	// If any of the required files is not present, we need to provision
	if _, err := os.Stat(path.Join(p, akchainFile)); err != nil {
		log.Info("SW Provisioning REQUIRED")
		return true
	}
	if _, err := os.Stat(path.Join(p, ikchainFile)); err != nil {
		log.Info("SW Provisioning REQUIRED")
		return true
	}
	if _, err := os.Stat(path.Join(p, akFile)); err != nil {
		log.Info("SW Provisioning REQUIRED")
		return true
	}
	if _, err := os.Stat(path.Join(p, ikFile)); err != nil {
		log.Info("SW Provisioning REQUIRED")
		return true
	}

	log.Info("SW Provisioning NOT REQUIRED")

	return false
}

func (sw *Sw) provision(c *ar.DriverConfig) error {
	var err error

	// Create new IK private key
	sw.akPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate AK private key: %w", err)
	}

	// Create new AK private key
	sw.ikPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate IK private key: %w", err)
	}

	log.Debug("Retrieving CA certs")
	caCerts, err := c.Provisioner.CaCerts()
	if err != nil {
		return fmt.Errorf("failed to retrieve certs: %w", err)
	}

	// Perform AK enrollment
	akCsr, err := ar.CreateCsr(sw.akPriv, c.DeviceConfig.Sw.AkCsr)
	if err != nil {
		return fmt.Errorf("failed to create AK CSR: %w", err)
	}

	log.Debugf("Performing simple AK enroll for CN=%v", akCsr.Subject.CommonName)
	akCert, err := c.Provisioner.SimpleEnroll(akCsr)
	if err != nil {
		return fmt.Errorf("failed to enroll AK cert: %w", err)
	}
	sw.akChain = append([]*x509.Certificate{akCert}, caCerts...)

	log.Debugf("Received certificate CN=%v", akCert.Subject.CommonName)

	// Perform IK enrollment
	ikCsr, err := ar.CreateCsr(sw.ikPriv, c.DeviceConfig.Sw.IkCsr)
	if err != nil {
		return fmt.Errorf("failed to create IK CSR: %w", err)
	}

	log.Debugf("Performing simple IK enroll for CN=%v", ikCsr.Subject.CommonName)
	ikCert, err := c.Provisioner.SimpleEnroll(ikCsr)
	if err != nil {
		return fmt.Errorf("failed to enroll cert: %w", err)
	}
	sw.ikChain = append([]*x509.Certificate{ikCert}, caCerts...)

	log.Debugf("Received certificate CN=%v", ikCert.Subject.CommonName)

	return nil
}

func loadCredentials(p string) ([]*x509.Certificate, []*x509.Certificate,
	crypto.PrivateKey, crypto.PrivateKey, error,
) {
	data, err := os.ReadFile(path.Join(p, akchainFile))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to read AK chain from %v: %w", p, err)
	}
	akchain, err := internal.ParseCertsPem(data)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse AK certs: %w", err)
	}
	log.Debugf("Parsed stored AK chain of length %v", len(akchain))

	data, err = os.ReadFile(path.Join(p, ikchainFile))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to read IK chain from %v: %w", p, err)
	}
	ikchain, err := internal.ParseCertsPem(data)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse IK certs: %w", err)
	}
	log.Debugf("Parsed stored IK chain of length %v", len(akchain))

	data, err = os.ReadFile(path.Join(p, akFile))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to read AK private key from %v: %w", p, err)
	}
	ak, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse AK private key: %w", err)
	}

	data, err = os.ReadFile(path.Join(p, ikFile))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to read IK private key from %v: %w", p, err)
	}
	ik, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse IK private key: %w", err)
	}

	return akchain, ikchain, ak, ik, nil
}

func saveCredentials(p string, sw *Sw) error {
	akchainPem := make([]byte, 0)
	for _, cert := range sw.akChain {
		c := internal.WriteCertPem(cert)
		akchainPem = append(akchainPem, c...)
	}
	if err := os.WriteFile(path.Join(p, akchainFile), akchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(p, akchainFile), err)
	}

	ikchainPem := make([]byte, 0)
	for _, cert := range sw.ikChain {
		c := internal.WriteCertPem(cert)
		ikchainPem = append(ikchainPem, c...)
	}
	if err := os.WriteFile(path.Join(p, ikchainFile), ikchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(p, ikchainFile), err)
	}

	ak, err := x509.MarshalPKCS8PrivateKey(sw.akPriv)
	if err != nil {
		return fmt.Errorf("failed marshal private key: %w", err)
	}
	if err := os.WriteFile(path.Join(p, akFile), ak, 0600); err != nil {
		return fmt.Errorf("failed to write %v: %w", path.Join(p, akFile), err)
	}

	ik, err := x509.MarshalPKCS8PrivateKey(sw.ikPriv)
	if err != nil {
		return fmt.Errorf("failed marshal private key: %w", err)
	}
	if err := os.WriteFile(path.Join(p, ikFile), ik, 0600); err != nil {
		return fmt.Errorf("failed to write %v: %w", path.Join(p, ikFile), err)
	}

	return nil
}
