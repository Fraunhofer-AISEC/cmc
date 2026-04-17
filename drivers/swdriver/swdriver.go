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
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
)

var (
	log = logrus.WithField("service", "swdriver")
)

// Sw is a struct required for implementing the signer and measurer interfaces
// of the attestation report to perform software measurements and signing
type Sw struct {
	*drivers.DriverConfig
	akPriv       crypto.PrivateKey
	akPub        crypto.PublicKey
	ctr          bool
	evidenceHash []byte
	serializer   ar.Serializer
}

const (
	akFile = "sw_ak_private.key"
)

// Name returns the name of the driver
func (s *Sw) Name() string {
	return "SW driver"
}

// Init a new object for software-based signing
func (sw *Sw) Init(c *drivers.DriverConfig) error {

	if sw == nil {
		return errors.New("internal error: SW object is nil")
	}

	// SW Evidence is always JSON serialized, as OCI specs are JSON
	s, err := ar.NewJsonSerializer()
	if err != nil {
		return fmt.Errorf("failed to initialize sw serializer: %w", err)
	}

	sw.DriverConfig = c
	sw.ctr = c.Ctr && strings.EqualFold(c.CtrDriver, "sw")
	sw.serializer = s

	// Create storage folder for storage of internal data if not existing
	if c.StoragePath != "" {
		if _, err := os.Stat(c.StoragePath); err != nil {
			if err := os.MkdirAll(c.StoragePath, 0755); err != nil {
				return fmt.Errorf("failed to create local storage '%v': %v", c.StoragePath, err)
			}
		}
	}

	if provisioningRequired(c.StoragePath) {
		log.Info("Performing SW provisioning")

		// Create CSR and fetch new certificate including its chain from EST server
		err = sw.provision()
		if err != nil {
			return fmt.Errorf("failed to provision sw driver: %w", err)
		}

		if c.StoragePath != "" {
			err = sw.saveAk()
			if err != nil {
				return fmt.Errorf("failed to save sw credentials: %w", err)
			}
		}
	} else {
		err = sw.loadAk()
		if err != nil {
			return fmt.Errorf("failed to load SW credentials: %w", err)
		}
	}

	return nil
}

func (sw *Sw) GetEvidence(nonce []byte) ([]ar.Evidence, error) {

	log.Debugf("Generating SW evidence with aggregated hash %x", sw.evidenceHash)

	// Generate Evidence = Nonce | Aggregated_Hash
	data, err := sw.serializer.Marshal(&ar.SwEvidence{
		Nonce:  nonce,
		Sha256: sw.evidenceHash,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal evidence: %w", err)
	}

	log.Tracef("Signing SW evidence with %v serialization", sw.serializer.String())
	swEvidence, err := internal.Sign(data, sw.akPriv, sw.serializer.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign sw evidence: %w", err)
	}

	evidence := ar.Evidence{
		Type: ar.TYPE_EVIDENCE_SW,
		Data: swEvidence,
	}

	log.Tracef("Created sw evidence: %v", string(swEvidence))

	return []ar.Evidence{evidence}, nil
}

func (sw *Sw) GetCollateral() ([]ar.Collateral, error) {

	log.Debug("Collecting SW collateral")

	if !sw.ctr {
		return nil, errors.New("sw driver specified but use containers equals false")
	}

	artifacts := make([]ar.Artifact, 0)
	aggregatedHash := make([]byte, 32)
	if _, err := os.Stat(sw.CtrLog); err == nil {

		log.Debugf("Reading container measurements")

		// If CMC container measurements are used, add the list of executed containers
		data, err := os.ReadFile(sw.CtrLog)
		if err != nil {
			return nil, fmt.Errorf("failed to read container measurements: %w", err)
		}

		var eventlog ar.Artifact
		err = sw.serializer.Unmarshal(data, &eventlog)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal measurement list: %w", err)
		}
		artifacts = append(artifacts, eventlog)

		// Calculate the aggregated evidence hash through extending all container measurements
		for _, ml := range eventlog.Events {
			hash := ml.GetHash(crypto.SHA256)
			log.Tracef("Extending template hash %x", hash)
			aggregatedHash = internal.ExtendSha256(aggregatedHash, hash)
		}

	} else if errors.Is(err, os.ErrNotExist) {
		log.Trace("No container measurements to read")
	} else {
		return nil, fmt.Errorf("failed to check container measurement file: %w", err)
	}

	// Store the aggregated hash for evidence retrieval
	log.Tracef("Calculated aggregated hash %x", aggregatedHash)
	sw.evidenceHash = aggregatedHash

	pub, err := internal.WritePublicKeyPem(sw.akPub)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	collateral := ar.Collateral{
		Type:      ar.TYPE_EVIDENCE_SW,
		Artifacts: artifacts,
		Key:       pub,
	}

	log.Tracef("Created collateral with public key: %v", string(pub))

	return []ar.Collateral{collateral}, nil
}

func (sw *Sw) UpdateCerts() error {
	var err error

	log.Info("Updating sw certificates")

	// Initial checks
	if sw == nil {
		return errors.New("internal error: sw object is nil")
	}

	err = sw.provision()
	if err != nil {
		return fmt.Errorf("failed to provision sw driver: %w", err)
	}

	if sw.StoragePath != "" {
		err = sw.saveAk()
		if err != nil {
			return fmt.Errorf("failed to save sw credentials: %w", err)
		}
	}

	return nil
}

func provisioningRequired(p string) bool {
	// Stateless operation always requires provisioning
	if p == "" {
		log.Info("SW Provisioning REQUIRED")
		return true
	}

	// If any of the required files is not present, we need to provision
	if _, err := os.Stat(path.Join(p, akFile)); err != nil {
		log.Info("SW Provisioning REQUIRED")
		return true
	}

	log.Info("SW Provisioning NOT REQUIRED")

	return false
}

func (sw *Sw) provision() error {
	var err error

	// Create new AK private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate AK private key: %w", err)
	}
	sw.akPriv = priv
	sw.akPub = &priv.PublicKey

	return nil
}

func (sw *Sw) loadAk() error {
	data, err := os.ReadFile(path.Join(sw.StoragePath, akFile))
	if err != nil {
		return fmt.Errorf("failed to read AK private key from %v: %w", sw.StoragePath, err)
	}
	sw.akPriv, err = internal.ParsePrivateKey(data)
	if err != nil {
		return fmt.Errorf("failed to parse AK private key: %w", err)
	}
	switch k := sw.akPriv.(type) {
	case ecdsa.PrivateKey:
		sw.akPub = &k.PublicKey
	case *ecdsa.PrivateKey:
		sw.akPub = &k.PublicKey
	case rsa.PrivateKey:
		sw.akPub = &k.PublicKey
	case *rsa.PrivateKey:
		sw.akPub = &k.PublicKey
	}

	return nil
}

func (sw *Sw) saveAk() error {
	ak, err := x509.MarshalPKCS8PrivateKey(sw.akPriv)
	if err != nil {
		return fmt.Errorf("failed marshal private key: %w", err)
	}
	if err := os.WriteFile(path.Join(sw.StoragePath, akFile), ak, 0600); err != nil {
		return fmt.Errorf("failed to write %v: %w", path.Join(sw.StoragePath, akFile), err)
	}

	return nil
}
