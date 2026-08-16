// Copyright (c) 2026 Fraunhofer AISEC
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

package swimadriver

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
	"sort"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers"
	"github.com/Fraunhofer-AISEC/cmc/ima"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
)

var (
	log = logrus.WithField("service", "imadriver")
)

// Swima is a struct required for implementing the signer and measurer interfaces of the
// attestation report to sign a Linux IMA runtime measurement list with a locally provisioned AK.
// It must only be used in combination with a Confidential Computing hardware trust anchor. On
// platforms with a TPM, IMA is handled by the tpmdriver instead
type Swima struct {
	*drivers.DriverConfig
	akPriv       crypto.PrivateKey
	akPub        crypto.PublicKey
	evidenceHash []byte
	serializer   ar.Serializer
}

const (
	akFile = "ima_ak_private.key"
)

// Name returns the name of the driver
func (i *Swima) Name() string {
	return "SWIMA driver"
}

// Init initializes a new IMA driver, loading or provisioning a local AK
func (i *Swima) Init(c *drivers.DriverConfig) error {

	if i == nil {
		return errors.New("internal error: IMA object is nil")
	}

	s, err := ar.NewJsonSerializer()
	if err != nil {
		return fmt.Errorf("failed to initialize ima serializer: %w", err)
	}

	i.DriverConfig = c
	i.serializer = s

	if c.StoragePath != "" {
		if _, err := os.Stat(c.StoragePath); err != nil {
			if err := os.MkdirAll(c.StoragePath, 0755); err != nil {
				return fmt.Errorf("failed to create local storage '%v': %w", c.StoragePath, err)
			}
		}
	}

	if provisioningRequired(c.StoragePath) {
		log.Info("Performing IMA provisioning")

		if err := i.provision(); err != nil {
			return fmt.Errorf("failed to provision ima driver: %w", err)
		}

		if c.StoragePath != "" {
			if err := i.saveAk(); err != nil {
				return fmt.Errorf("failed to save ima credentials: %w", err)
			}
		}
	} else {
		if err := i.loadAk(); err != nil {
			return fmt.Errorf("failed to load ima credentials: %w", err)
		}
	}

	return nil
}

// GetEvidence signs Nonce | Aggregated_Hash with the IMA AK
func (i *Swima) GetEvidence(nonce []byte) ([]ar.Evidence, error) {

	log.Debugf("Generating IMA evidence with aggregated hash %x", i.evidenceHash)

	data, err := i.serializer.Marshal(&ar.SwEvidence{
		Nonce:  nonce,
		Sha256: i.evidenceHash,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal evidence: %w", err)
	}

	log.Tracef("Signing IMA evidence with %v serialization", i.serializer.String())
	imaEvidence, err := internal.Sign(data, i.akPriv, i.serializer.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign ima evidence: %w", err)
	}

	evidence := ar.Evidence{
		Type: ar.TYPE_EVIDENCE_SWIMA,
		Data: imaEvidence,
	}

	return []ar.Evidence{evidence}, nil
}

// GetCollateral reads the IMA runtime measurement list, packages the parsed events as artifacts
// and returns them together with the AK public key. The aggregated hash over the template hashes
// is stored for evidence retrieval
func (i *Swima) GetCollateral() ([]ar.Collateral, error) {

	log.Debug("Collecting IMA collateral")

	logPath := ima.DEFAULT_BINARY_RUNTIME_MEASUREMENTS
	if _, err := os.Stat(logPath); err != nil {
		return nil, fmt.Errorf("failed to stat IMA runtime measurements at %v: %w", logPath, err)
	}

	artifactmap, err := ima.GetImaArtifacts(logPath, ar.TRUST_ANCHOR_SWIMA)
	if err != nil {
		return nil, fmt.Errorf("failed to read IMA runtime measurements: %w", err)
	}

	artifacts := make([]ar.Artifact, 0, len(artifactmap))
	for _, a := range artifactmap {
		artifacts = append(artifacts, a)
	}
	sort.Slice(artifacts, func(a, b int) bool {
		return artifacts[a].Index < artifacts[b].Index
	})

	aggregatedHash := make([]byte, 32)
	for _, a := range artifacts {
		for _, event := range a.Events {
			hash := event.GetHash(crypto.SHA256)
			log.Tracef("Extending template hash %x", hash)
			aggregatedHash = internal.ExtendSha256(aggregatedHash, hash)
		}
	}
	log.Tracef("Calculated aggregated hash %x", aggregatedHash)
	i.evidenceHash = aggregatedHash

	pub, err := internal.WritePublicKeyPem(i.akPub)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	collateral := ar.Collateral{
		Type:      ar.TYPE_EVIDENCE_SWIMA,
		Artifacts: artifacts,
		Key:       pub,
	}

	log.Tracef("Created IMA collateral with public key: %v", string(pub))

	return []ar.Collateral{collateral}, nil
}

// UpdateCerts regenerates the IMA AK. The AK is not part of a certificate chain, as trust is
// derived from its binding to the hardware report via the collateral hash
func (i *Swima) UpdateCerts() error {

	log.Info("Updating IMA credentials")

	if i == nil {
		return errors.New("internal error: ima object is nil")
	}

	if err := i.provision(); err != nil {
		return fmt.Errorf("failed to provision ima driver: %w", err)
	}

	if i.StoragePath != "" {
		if err := i.saveAk(); err != nil {
			return fmt.Errorf("failed to save ima credentials: %w", err)
		}
	}

	return nil
}

func provisioningRequired(p string) bool {
	if p == "" {
		log.Info("IMA Provisioning REQUIRED")
		return true
	}
	if _, err := os.Stat(path.Join(p, akFile)); err != nil {
		log.Info("IMA Provisioning REQUIRED")
		return true
	}
	log.Info("IMA Provisioning NOT REQUIRED")
	return false
}

func (i *Swima) provision() error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate AK private key: %w", err)
	}
	i.akPriv = priv
	i.akPub = &priv.PublicKey
	return nil
}

func (i *Swima) loadAk() error {
	data, err := os.ReadFile(path.Join(i.StoragePath, akFile))
	if err != nil {
		return fmt.Errorf("failed to read AK private key from %v: %w", i.StoragePath, err)
	}
	i.akPriv, err = internal.ParsePrivateKey(data)
	if err != nil {
		return fmt.Errorf("failed to parse AK private key: %w", err)
	}
	switch k := i.akPriv.(type) {
	case ecdsa.PrivateKey:
		i.akPub = &k.PublicKey
	case *ecdsa.PrivateKey:
		i.akPub = &k.PublicKey
	case rsa.PrivateKey:
		i.akPub = &k.PublicKey
	case *rsa.PrivateKey:
		i.akPub = &k.PublicKey
	}
	return nil
}

func (i *Swima) saveAk() error {
	ak, err := x509.MarshalPKCS8PrivateKey(i.akPriv)
	if err != nil {
		return fmt.Errorf("failed marshal private key: %w", err)
	}
	if err := os.WriteFile(path.Join(i.StoragePath, akFile), ak, 0600); err != nil {
		return fmt.Errorf("failed to write %v: %w", path.Join(i.StoragePath, akFile), err)
	}
	return nil
}
