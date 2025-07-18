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

package cmc

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
)

var (
	log = logrus.WithField("service", "cmc")

	policyEngines = map[string]verifier.PolicyEngineSelect{
		"js":      verifier.PolicyEngineSelect_JS,
		"duktape": verifier.PolicyEngineSelect_DukTape,
	}

	drivers = map[string]ar.Driver{}
)

type Cmc struct {
	IdentityCas        []*x509.Certificate
	MetadataCas        []*x509.Certificate
	Metadata           map[string][]byte
	CachedPeerMetadata map[string]map[string][]byte
	PolicyEngineSelect verifier.PolicyEngineSelect
	Drivers            []ar.Driver
	Serializer         ar.Serializer
	PeerCache          string
	Ctr                bool
	CtrDriver          string
	CtrPcr             int
	CtrLog             string
}

func GetDrivers() map[string]ar.Driver {
	return drivers
}

func GetPolicyEngines() map[string]verifier.PolicyEngineSelect {
	return policyEngines
}

func NewCmc(c *Config) (*Cmc, error) {

	// Read trusted root CAs for EST server TLS authentication, IKs and metadata
	estTlsCas, err := internal.ReadCerts(c.EstTlsCas)
	if err != nil {
		return nil, fmt.Errorf("failed to read EST TLS CA certificates: %w", err)
	}
	identityCas, err := internal.ReadCerts(c.IdentityCas)
	if err != nil {
		return nil, fmt.Errorf("failed to read trusted identity root CAs: %w", err)
	}
	metadataCas, err := internal.ReadCerts(c.MetadataCas)
	if err != nil {
		return nil, fmt.Errorf("failed to read trusted metadata root CAs: %w", err)
	}

	cmc := &Cmc{
		IdentityCas: identityCas,
		MetadataCas: metadataCas,
		PeerCache:   c.PeerCache,
		Ctr:         c.Ctr,
		CtrDriver:   c.CtrDriver,
		CtrPcr:      c.CtrPcr,
		CtrLog:      c.CtrLog,
	}

	// Read metadata and device config from the file system
	metadata, s, err := GetMetadata(c.Metadata, c.Cache, estTlsCas, c.EstTlsSysRoots)
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata: %v", err)
	}

	// Read bootstrap token if present
	var token []byte
	if c.Token != "" {
		token, err = os.ReadFile(c.Token)
		if err != nil {
			return nil, fmt.Errorf("failed to read token: %v", err)
		}
	}

	// If no metadata is specified, the cmc can only work as verifier
	if metadata != nil {

		cmc.Serializer = s
		cmc.Metadata = metadata

		deviceConfig, err := ar.GetDeviceConfig(s, metadata, metadataCas)
		if err != nil {
			return nil, fmt.Errorf("failed to get signed device config: %v", err)
		}

		// Create driver configuration
		driverConf := &ar.DriverConfig{
			StoragePath:      c.Storage,
			ServerAddr:       c.ProvAddr,
			KeyConfig:        c.KeyConfig,
			DeviceConfig:     *deviceConfig,
			Metadata:         metadata,
			Ima:              c.Ima,
			ImaPcr:           c.ImaPcr,
			MeasurementLog:   c.MeasurementLog,
			Serializer:       s,
			CtrPcr:           c.CtrPcr,
			CtrLog:           c.CtrLog,
			CtrDriver:        c.CtrDriver,
			Ctr:              c.Ctr,
			EstTlsCas:        estTlsCas,
			UseSystemRootCas: c.EstTlsSysRoots,
			Vmpl:             c.Vmpl,
			Token:            token,
		}

		// Initialize drivers
		usedDrivers := make([]ar.Driver, 0)
		for _, driver := range c.Drivers {
			d, ok := drivers[strings.ToLower(driver)]
			if !ok {
				return nil, fmt.Errorf("driver %v not implemented", driver)
			}
			err = d.Init(driverConf)
			if err != nil {
				return nil, fmt.Errorf("failed to initialize driver: %w", err)
			}
			usedDrivers = append(usedDrivers, d)
		}
		cmc.Drivers = usedDrivers

		// Check container driver
		if c.Ctr {
			if !internal.Contains(c.CtrDriver, c.Drivers) {
				return nil, fmt.Errorf("cannot use %v as container driver: driver not configured",
					c.CtrDriver)
			}
		}

		// Get policy engine
		sel, ok := policyEngines[strings.ToLower(c.PolicyEngine)]
		if !ok {
			log.Tracef("No optional policy engine selected or %v not implemented", c.PolicyEngine)
		}
		cmc.PolicyEngineSelect = sel
	}

	// Load cached metadata from known peers
	cachedPeerMetadata, err := LoadCacheMetadata(c.PeerCache)
	if err != nil {
		return nil, fmt.Errorf("failed to load peer cache: %w", err)
	}
	cmc.CachedPeerMetadata = cachedPeerMetadata

	return cmc, nil
}
