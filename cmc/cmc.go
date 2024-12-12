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
	"fmt"
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

type Config struct {
	Addr           string   `json:"addr,omitempty"`
	ProvServerAddr string   `json:"provServerAddr"`
	Metadata       []string `json:"metadata"`
	Drivers        []string `json:"drivers"`
	UseIma         bool     `json:"useIma"`
	ImaPcr         int      `json:"imaPcr"`
	KeyConfig      string   `json:"keyConfig,omitempty"`
	Api            string   `json:"api"`
	Network        string   `json:"network,omitempty"`
	PolicyEngine   string   `json:"policyEngine,omitempty"`
	LogLevel       string   `json:"logLevel,omitempty"`
	Storage        string   `json:"storage,omitempty"`
	Cache          string   `json:"cache,omitempty"`
	PeerCache      string   `json:"peerCache,omitempty"`
	MeasurementLog bool     `json:"measurementLog,omitempty"`
	// Only for container measurements
	UseCtr    bool   `json:"useCtr,omitempty"`
	CtrDriver string `json:"ctrDriver,omitempty"`
	CtrPcr    int    `json:"ctrPcr,omitempty"`
	CtrLog    string `json:"ctrLog"`
	ExtCtrLog bool   `json:"extendedCtrLog"`
}

type Cmc struct {
	Metadata           map[string][]byte
	CachedPeerMetadata map[string]map[string][]byte
	PolicyEngineSelect verifier.PolicyEngineSelect
	Drivers            []ar.Driver
	Serializer         ar.Serializer
	Network            string
	IntelStorage       string
	PeerCache          string
	UseCtr             bool
	CtrDriver          string
	CtrPcr             int
	CtrLog             string
	ExtCtrLog          bool
}

func GetDrivers() map[string]ar.Driver {
	return drivers
}

func GetPolicyEngines() map[string]verifier.PolicyEngineSelect {
	return policyEngines
}

func NewCmc(c *Config) (*Cmc, error) {

	cmc := &Cmc{
		Network:      c.Network,
		IntelStorage: c.Storage,
		PeerCache:    c.PeerCache,
		UseCtr:       c.UseCtr,
		CtrDriver:    c.CtrDriver,
		CtrPcr:       c.CtrPcr,
		CtrLog:       c.CtrLog,
		ExtCtrLog:    c.ExtCtrLog,
	}

	// Read metadata and device config from the file system
	metadata, s, err := GetMetadata(c.Metadata, c.Cache)
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata: %v", err)
	}

	// If no metadata is specified, the cmc can only work as verifier
	if metadata != nil {

		cmc.Serializer = s
		cmc.Metadata = metadata

		deviceConfig, err := ar.GetDeviceConfig(s, metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to get signed device config: %v", err)
		}

		// Create driver configuration
		driverConf := &ar.DriverConfig{
			StoragePath:    c.Storage,
			ServerAddr:     c.ProvServerAddr,
			KeyConfig:      c.KeyConfig,
			DeviceConfig:   *deviceConfig,
			UseIma:         c.UseIma,
			ImaPcr:         c.ImaPcr,
			MeasurementLog: c.MeasurementLog,
			Serializer:     s,
			CtrPcr:         c.CtrPcr,
			CtrLog:         c.CtrLog,
			ExtCtrLog:      c.ExtCtrLog,
			CtrDriver:      c.CtrDriver,
			UseCtr:         c.UseCtr,
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
		if c.UseCtr {
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
