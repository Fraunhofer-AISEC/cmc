// Copyright (c) 2021 -2024 Fraunhofer AISEC
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
	"path/filepath"
	"runtime/debug"
	"strings"

	"flag"

	// local modules

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"golang.org/x/exp/maps"
)

type Config struct {
	CmcAddr        string   `json:"cmcAddr,omitempty"`
	ProvAddr       string   `json:"provAddr,omitempty"`
	Metadata       []string `json:"metadata,omitempty"`
	Drivers        []string `json:"drivers,omitempty"`
	Ima            bool     `json:"ima,omitempty"`
	ImaPcr         int      `json:"imaPcr,omitempty"`
	KeyConfig      string   `json:"keyConfig,omitempty"`
	Api            string   `json:"api,omitempty"`
	PolicyEngine   string   `json:"policyEngine,omitempty"`
	Storage        string   `json:"storage,omitempty"`
	Cache          string   `json:"cache,omitempty"`
	PeerCache      string   `json:"peerCache,omitempty"`
	MeasurementLog bool     `json:"measurementLog,omitempty"`
	Ctr            bool     `json:"ctr,omitempty"`
	CtrDriver      string   `json:"ctrDriver,omitempty"`
	CtrPcr         int      `json:"ctrPcr,omitempty"`
	CtrLog         string   `json:"ctrLog,omitempty"`
	EstTlsCas      []string `json:"estTlsCas,omitempty"`
	EstTlsSysRoots bool     `json:"estTlsSysRoots"`
	Vmpl           int      `json:"vmpl"`
}

const (
	cmcAddrFlag        = "cmcaddr"
	provAddrFlag       = "provaddr"
	metadataFlag       = "metadata"
	DriversFlag        = "drivers"
	ImaFlag            = "ima"
	ImaPcrFlag         = "imapcr"
	KeyConfigFlag      = "keyconfig"
	ApiFlag            = "api"
	PolicyEngineFlag   = "policyengine"
	StorageFlag        = "storage"
	CacheFlag          = "cache"
	PeerCacheFlag      = "peercache"
	MeasurementLogFlag = "measurementlog"
	CtrFlag            = "ctr"
	CtrDriverFlag      = "ctrdriver"
	CtrPcrFlag         = "ctrpcr"
	CtrLogFlag         = "ctrlog"
	EstTlsCasFlag      = "esttlscas"
	EstTlsSysRootsFlag = "esttlssysroots"
	VmplFlag           = "vmpl"
)

var (
	cmcAddr  = flag.String(cmcAddrFlag, "", "CMC server address")
	provAddr = flag.String(provAddrFlag, "", "Address of the provisioning server")
	metadata = flag.String(metadataFlag, "", "List of locations with metadata, starting either "+
		"with file:// for local locations or https:// for remote locations (can be mixed)")
	driversList = flag.String(DriversFlag, "",
		fmt.Sprintf("Drivers (comma separated list). Possible: %v",
			strings.Join(maps.Keys(GetDrivers()), ",")))
	ima = flag.Bool(ImaFlag, false,
		"Specifies whether to use Integrity Measurement Architecture (IMA)")
	imaPcr       = flag.Int(ImaPcrFlag, 0, "IMA PCR")
	keyConfig    = flag.String(KeyConfigFlag, "", "Key configuration")
	cmcApi       = flag.String(ApiFlag, "", "API to use. Possible: [coap grpc libapi socket]")
	policyEngine = flag.String(PolicyEngineFlag, "",
		fmt.Sprintf("Possible policy engines: %v",
			strings.Join(maps.Keys(GetPolicyEngines()), ",")))
	storage   = flag.String(StorageFlag, "", "Optional folder to store internal CMC data in")
	cache     = flag.String(CacheFlag, "", "Optional folder to cache metadata for offline backup")
	peerCache = flag.String(PeerCacheFlag, "",
		"Optional folder to cache peer metadata to reduce attestation report size")
	measurementLog = flag.Bool(MeasurementLogFlag, false,
		"Specifies whether to include measured events in measurement and validation report")
	ctr       = flag.Bool(CtrFlag, false, "Specifies whether to conduct container measurements")
	ctrDriver = flag.String(CtrDriverFlag, "",
		"Specifies which driver to use for container measurements")
	ctrPcr         = flag.Int(CtrPcrFlag, 0, "Container PCR")
	ctrLog         = flag.String(CtrLogFlag, "", "Container runtime measurements path")
	estTlsCas      = flag.String(EstTlsCasFlag, "", "Path to the EST TLS CA certificates")
	estTlsSysRoots = flag.Bool(EstTlsSysRootsFlag, false, "Use system root CAs for EST TLS")
	vmpl           = flag.Int(VmplFlag, 0, "SNP Virtual Machine Privilege Level (VMPL)")
)

// GetConfig retrieves the cmc configuration from commandline flags
func GetConfig(c *Config) error {

	flag.Parse()

	// Overwrite config file configuration with given command line arguments
	if internal.FlagPassed(cmcAddrFlag) {
		c.CmcAddr = *cmcAddr
	}
	if internal.FlagPassed(provAddrFlag) {
		c.ProvAddr = *provAddr
	}
	if internal.FlagPassed(metadataFlag) {
		c.Metadata = strings.Split(*metadata, ",")
	}
	if internal.FlagPassed(DriversFlag) {
		c.Drivers = strings.Split(*driversList, ",")
	}
	if internal.FlagPassed(ImaFlag) {
		c.Ima = *ima
	}
	if internal.FlagPassed(ImaPcrFlag) {
		c.ImaPcr = *imaPcr
	}
	if internal.FlagPassed(KeyConfigFlag) {
		c.KeyConfig = *keyConfig
	}
	if internal.FlagPassed(ApiFlag) {
		c.Api = *cmcApi
	}
	if internal.FlagPassed(PolicyEngineFlag) {
		c.PolicyEngine = *policyEngine
	}
	if internal.FlagPassed(StorageFlag) {
		c.Storage = *storage
	}
	if internal.FlagPassed(CacheFlag) {
		c.Cache = *cache
	}
	if internal.FlagPassed(PeerCacheFlag) {
		c.PeerCache = *peerCache
	}
	if internal.FlagPassed(MeasurementLogFlag) {
		c.MeasurementLog = *measurementLog
	}
	if internal.FlagPassed(CtrFlag) {
		c.Ctr = *ctr
	}
	if internal.FlagPassed(CtrDriverFlag) {
		c.CtrDriver = *ctrDriver
	}
	if internal.FlagPassed(CtrPcrFlag) {
		c.CtrPcr = *ctrPcr
	}
	if internal.FlagPassed(CtrLogFlag) {
		c.CtrLog = *ctrLog
	}
	if internal.FlagPassed(EstTlsCasFlag) {
		c.EstTlsCas = strings.Split(*estTlsCas, ",")
	}
	if internal.FlagPassed(EstTlsSysRootsFlag) {
		c.EstTlsSysRoots = *estTlsSysRoots
	}
	if internal.FlagPassed(VmplFlag) {
		c.Vmpl = *vmpl
	}

	// Convert all paths to absolute paths
	pathsToAbs(c)

	return nil
}

func GetVersion() string {
	version := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		if strings.EqualFold(info.Main.Version, "(devel)") {
			commit := "unknown"
			created := "unknown"
			for _, elem := range info.Settings {
				if strings.EqualFold(elem.Key, "vcs.revision") {
					commit = elem.Value
				}
				if strings.EqualFold(elem.Key, "vcs.time") {
					created = elem.Value
				}
			}
			version = fmt.Sprintf("%v, commit %v, created %v", info.Main.Version, commit, created)
		} else {
			version = info.Main.Version
		}
	}
	return version
}

func pathsToAbs(c *Config) {
	var err error
	if c.Storage != "" {
		c.Storage, err = filepath.Abs(c.Storage)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.Storage, err)
		}
	}
	if c.Cache != "" {
		c.Cache, err = filepath.Abs(c.Cache)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.Cache, err)
		}
	}
	if c.PeerCache != "" {
		c.PeerCache, err = filepath.Abs(c.PeerCache)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.Cache, err)
		}
	}
	for i := 0; i < len(c.Metadata); i++ {
		if strings.HasPrefix(c.Metadata[i], "file://") {
			f := strings.TrimPrefix(c.Metadata[i], "file://")
			f, err = filepath.Abs(f)
			if err != nil {
				log.Warnf("Failed to get absolute path for %v: %v", f, err)
				continue
			}
			c.Metadata[i] = "file://" + f
		}
	}
	if c.CtrLog != "" {
		c.CtrLog, err = filepath.Abs(c.CtrLog)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.CtrLog, err)
		}
	}
	for i := 0; i < len(c.EstTlsCas); i++ {
		c.EstTlsCas[i], err = filepath.Abs(c.EstTlsCas[i])
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.EstTlsCas[i], err)
		}
	}
}

func (c *Config) Print() {

	log.Debugf("Using the following cmc configuration:")
	log.Debugf("\tCMC listen address             : %v", c.CmcAddr)
	log.Debugf("\tProvisioning server URL        : %v", c.ProvAddr)
	log.Debugf("\tMetadata locations             : %v", strings.Join(c.Metadata, ","))
	log.Debugf("\tUse IMA                        : %v", c.Ima)
	if c.Ima {
		log.Debugf("\tIMA PCR                        : %v", c.ImaPcr)
	}
	log.Debugf("\tAPI                            : %v", c.Api)
	log.Debugf("\tPolicy engine                  : %v", c.PolicyEngine)
	log.Debugf("\tKey config                     : %v", c.KeyConfig)
	log.Debugf("\tDrivers                        : %v", strings.Join(c.Drivers, ","))
	log.Debugf("\tMeasurement log                : %v", c.MeasurementLog)
	log.Debugf("\tMeasure containers             : %v", c.Ctr)
	if c.Ctr {
		log.Debugf("\tContainer driver               : %v", c.CtrDriver)
		log.Debugf("\tContainer measurements         : %v", c.CtrLog)
		log.Debugf("\tContainer PCR                  : %v", c.CtrPcr)
	}
	if c.Storage != "" {
		log.Debugf("\tInternal storage path          : %v", c.Storage)
	}
	if c.Cache != "" {
		log.Debugf("\tMetadata cache path            : %v", c.Cache)
	}
	if c.PeerCache != "" {
		log.Debugf("\tPeer cache path                : %v", c.PeerCache)
	}
	for _, ca := range c.EstTlsCas {
		log.Debugf("\tEST TLS CA path                : %v", ca)
	}
	log.Debugf("\tUse system root CAs for EST TLS: %v", c.EstTlsSysRoots)
}
