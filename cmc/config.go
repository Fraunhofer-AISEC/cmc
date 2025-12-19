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
	"strings"

	"flag"

	// local modules

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"golang.org/x/exp/maps"
)

type Config struct {
	CmcAddr         string   `json:"cmcAddr,omitempty"`
	ProvisionAddr   string   `json:"provisionAddr,omitempty"`
	ProvisionMode   string   `json:"provisionMode,omitempty"`
	ProvisionToken  string   `json:"provisionToken,omitempty"`
	ProvisionAuth   []string `json:"provisionAuth,omitempty"`
	Metadata        []string `json:"metadata,omitempty"`
	Drivers         []string `json:"drivers,omitempty"`
	Ima             bool     `json:"ima,omitempty"`
	ImaPcr          int      `json:"imaPcr,omitempty"`
	ExcludePcrs     []int    `json:"excludePcrs,omitempty"`
	KeyConfig       string   `json:"keyConfig,omitempty"`
	Api             string   `json:"api,omitempty"`
	PolicyEngine    string   `json:"policyEngine,omitempty"`
	PolicyOverwrite bool     `json:"policyOverwrite,omitempty"`
	Storage         string   `json:"storage,omitempty"`
	Cache           string   `json:"cache,omitempty"`
	PeerCache       string   `json:"peerCache,omitempty"`
	MeasurementLog  bool     `json:"measurementLog,omitempty"`
	Ctr             bool     `json:"ctr,omitempty"`
	CtrDriver       string   `json:"ctrDriver,omitempty"`
	CtrPcr          int      `json:"ctrPcr,omitempty"`
	CtrLog          string   `json:"ctrLog,omitempty"`
	IdentityCas     []string `json:"identityCas,omitempty"`
	MetadataCas     []string `json:"metadataCas,omitempty"`
	EstTlsCas       []string `json:"estTlsCas,omitempty"`
	EstTlsSysRoots  bool     `json:"estTlsSysRoots"`
	Vmpl            int      `json:"vmpl,omitempty"`
	VerifyEkCert    bool     `json:"verifyEkCert,omitempty"`
	TpmEkCertDb     string   `json:"tpmEkCertDb,omitempty"`
	CaKey           string   `json:"caKey,omitempty"`
}

const (
	provisionModeEst        = "est"
	provisionModeSelfSigned = "selfsigned"
)

const (
	cmcAddrFlag         = "cmcaddr"
	ProvisionModeFlag   = "provisionmode"
	provisionAddrFlag   = "provisionaddr"
	ProvisionTokenFlag  = "provisiontoken"
	ProvisionAuthFlag   = "provisionauth"
	metadataFlag        = "metadata"
	DriversFlag         = "drivers"
	ImaFlag             = "ima"
	ImaPcrFlag          = "imapcr"
	ExcludePcrsFlag     = "excludepcrs"
	KeyConfigFlag       = "keyconfig"
	ApiFlag             = "api"
	PolicyEngineFlag    = "policyengine"
	PolicyOverwriteFlag = "policyoverwrite"
	StorageFlag         = "storage"
	CacheFlag           = "cache"
	PeerCacheFlag       = "peercache"
	MeasurementLogFlag  = "measurementlog"
	CtrFlag             = "ctr"
	CtrDriverFlag       = "ctrdriver"
	CtrPcrFlag          = "ctrpcr"
	CtrLogFlag          = "ctrlog"
	IdentityCasFlag     = "identitycas"
	MetadataCasFlag     = "metadatacas"
	EstTlsCasFlag       = "esttlscas"
	EstTlsSysRootsFlag  = "esttlssysroots"
	VmplFlag            = "vmpl"
	verifyEkCertFlag    = "verifyekcert"
	tpmEkCertDbFlag     = "tpmekcertdb"
	caKeyFlag           = "cakey"
)

var (
	cmcAddr       = flag.String(cmcAddrFlag, "", "CMC server address")
	provisionMode = flag.String(ProvisionModeFlag, "",
		fmt.Sprintf("Provisioning Mode. Possible: [%v %v]",
			provisionModeEst, provisionModeSelfSigned))
	provisionAddr  = flag.String(provisionAddrFlag, "", "Address of the provisioning server")
	provisionToken = flag.String(ProvisionTokenFlag, "",
		"Bootstrap token for EST client authentication")
	provisionAuth = flag.String(ProvisionAuthFlag, "",
		"Provisioning authentication methods (none,token,certificate,attestation)")
	metadata = flag.String(metadataFlag, "", "List of locations with metadata, starting either "+
		"with file:// for local locations or https:// for remote locations (can be mixed)")
	driversList = flag.String(DriversFlag, "",
		fmt.Sprintf("Drivers for generating attestation reports (comma separated list). "+
			"Possible: %v", strings.Join(maps.Keys(GetDrivers()), ",")))
	ima = flag.Bool(ImaFlag, false,
		"Specifies whether to use Integrity Measurement Architecture (IMA)")
	imaPcr      = flag.Int(ImaPcrFlag, 0, "IMA PCR")
	excludePcrs = flag.String(ExcludePcrsFlag, "", "TPM PCRs to be excluded from the quote "+
		"(comma-separated list)")
	keyConfig    = flag.String(KeyConfigFlag, "", "Key configuration")
	cmcApi       = flag.String(ApiFlag, "", "API to use. Possible: [coap grpc libapi socket]")
	policyEngine = flag.String(PolicyEngineFlag, "",
		fmt.Sprintf("Possible policy engines: %v",
			strings.Join(maps.Keys(GetPolicyEngines()), ",")))
	policyOverwrite = flag.Bool(PolicyOverwriteFlag, false,
		"Specifies whether attestation policies can overwrite verification result properties. "+
			"This should be used with care, as it can overwrite the entire attestation process")
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
	identityCas    = flag.String(IdentityCasFlag, "", "Paths to trusted identity root CAs")
	metadataCas    = flag.String(MetadataCasFlag, "", "Paths to trusted metadata root CAs")
	estTlsCas      = flag.String(EstTlsCasFlag, "", "Path to the EST TLS CA certificates")
	estTlsSysRoots = flag.Bool(EstTlsSysRootsFlag, false, "Use system root CAs for EST TLS")
	vmpl           = flag.Int(VmplFlag, 0, "SNP Virtual Machine Privilege Level (VMPL)")
	verifyEkCert   = flag.Bool(verifyEkCertFlag, false,
		"Self-signed mode only: Indicates whether to verify TPM EK certificate chains")
	tpmEkCertDb = flag.String(tpmEkCertDbFlag, "",
		"Self-signed mode only: Database for EK cert chain verification")
	caKey = flag.String(caKeyFlag, "", "Self-signed mode only: CA key")
)

// GetConfig retrieves the cmc configuration from commandline flags
func GetConfig(c *Config) error {

	flag.Parse()

	// Overwrite config file configuration with given command line arguments
	if internal.FlagPassed(cmcAddrFlag) {
		c.CmcAddr = *cmcAddr
	}
	if internal.FlagPassed(provisionAddrFlag) {
		c.ProvisionAddr = *provisionAddr
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
	if internal.FlagPassed(ExcludePcrsFlag) {
		excludePcrs, err := internal.StrToInt(strings.Split(*excludePcrs, ","))
		if err != nil {
			return fmt.Errorf("failed to convert excluded PCRs: %w", err)
		}
		c.ExcludePcrs = excludePcrs
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
	if internal.FlagPassed(PolicyOverwriteFlag) {
		c.PolicyOverwrite = *policyOverwrite
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
	if internal.FlagPassed(IdentityCasFlag) {
		c.IdentityCas = strings.Split(*identityCas, ",")
	}
	if internal.FlagPassed(MetadataCasFlag) {
		c.MetadataCas = strings.Split(*metadataCas, ",")
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
	if internal.FlagPassed(ProvisionTokenFlag) {
		c.ProvisionToken = *provisionToken
	}
	if internal.FlagPassed(ProvisionModeFlag) {
		c.ProvisionMode = *provisionMode
	}
	if internal.FlagPassed(ProvisionAuthFlag) {
		c.ProvisionAuth = strings.Split(*provisionAuth, ",")
	}
	if internal.FlagPassed(verifyEkCertFlag) {
		c.VerifyEkCert = *verifyEkCert
	}
	if internal.FlagPassed(tpmEkCertDbFlag) {
		c.TpmEkCertDb = *tpmEkCertDb
	}
	if internal.FlagPassed(caKeyFlag) {
		c.CaKey = *caKey
	}

	// Convert all paths to absolute paths
	pathsToAbs(c)

	return nil
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
	for i := 0; i < len(c.IdentityCas); i++ {
		c.IdentityCas[i], err = filepath.Abs(c.IdentityCas[i])
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.IdentityCas[i], err)
		}
	}
	for i := 0; i < len(c.MetadataCas); i++ {
		c.MetadataCas[i], err = filepath.Abs(c.MetadataCas[i])
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.MetadataCas[i], err)
		}
	}
	for i := 0; i < len(c.EstTlsCas); i++ {
		c.EstTlsCas[i], err = filepath.Abs(c.EstTlsCas[i])
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.EstTlsCas[i], err)
		}
	}
	if c.ProvisionToken != "" {
		c.ProvisionToken, err = filepath.Abs(c.ProvisionToken)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.Cache, err)
		}
	}
	if c.CaKey != "" {
		c.CaKey, err = filepath.Abs(c.CaKey)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.CaKey, err)
		}
	}
}

func (c *Config) Print() {

	log.Debugf("Using the following cmc configuration:")
	log.Debugf("\tCMC listen address             : %v", c.CmcAddr)
	log.Debugf("\tProvision mode                 : %v", c.ProvisionMode)
	log.Debugf("\tProvision authentication       : %v", strings.Join(c.ProvisionAuth, ","))
	log.Debugf("\tProvisioning server URL        : %v", c.ProvisionAddr)
	if c.ProvisionToken != "" {
		log.Debugf("\tProvisioning token             : %v", c.ProvisionToken)
	}
	log.Debugf("\tMetadata locations             : %v", strings.Join(c.Metadata, ","))
	log.Debugf("\tUse IMA                        : %v", c.Ima)
	if c.Ima {
		log.Debugf("\tIMA PCR                        : %v", c.ImaPcr)
	}
	if len(c.ExcludePcrs) > 0 {
		log.Debugf("\tExclude TPM PCRs               : %v", c.ExcludePcrs)
	}
	log.Debugf("\tAPI                            : %v", c.Api)
	log.Debugf("\tPolicy engine                  : %v", c.PolicyEngine)
	log.Debugf("\tPolicy overwrite enabled       : %v", c.PolicyOverwrite)
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
	log.Debugf("\tIdentity root CA paths         : %v", strings.Join(c.EstTlsCas, ","))
	log.Debugf("\tMetadata root CA paths         : %v", strings.Join(c.EstTlsCas, ","))
	log.Debugf("\tEST TLS root CA paths          : %v", strings.Join(c.EstTlsCas, ","))
	log.Debugf("\tUse system root CAs for EST TLS: %v", c.EstTlsSysRoots)
	if strings.EqualFold(c.ProvisionMode, provisionModeSelfSigned) {
		log.Debugf("\tVerify EK Cert                 : %v", c.VerifyEkCert)
		log.Debugf("\tTPM EK DB                      : %v", c.TpmEkCertDb)
		log.Debugf("\tCA Key                         : %v", c.CaKey)
	}
}
