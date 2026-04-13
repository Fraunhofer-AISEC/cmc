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
	"strings"

	"flag"

	// local modules

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"golang.org/x/exp/maps"
)

type Config struct {
	CmcAddr          string   `json:"cmcAddr,omitempty"`
	ProvisionToken   string   `json:"provisionToken,omitempty"`
	ProvisionAuth    []string `json:"provisionAuth,omitempty"`
	EndorsementMode  string   `json:"endorsementMode,omitempty"`
	EndorsementAddr  string   `json:"endorsementAddr,omitempty"`
	EnrollmentMode   string   `json:"enrollmentMode,omitempty"`
	EnrollmentAddr   string   `json:"enrollmentAddr,omitempty"`
	MetadataLocation []string `json:"metadata,omitempty"`
	Drivers          []string `json:"drivers,omitempty"`
	ExcludePcrs      []int    `json:"excludePcrs,omitempty"`
	HashAlg          string   `json:"hashAlg,omitempty"`
	Api              string   `json:"api,omitempty"`
	PolicyEngine     string   `json:"policyEngine,omitempty"`
	PolicyOverwrite  bool     `json:"policyOverwrite,omitempty"`
	Storage          string   `json:"storage,omitempty"`
	Cache            string   `json:"cache,omitempty"`
	PeerCache        string   `json:"peerCache,omitempty"`
	MeasurementLogs  bool     `json:"measurementLogs,omitempty"`
	Ctr              bool     `json:"ctr,omitempty"`
	CtrDriver        string   `json:"ctrDriver,omitempty"`
	CtrLog           string   `json:"ctrLog,omitempty"`
	RootCas          []string `json:"rootCas,omitempty"`
	AllowSystemCerts bool     `json:"allowSystemCerts"`
	Vmpl             int      `json:"vmpl,omitempty"`
	SnpCache         string   `json:"snpCache,omitempty"`
	TpmKeyAlg        string   `json:"tpmKeyAlg,omitempty"`
}

const (
	cmcAddrFlag          = "cmcaddr"
	ProvisionTokenFlag   = "provisiontoken"
	ProvisionAuthFlag    = "provisionauth"
	EndorsementModeFlag  = "endorsementmode"
	EndorsementAddrFlag  = "endorsementaddr"
	EnrollmentModeFlag   = "enrollmentmode"
	EnrollmentAddrFlag   = "enrollmentaddr"
	metadataFlag         = "metadata"
	DriversFlag          = "drivers"
	ImaFlag              = "ima"
	ImaPcrFlag           = "imapcr"
	ExcludePcrsFlag      = "excludepcrs"
	HashAlgFlag          = "hashalg"
	ApiFlag              = "api"
	PolicyEngineFlag     = "policyengine"
	PolicyOverwriteFlag  = "policyoverwrite"
	StorageFlag          = "storage"
	CacheFlag            = "cache"
	PeerCacheFlag        = "peercache"
	MeasurementLogsFlag  = "measurementlogs"
	CtrFlag              = "ctr"
	CtrDriverFlag        = "ctrdriver"
	CtrLogFlag           = "ctrlog"
	RootCasFlag          = "metadatacas"
	AllowSystemCertsFlag = "allowsystemcerts"
	VmplFlag             = "vmpl"
	snpCacheFlag         = "snpcache"
	tpmKeyAlgFlag        = "tpmkeyalg"
)

var (
	cmcAddr         = flag.String(cmcAddrFlag, "", "CMC server address")
	endorsementMode = flag.String(EndorsementModeFlag, "", "Endorsement Mode. Possible: [direct | est]")
	endorsementAddr = flag.String(EndorsementAddrFlag, "", "Address of the EST endorsement server")
	enrollmentMode  = flag.String(EnrollmentModeFlag, "", "Enrollment Mode. Possible: [acme | est]")
	enrollmentAddr  = flag.String(EnrollmentAddrFlag, "", "Address of the ACME/EST enrollment server")
	provisionToken  = flag.String(ProvisionTokenFlag, "",
		"Bootstrap token for EST client authentication")
	provisionAuth = flag.String(ProvisionAuthFlag, "",
		"Provisioning authentication methods (none,token,certificate,attestation)")
	metadata = flag.String(metadataFlag, "", "List of locations with metadata, starting either "+
		"with file:// for local locations or https:// for remote locations (can be mixed)")
	driversList = flag.String(DriversFlag, "",
		fmt.Sprintf("Drivers for generating attestation reports (comma separated list). "+
			"Possible: %v", strings.Join(maps.Keys(GetDrivers()), ",")))
	excludePcrs = flag.String(ExcludePcrsFlag, "", "TPM PCRs to be excluded from the quote "+
		"(comma-separated list)")
	hashAlg      = flag.String(HashAlgFlag, "", "Hash algorithm for attestation report integrity")
	cmcApi       = flag.String(ApiFlag, "", "API to use. Possible: [coap grpc libapi socket]")
	policyEngine = flag.String(PolicyEngineFlag, "",
		fmt.Sprintf("Possible policy engines: %v",
			strings.Join(maps.Keys(GetPolicyEngines()), ",")))
	policyOverwrite = flag.Bool(PolicyOverwriteFlag, false,
		"Specifies whether attestation policies can overwrite attestation result properties. "+
			"This should be used with care, as it can overwrite the entire attestation process")
	storage   = flag.String(StorageFlag, "", "Optional folder to store internal CMC data in")
	cache     = flag.String(CacheFlag, "", "Optional folder to cache metadata for offline backup")
	peerCache = flag.String(PeerCacheFlag, "",
		"Optional folder to cache peer metadata to reduce attestation report size")
	measurementLogs = flag.Bool(MeasurementLogsFlag, false,
		"Specifies whether to include measured events in measurement and validation report")
	ctr       = flag.Bool(CtrFlag, false, "Specifies whether to conduct container measurements")
	ctrDriver = flag.String(CtrDriverFlag, "",
		"Specifies which driver to use for container measurements")
	ctrLog           = flag.String(CtrLogFlag, "", "Container runtime measurements path")
	rootCas          = flag.String(RootCasFlag, "", "Paths to trusted root CAs")
	allowSystemCerts = flag.Bool(AllowSystemCertsFlag, false,
		"Allow using the system cert pool as trusted root CAs")
	vmpl     = flag.Int(VmplFlag, 0, "SNP Virtual Machine Privilege Level (VMPL)")
	snpCache = flag.String(snpCacheFlag, "",
		"Optional folder for caching SNP VCEKs and CAs in direct endorsement mode")
	tpmKeyAlg = flag.String(tpmKeyAlgFlag, "", "TPM AK key algorithm (EC256, RSA2048)")
)

// GetConfig retrieves the cmc configuration from commandline flags
func GetConfig(c *Config) error {

	flag.Parse()

	// Overwrite config file configuration with given command line arguments
	if internal.FlagPassed(cmcAddrFlag) {
		c.CmcAddr = *cmcAddr
	}
	if internal.FlagPassed(metadataFlag) {
		c.MetadataLocation = strings.Split(*metadata, ",")
	}
	if internal.FlagPassed(DriversFlag) {
		c.Drivers = strings.Split(*driversList, ",")
	}
	if internal.FlagPassed(ExcludePcrsFlag) {
		excludePcrs, err := internal.StrToInt(strings.Split(*excludePcrs, ","))
		if err != nil {
			return fmt.Errorf("failed to convert excluded PCRs: %w", err)
		}
		c.ExcludePcrs = excludePcrs
	}
	if internal.FlagPassed(HashAlgFlag) {
		c.HashAlg = *hashAlg
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
	if internal.FlagPassed(MeasurementLogsFlag) {
		c.MeasurementLogs = *measurementLogs
	}
	if internal.FlagPassed(CtrFlag) {
		c.Ctr = *ctr
	}
	if internal.FlagPassed(CtrDriverFlag) {
		c.CtrDriver = *ctrDriver
	}
	if internal.FlagPassed(CtrLogFlag) {
		c.CtrLog = *ctrLog
	}
	if internal.FlagPassed(RootCasFlag) {
		c.RootCas = strings.Split(*rootCas, ",")
	}
	if internal.FlagPassed(AllowSystemCertsFlag) {
		c.AllowSystemCerts = *allowSystemCerts
	}
	if internal.FlagPassed(VmplFlag) {
		c.Vmpl = *vmpl
	}
	if internal.FlagPassed(ProvisionTokenFlag) {
		c.ProvisionToken = *provisionToken
	}
	if internal.FlagPassed(ProvisionAuthFlag) {
		c.ProvisionAuth = strings.Split(*provisionAuth, ",")
	}
	if internal.FlagPassed(EndorsementModeFlag) {
		c.EndorsementMode = *endorsementMode
	}
	if internal.FlagPassed(EndorsementAddrFlag) {
		c.EndorsementAddr = *endorsementAddr
	}
	if internal.FlagPassed(EnrollmentModeFlag) {
		c.EnrollmentMode = *enrollmentMode
	}
	if internal.FlagPassed(EnrollmentAddrFlag) {
		c.EnrollmentAddr = *enrollmentAddr
	}
	if internal.FlagPassed(snpCacheFlag) {
		c.SnpCache = *snpCache
	}
	if internal.FlagPassed(tpmKeyAlgFlag) {
		c.TpmKeyAlg = *tpmKeyAlg
	}

	return nil
}

func (c *Config) Print() {

	log.Debugf("Using the following cmc configuration:")
	log.Debugf("\tCMC listen address             : %v", c.CmcAddr)
	log.Debugf("\tProvision authentication       : %v", strings.Join(c.ProvisionAuth, ","))
	if c.ProvisionToken != "" {
		log.Debugf("\tProvisioning token             : %v", c.ProvisionToken)
	}
	log.Debugf("\tEndorsement mode               : %v", c.EndorsementMode)
	log.Debugf("\tEndorsement server URL         : %v", c.EndorsementAddr)
	log.Debugf("\tEnrollment mode                : %v", c.EnrollmentMode)
	log.Debugf("\tEnrollment server URL          : %v", c.EnrollmentAddr)
	log.Debugf("\tMetadata locations             : %v", strings.Join(c.MetadataLocation, ","))
	if len(c.ExcludePcrs) > 0 {
		log.Debugf("\tExclude TPM PCRs               : %v", c.ExcludePcrs)
	}
	log.Debugf("\tAPI                            : %v", c.Api)
	log.Debugf("\tPolicy engine                  : %v", c.PolicyEngine)
	log.Debugf("\tPolicy overwrite enabled       : %v", c.PolicyOverwrite)
	log.Debugf("\tHash algorithm                 : %v", c.HashAlg)
	log.Debugf("\tDrivers                        : %v", strings.Join(c.Drivers, ","))
	log.Debugf("\tMeasurement log                : %v", c.MeasurementLogs)
	log.Debugf("\tMeasure containers             : %v", c.Ctr)
	if c.Ctr {
		log.Debugf("\tContainer driver               : %v", c.CtrDriver)
		log.Debugf("\tContainer measurements         : %v", c.CtrLog)
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
	log.Debugf("\tMetadata root CA paths         : %v", strings.Join(c.RootCas, ","))
	log.Debugf("\tAllow system root CAs:         : %v", c.AllowSystemCerts)
	log.Debugf("\tSNP VCEK and CA cache folder   : %v", c.SnpCache)
	log.Debugf("\tTPM AK key algorithm           : %v", c.TpmKeyAlg)

}
