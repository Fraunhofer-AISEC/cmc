// Copyright (c) 2021 - 2026 Fraunhofer AISEC
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

package cmcflags

import (
	"fmt"
	"strings"

	"github.com/urfave/cli/v3"
	"golang.org/x/exp/maps"

	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

const (
	CmcAddrFlag          = "cmc-addr"
	ProvisionTokenFlag   = "provision-token"
	ProvisionAuthFlag    = "provision-auth"
	EndorsementModeFlag  = "endorsement-mode"
	EndorsementAddrFlag  = "endorsement-addr"
	EnrollmentModeFlag   = "enrollment-mode"
	EnrollmentAddrFlag   = "enrollment-addr"
	MetadataFlag         = "metadata"
	DriversFlag          = "drivers"
	ExcludePcrsFlag      = "exclude-pcrs"
	HashAlgFlag          = "hash-alg"
	ApiFlag              = "api"
	PolicyEngineFlag     = "policy-engine"
	PolicyOverwriteFlag  = "policy-overwrite"
	StorageFlag          = "storage"
	CacheFlag            = "cache"
	PeerCacheFlag        = "peer-cache"
	MeasurementLogsFlag  = "measurement-logs"
	CtrFlag              = "ctr"
	CtrDriverFlag        = "ctr-driver"
	CtrLogFlag           = "ctr-log"
	RootCasFlag          = "root-cas"
	AllowSystemCertsFlag = "allow-system-certs"
	VmplFlag             = "vmpl"
	SnpCacheFlag         = "snp-cache"
	TpmKeyAlgFlag        = "tpm-key-alg"
	UseOmspFlag          = "use-omsp"
	OmspFormatFlag       = "omsp-format"
)

var Flags = []cli.Flag{
	&cli.StringFlag{
		Name:  CmcAddrFlag,
		Usage: "CMC server address",
	},
	&cli.StringFlag{
		Name:  ProvisionTokenFlag,
		Usage: "bootstrap token for EST client authentication",
	},
	&cli.StringFlag{
		Name:  ProvisionAuthFlag,
		Usage: "provisioning authentication methods (none,token,certificate,attestation)",
	},
	&cli.StringFlag{
		Name:  EndorsementModeFlag,
		Usage: "endorsement mode [direct, est]",
	},
	&cli.StringFlag{
		Name:  EndorsementAddrFlag,
		Usage: "address of the EST endorsement server",
	},
	&cli.StringFlag{
		Name:  EnrollmentModeFlag,
		Usage: "enrollment mode [acme, est]",
	},
	&cli.StringFlag{
		Name:  EnrollmentAddrFlag,
		Usage: "address of the ACME/EST enrollment server",
	},
	&cli.StringFlag{
		Name:  MetadataFlag,
		Usage: "comma-separated list of metadata locations (file://, https://, or blob://)",
	},
	&cli.StringFlag{
		Name: DriversFlag,
		Usage: fmt.Sprintf("comma-separated list of attestation report drivers. Possible: %v",
			strings.Join(maps.Keys(cmc.GetDrivers()), ",")),
	},
	&cli.StringFlag{
		Name:  ExcludePcrsFlag,
		Usage: "comma-separated list of TPM PCRs to exclude from the quote",
	},
	&cli.StringFlag{
		Name:  HashAlgFlag,
		Usage: "hash algorithm for attestation report integrity",
	},
	&cli.StringFlag{
		Name:  ApiFlag,
		Usage: "API to use [coap, grpc, libapi, socket]",
	},
	&cli.StringFlag{
		Name: PolicyEngineFlag,
		Usage: fmt.Sprintf("policy engine: %v",
			strings.Join(maps.Keys(cmc.GetPolicyEngines()), ",")),
	},
	&cli.BoolFlag{
		Name:  PolicyOverwriteFlag,
		Usage: "allow attestation policies to overwrite attestation result properties",
	},
	&cli.StringFlag{
		Name:  StorageFlag,
		Usage: "folder to store internal CMC data",
	},
	&cli.StringFlag{
		Name:  CacheFlag,
		Usage: "folder to cache metadata for offline backup",
	},
	&cli.StringFlag{
		Name:  PeerCacheFlag,
		Usage: "folder to cache peer metadata to reduce attestation report size",
	},
	&cli.BoolFlag{
		Name:  MeasurementLogsFlag,
		Usage: "include measured events in measurement and validation report",
	},
	&cli.BoolFlag{
		Name:  CtrFlag,
		Usage: "conduct container measurements",
	},
	&cli.StringFlag{
		Name:  CtrDriverFlag,
		Usage: "driver to use for container measurements",
	},
	&cli.StringFlag{
		Name:  CtrLogFlag,
		Usage: "container runtime measurements path",
	},
	&cli.StringFlag{
		Name:  RootCasFlag,
		Usage: "comma-separated paths to trusted root CA PEM files",
	},
	&cli.BoolFlag{
		Name:  AllowSystemCertsFlag,
		Usage: "allow using the system cert pool as trusted root CAs",
	},
	&cli.IntFlag{
		Name:  VmplFlag,
		Usage: "SNP Virtual Machine Privilege Level (VMPL)",
	},
	&cli.StringFlag{
		Name:  SnpCacheFlag,
		Usage: "folder for caching SNP VCEKs and CAs in direct endorsement mode",
	},
	&cli.StringFlag{
		Name:  TpmKeyAlgFlag,
		Usage: "TPM AK key algorithm (EC256, RSA2048)",
	},
	&cli.BoolFlag{
		Name:  UseOmspFlag,
		Usage: "Indicates whether to use revocation information for manifests",
	},
	&cli.StringFlag{
		Name:  OmspFormatFlag,
		Usage: "Indicates which serialization format to use for revocation information for manifests. Possible: [json | cbor]",
	},
}

// Override applies CLI flag values to the given cmc.Config, only overwriting
// fields for flags that were explicitly set on the command line.
func Override(cmd *cli.Command, c *cmc.Config) error {
	if cmd.IsSet(CmcAddrFlag) {
		c.CmcAddr = cmd.String(CmcAddrFlag)
	}
	if cmd.IsSet(MetadataFlag) {
		c.MetadataLocation = strings.Split(cmd.String(MetadataFlag), ",")
	}
	if cmd.IsSet(DriversFlag) {
		c.Drivers = strings.Split(cmd.String(DriversFlag), ",")
	}
	if cmd.IsSet(ExcludePcrsFlag) {
		excludePcrs, err := internal.StrToInt(strings.Split(cmd.String(ExcludePcrsFlag), ","))
		if err != nil {
			return fmt.Errorf("failed to convert excluded PCRs: %w", err)
		}
		c.ExcludePcrs = excludePcrs
	}
	if cmd.IsSet(HashAlgFlag) {
		c.HashAlg = cmd.String(HashAlgFlag)
	}
	if cmd.IsSet(ApiFlag) {
		c.Api = cmd.String(ApiFlag)
	}
	if cmd.IsSet(PolicyEngineFlag) {
		c.PolicyEngine = cmd.String(PolicyEngineFlag)
	}
	if cmd.IsSet(PolicyOverwriteFlag) {
		c.PolicyOverwrite = cmd.Bool(PolicyOverwriteFlag)
	}
	if cmd.IsSet(StorageFlag) {
		c.Storage = cmd.String(StorageFlag)
	}
	if cmd.IsSet(CacheFlag) {
		c.Cache = cmd.String(CacheFlag)
	}
	if cmd.IsSet(PeerCacheFlag) {
		c.PeerCache = cmd.String(PeerCacheFlag)
	}
	if cmd.IsSet(MeasurementLogsFlag) {
		c.MeasurementLogs = cmd.Bool(MeasurementLogsFlag)
	}
	if cmd.IsSet(CtrFlag) {
		c.Ctr = cmd.Bool(CtrFlag)
	}
	if cmd.IsSet(CtrDriverFlag) {
		c.CtrDriver = cmd.String(CtrDriverFlag)
	}
	if cmd.IsSet(CtrLogFlag) {
		c.CtrLog = cmd.String(CtrLogFlag)
	}
	if cmd.IsSet(RootCasFlag) {
		c.RootCas = strings.Split(cmd.String(RootCasFlag), ",")
	}
	if cmd.IsSet(AllowSystemCertsFlag) {
		c.AllowSystemCerts = cmd.Bool(AllowSystemCertsFlag)
	}
	if cmd.IsSet(VmplFlag) {
		c.Vmpl = int(cmd.Int(VmplFlag))
	}
	if cmd.IsSet(ProvisionTokenFlag) {
		c.ProvisionToken = cmd.String(ProvisionTokenFlag)
	}
	if cmd.IsSet(ProvisionAuthFlag) {
		c.ProvisionAuth = strings.Split(cmd.String(ProvisionAuthFlag), ",")
	}
	if cmd.IsSet(EndorsementModeFlag) {
		c.EndorsementMode = cmd.String(EndorsementModeFlag)
	}
	if cmd.IsSet(EndorsementAddrFlag) {
		c.EndorsementAddr = cmd.String(EndorsementAddrFlag)
	}
	if cmd.IsSet(EnrollmentModeFlag) {
		c.EnrollmentMode = cmd.String(EnrollmentModeFlag)
	}
	if cmd.IsSet(EnrollmentAddrFlag) {
		c.EnrollmentAddr = cmd.String(EnrollmentAddrFlag)
	}
	if cmd.IsSet(SnpCacheFlag) {
		c.SnpCache = cmd.String(SnpCacheFlag)
	}
	if cmd.IsSet(TpmKeyAlgFlag) {
		c.TpmKeyAlg = cmd.String(TpmKeyAlgFlag)
	}
	if cmd.IsSet(UseOmspFlag) {
		c.UseOmsp = cmd.Bool(UseOmspFlag)
	}
	if cmd.IsSet(OmspFormatFlag) {
		c.OmspFormat = cmd.String(OmspFormatFlag)
	}

	return nil
}
