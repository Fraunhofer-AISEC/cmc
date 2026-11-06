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
	CmcFlag              = "cmc"
	ProvisionTokenFlag   = "provision-token"
	ProvisionAuthFlag    = "provision-auth"
	EndorsementFlag      = "endorsement"
	EnrollmentFlag       = "enrollment"
	MetadataFlag         = "metadata"
	DriversFlag          = "drivers"
	ExcludePcrsFlag      = "exclude-pcrs"
	HashAlgFlag          = "hash-alg"
	PolicyEngineFlag     = "policy-engine"
	PolicyOverwriteFlag  = "policy-overwrite"
	StorageFlag          = "storage"
	MeasurementLogsFlag  = "measurement-logs"
	CtrDriverFlag        = "ctr-driver"
	CtrLogFlag           = "ctr-log"
	RootCasFlag          = "root-cas"
	AllowSystemCertsFlag = "allow-system-certs"
	VmplFlag             = "vmpl"
	TpmKeyAlgFlag        = "tpm-key-alg"
	UseOmspFlag          = "use-omsp"
	OmspFormatFlag       = "omsp-format"
	AppendEbsFlag        = "append-ebs"
)

var Flags = []cli.Flag{
	&cli.StringFlag{
		Name: CmcFlag,
		Usage: "CMC API and address in the form <api>://<address>, e.g. " +
			"socket:///run/cmc/cmc.sock, socket://127.0.0.1:9955, grpc://127.0.0.1:9955 or " +
			"coap://127.0.0.1:9955",
	},
	&cli.StringFlag{
		Name:  ProvisionTokenFlag,
		Usage: "bootstrap token for EST client authentication",
	},
	&cli.StringFlag{
		Name:  ProvisionAuthFlag,
		Usage: "provisioning authentication methods [none token certificate attestation]",
	},
	&cli.StringFlag{
		Name: EndorsementFlag,
		Usage: "endorsement mode for fetching driver certs and collateral, with the server\n" +
			"\t\taddress for the modes that require one [direct host est:<url> cps:<url>]:\n" +
			"\t\tdirect\n" +
			"\t\t\tSNP: fetch AMD SNP VCEK/CA directly from AMD KDS (rate-limited: 10s per request)\n" +
			"\t\t\tTDX: fetch TDX collateral directly from Intel PCS\n" +
			"\t\t\tTPM: Noop endorser. Requires tdx/snp driver (vtpm acts as secondary trust anchor)\n" +
			"\t\tcps:<url>\n" +
			"\t\t\tSNP: Fetch AMD SNP VCEK/CA from custom caching proxy service (CPS)\n" +
			"\t\t\tTDX: Fetch TDX collateral from Provisioning Certififcation Caching Service (PCCS)\n" +
			"\t\t\tTPM: Noop endorser. Requires tdx/snp driver (vtpm acts as secondary trust anchor)\n" +
			"\t\thost:\n" +
			"\t\t\tSNP: Fetch AMD SNP VCEK/CA from the local hypervisor via SNP_GET_EXT_REPORT\n" +
			"\t\test:<url>\n" +
			"\t\t\tTPM: Enroll TPM EK certificate via Enrollment over Secure Transport (EST) server\n",
	},
	&cli.StringFlag{
		Name: EnrollmentFlag,
		Usage: "enrollment mode, with the address of the enrollment server for the modes that " +
			"require one [self est:<url>]",
	},
	&cli.StringFlag{
		Name:  MetadataFlag,
		Usage: "comma-separated list of metadata locations [file:// https:// blob://]",
	},
	&cli.StringFlag{
		Name: DriversFlag,
		Usage: fmt.Sprintf("comma-separated list of attestation report drivers %v",
			maps.Keys(cmc.GetDrivers())),
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
		Name:  PolicyEngineFlag,
		Usage: fmt.Sprintf("policy engine: %v", maps.Keys(cmc.GetPolicyEngines())),
	},
	&cli.BoolFlag{
		Name:  PolicyOverwriteFlag,
		Usage: "allow attestation policies to overwrite attestation result properties",
	},
	&cli.StringFlag{
		Name: StorageFlag,
		Usage: "folder for all data the CMC persists, such as keys, the metadata cache, the " +
			"peer cache and the hardware vendor collateral cache",
	},
	&cli.BoolFlag{
		Name:  MeasurementLogsFlag,
		Usage: "include measured events in measurement and validation report",
	},
	&cli.StringFlag{
		Name:  CtrDriverFlag,
		Usage: "driver to use for container measurements, empty to not measure containers",
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
		Name:  TpmKeyAlgFlag,
		Usage: "TPM AK key algorithm [ec256 rsa2048]",
	},
	&cli.BoolFlag{
		Name:  UseOmspFlag,
		Usage: "Indicates whether to use revocation information for manifests",
	},
	&cli.StringFlag{
		Name: OmspFormatFlag,
		Usage: "Indicates which serialization format to use for revocation information for " +
			"manifests [json cbor]",
	},
	&cli.BoolFlag{
		Name: AppendEbsFlag,
		Usage: "reconstruct the ExitBootServices EV_EFI_ACTION events for PCR 5. This is only " +
			"required for TPM2.0 which uses legacy event log format v1, which does not support " +
			"EFI_TCG2_FINAL_EVENTS_TABLE, which carries events measured after the firmware " +
			"handed out the event log. Those events are therefore extended into the TPM, as they " +
			"can never appear in the log, making it impossible to replay PCR 5 from the log",
	},
}

// Override applies CLI flag values to the given cmc.Config, only overwriting
// fields for flags that were explicitly set on the command line.
func Override(cmd *cli.Command, c *cmc.Config) error {
	if cmd.IsSet(CmcFlag) {
		c.Cmc = cmd.String(CmcFlag)
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
	if cmd.IsSet(PolicyEngineFlag) {
		c.PolicyEngine = cmd.String(PolicyEngineFlag)
	}
	if cmd.IsSet(PolicyOverwriteFlag) {
		c.PolicyOverwrite = cmd.Bool(PolicyOverwriteFlag)
	}
	if cmd.IsSet(StorageFlag) {
		c.Storage = cmd.String(StorageFlag)
	}
	if cmd.IsSet(MeasurementLogsFlag) {
		c.MeasurementLogs = cmd.Bool(MeasurementLogsFlag)
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
	if cmd.IsSet(EndorsementFlag) {
		c.Endorsement = cmd.String(EndorsementFlag)
	}
	if cmd.IsSet(EnrollmentFlag) {
		c.Enrollment = cmd.String(EnrollmentFlag)
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
	if cmd.IsSet(AppendEbsFlag) {
		c.AppendEbsEvent = cmd.Bool(AppendEbsFlag)
	}

	return nil
}
