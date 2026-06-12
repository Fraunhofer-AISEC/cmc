// Copyright (c) 2025 - 2026 Fraunhofer AISEC
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

package tcg

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/sirupsen/logrus"
)

var (
	log = logrus.WithField("service", "mrtool")
)

type Conf struct {
	Ovmf         string
	AcpiRsdp     string
	AcpiTables   string
	TableLoader  string
	TpmLog       string
	SmbiosTables string
	SmbiosSpec   *SmbiosSpec
	BootOrder    []string
	BootXxxx     []string
	NoBootVars   bool
	Drivers      []string
	Bootloaders  []string
	LoaderConfs  []string
	Config       string
	Kernel       string
	Initrd       string
	Cmdline      string
	Qemu         bool
	AddZeros     int
	StripNewline bool
	Gpt          string
	SecureBoot   string
	Pk           string
	Kek          string
	Db           string
	Dbx          string
	SbatLevel    string
	DumpPei      string
	DumpDxe      string
	DumpKernel   string
	DumpGpt      string
	DumpSmbios   string
}

const (
	ovmfFlag         = "ovmf"
	acpirsdpFlag     = "acpirsdp"
	acpitablesFlag   = "acpitables"
	tableloaderFlag  = "tableloader"
	tpmlogFlag       = "tpmlog"
	smbiosTablesFlag = "smbios-tables"

	smbiosSocketsFlag         = "smbios-sockets"
	smbiosRamSizeFlag         = "smbios-ram-size"
	smbiosRamBelow4GFlag      = "smbios-ram-below-4g"
	smbiosManufacturerFlag    = "smbios-manufacturer"
	smbiosProductFlag         = "smbios-product"
	smbiosMachineVersionFlag  = "smbios-machine-version"
	smbiosProcessorIdFlag     = "smbios-processor-id"
	smbiosChassisSecurityFlag = "smbios-chassis-security"
	smbiosBiosVendorFlag      = "smbios-bios-vendor"
	smbiosBiosVersionFlag     = "smbios-bios-version"
	smbiosBiosDateFlag        = "smbios-bios-date"

	bootorderFlag    = "bootorder"
	bootxxxxFlag     = "bootxxxx"
	nobootvarsFlag   = "nobootvars"
	driversFlag      = "drivers"
	bootloadersFlag  = "bootloaders"
	loaderConfsFlag  = "loaderconfs"
	configFlag       = "config"
	kernelFlag       = "kernel"
	initrdFlag       = "initrd"
	cmdlineFlag      = "cmdline"
	qemuFlag         = "qemu"
	addzerosFlag     = "addzeros"
	stripnewlineFlag = "stripnewline"
	gptFlag          = "gpt"
	securebootFlag   = "secureboot"
	pkFlag           = "pk"
	kekFlag          = "kek"
	dbFlag           = "db"
	dbxFlag          = "dbx"
	sbatlevelFlag    = "sbatlevel"

	dumppeiFlag    = "dumppei"
	dumpdxeFlag    = "dumpdxe"
	dumpkernelFlag = "dumpkernel"
	dumpgptFlag    = "dumpgpt"
	dumpsmbiosFlag = "dumpsmbios"
)

var Flags = []cli.Flag{
	&cli.StringFlag{Name: ovmfFlag, Usage: "The filename of the OVMF.fd file to be measured into PCR0/MRTD"},
	&cli.StringFlag{Name: acpirsdpFlag, Usage: "Path to QEMU etc/acpi/rsdp file for PCR1/RTMR0"},
	&cli.StringFlag{Name: acpitablesFlag, Usage: "Path to QEMU etc/acpi/tables file for PCR1/RTMR0"},
	&cli.StringFlag{Name: tableloaderFlag, Usage: "Path to QEMU etc/table-loader file for PCR1/RTMR0"},
	&cli.StringFlag{Name: tpmlogFlag, Usage: "Path to QEMU etc/tpm/log file for PCR1/RTMR0"},
	&cli.StringFlag{Name: smbiosTablesFlag, Usage: "Path to a DMI dump (/sys/firmware/dmi/tables/DMI) captured from a reference VM; EDK2 SmbiosMeasurementDxe filter is applied before hashing (mutually exclusive with --smbios-*)"},

	&cli.StringFlag{Name: smbiosRamSizeFlag, Usage: "Spec-mode: guest RAM size (e.g. 4G, 8192M); enables spec mode"},
	&cli.IntFlag{Name: smbiosSocketsFlag, Usage: "Spec-mode: number of CPU sockets"},
	&cli.StringFlag{Name: smbiosRamBelow4GFlag, Usage: "Spec-mode: override below-4G RAM split"},
	&cli.StringFlag{Name: smbiosManufacturerFlag, Usage: "Spec-mode: SMBIOS Manufacturer string"},
	&cli.StringFlag{Name: smbiosProductFlag, Usage: "Spec-mode: SMBIOS ProductName"},
	&cli.StringFlag{Name: smbiosMachineVersionFlag, Usage: "Spec-mode: SMBIOS Type Version (e.g. pc-q35-10.1)"},
	&cli.StringFlag{Name: smbiosProcessorIdFlag, Usage: "Spec-mode: SMBIOS ProcessorID as 16-hex-digit string (Default matches QEMU -cpu EPYC-v4)"},
	&cli.IntFlag{Name: smbiosChassisSecurityFlag, Usage: "Spec-mode: SMBIOS Type 3 ChassisSecurityStatus byte"},
	&cli.StringFlag{Name: smbiosBiosVendorFlag, Usage: "Spec-mode: SMBIOS Vendor"},
	&cli.StringFlag{Name: smbiosBiosVersionFlag, Usage: "Spec-mode: SMBIOS BIOSVersion"},
	&cli.StringFlag{Name: smbiosBiosDateFlag, Usage: "Spec-mode: SMBIOS BIOSReleaseDate (MM/DD/YYYY)"},

	&cli.StringFlag{Name: bootorderFlag, Usage: "Comma-separated list of UEFI boot order numbers to be measured into PCR1/RTMR0"},
	&cli.StringFlag{Name: bootxxxxFlag, Usage: "Comma-separated list of UEFI Boot#### variable data files to be measured into PCR1/RTMR0"},
	&cli.BoolFlag{Name: nobootvarsFlag, Usage: "Do not measure UEFI boot variables into PCR1/RTMR0"},
	&cli.StringFlag{Name: driversFlag, Usage: "Comma-separated list of driver EFI files (PE/COFF or Option ROM format) to be measured into PCR2"},
	&cli.StringFlag{Name: bootloadersFlag, Usage: "Comma-separated list of bootloader EFI images to be measured into PCR4/RTMR1"},
	&cli.StringFlag{Name: loaderConfsFlag, Usage: "Comma-separated list of bootloader configuration files to be measured into PCR5"},
	&cli.StringFlag{Name: kernelFlag, Usage: "Path to a direct boot kernel image (PE/COFF format) measured into PCR4/RTMR1"},
	&cli.StringFlag{Name: configFlag, Usage: "Path to kernel configuration file"},
	&cli.StringFlag{Name: initrdFlag, Usage: "The filename of the initrd/initramfs"},
	&cli.StringFlag{Name: cmdlineFlag, Usage: "Kernel commandline"},
	&cli.BoolFlag{Name: qemuFlag, Usage: "QEMU VM (appends initrd=initrd to kernel cmdline)"},
	&cli.IntFlag{Name: addzerosFlag, Usage: "Add <num> trailing zeros to kernel cmdline", Value: 1},
	&cli.BoolFlag{Name: stripnewlineFlag, Usage: "Strip potential newline character from the cmdline"},
	&cli.StringFlag{Name: gptFlag, Usage: "Path to EFI GPT partition table file to be extended into PCR5/RTMR1"},
	&cli.StringFlag{Name: securebootFlag, Usage: "UEFI secure boot SecureBoot variable data file to be measured into PCR7/RTMR0"},
	&cli.StringFlag{Name: pkFlag, Usage: "UEFI secure boot Platform Key (PK) variable data file to be measured into PCR7/RTMR0"},
	&cli.StringFlag{Name: kekFlag, Usage: "UEFI secure boot Key Exchange Key (KEK) variable data file to be measured into PCR7/RTMR0"},
	&cli.StringFlag{Name: dbFlag, Usage: "UEFI secure boot DB variable data file to be measured into PCR7/RTMR0"},
	&cli.StringFlag{Name: dbxFlag, Usage: "UEFI secure boot DBX variable data file to be measured into PCR7/RTMR0"},
	&cli.StringFlag{Name: sbatlevelFlag, Usage: "SBAT level string for measuring DBX authority into PCR7"},
	&cli.StringFlag{Name: dumppeiFlag, Usage: "Optional path to folder to dump the measured PEIFV"},
	&cli.StringFlag{Name: dumpdxeFlag, Usage: "Optional path to folder to dump the measured DXEFV"},
	&cli.StringFlag{Name: dumpkernelFlag, Usage: "Optional path to folder to dump the measured kernel"},
	&cli.StringFlag{Name: dumpgptFlag, Usage: "Optional path to folder to dump the measured GPT"},
	&cli.StringFlag{Name: dumpsmbiosFlag, Usage: "Optional path to folder to dump the measured smbios tables"},
}

func GetTcgConf(cmd *cli.Command) (*Conf, error) {
	c := &Conf{}

	if cmd.IsSet(ovmfFlag) {
		c.Ovmf = cmd.String(ovmfFlag)
	}
	if cmd.IsSet(acpirsdpFlag) {
		c.AcpiRsdp = cmd.String(acpirsdpFlag)
	}
	if cmd.IsSet(acpitablesFlag) {
		c.AcpiTables = cmd.String(acpitablesFlag)
	}
	if cmd.IsSet(tableloaderFlag) {
		c.TableLoader = cmd.String(tableloaderFlag)
	}
	if cmd.IsSet(tpmlogFlag) {
		c.TpmLog = cmd.String(tpmlogFlag)
	}
	if cmd.IsSet(smbiosTablesFlag) {
		c.SmbiosTables = cmd.String(smbiosTablesFlag)
	}

	spec, err := parseSmbiosSpec(cmd)
	if err != nil {
		return nil, err
	}
	if spec != nil && c.SmbiosTables != "" {
		return nil, fmt.Errorf("--%s and --smbios-* are mutually exclusive", smbiosTablesFlag)
	}
	c.SmbiosSpec = spec

	if cmd.IsSet(bootorderFlag) {
		c.BootOrder = strings.Split(cmd.String(bootorderFlag), ",")
	}
	if cmd.IsSet(bootxxxxFlag) {
		c.BootXxxx = strings.Split(cmd.String(bootxxxxFlag), ",")
	}

	c.NoBootVars = cmd.Bool(nobootvarsFlag)

	if cmd.IsSet(driversFlag) {
		c.Drivers = strings.Split(cmd.String(driversFlag), ",")
	}
	if cmd.IsSet(bootloadersFlag) {
		c.Bootloaders = strings.Split(cmd.String(bootloadersFlag), ",")
	}
	if cmd.IsSet(loaderConfsFlag) {
		c.LoaderConfs = strings.Split(cmd.String(loaderConfsFlag), ",")
	}
	if cmd.IsSet(configFlag) {
		c.Config = cmd.String(configFlag)
	}
	if cmd.IsSet(kernelFlag) {
		c.Kernel = cmd.String(kernelFlag)
	}
	if cmd.IsSet(initrdFlag) {
		c.Initrd = cmd.String(initrdFlag)
	}
	if cmd.IsSet(cmdlineFlag) {
		c.Cmdline = cmd.String(cmdlineFlag)
	}

	c.Qemu = cmd.Bool(qemuFlag)

	// default initialize to 1
	if cmd.IsSet(addzerosFlag) {
		c.AddZeros = cmd.Int(addzerosFlag)
	} else {
		c.AddZeros = 1
	}
	c.StripNewline = cmd.Bool(stripnewlineFlag)

	if cmd.IsSet(gptFlag) {
		c.Gpt = cmd.String(gptFlag)
	}

	if cmd.IsSet(securebootFlag) {
		c.SecureBoot = cmd.String(securebootFlag)
	}
	if cmd.IsSet(pkFlag) {
		c.Pk = cmd.String(pkFlag)
	}
	if cmd.IsSet(kekFlag) {
		c.Kek = cmd.String(kekFlag)
	}
	if cmd.IsSet(dbFlag) {
		c.Db = cmd.String(dbFlag)
	}
	if cmd.IsSet(dbxFlag) {
		c.Dbx = cmd.String(dbxFlag)
	}
	if cmd.IsSet(sbatlevelFlag) {
		c.SbatLevel = cmd.String(sbatlevelFlag)
	}

	if cmd.IsSet(dumppeiFlag) {
		c.DumpPei = cmd.String(dumppeiFlag)
	}
	if cmd.IsSet(dumpdxeFlag) {
		c.DumpDxe = cmd.String(dumpdxeFlag)
	}
	if cmd.IsSet(dumpkernelFlag) {
		c.DumpKernel = cmd.String(dumpkernelFlag)
	}
	if cmd.IsSet(dumpgptFlag) {
		c.DumpGpt = cmd.String(dumpgptFlag)
	}
	if cmd.IsSet(dumpsmbiosFlag) {
		c.DumpSmbios = cmd.String(dumpsmbiosFlag)
	}

	return c, nil
}

func (c *Conf) Print() {

	if c.Ovmf != "" {
		log.Debugf("\tOVMF: %q", c.Ovmf)
	}
	if c.AcpiRsdp != "" {
		log.Debugf("\tACPI RSDP: %q", c.AcpiRsdp)
	}
	if c.AcpiTables != "" {
		log.Debugf("\tACPI Tables: %q", c.AcpiTables)
	}
	if c.TableLoader != "" {
		log.Debugf("\tTable Loader: %q", c.TableLoader)
	}
	if c.TpmLog != "" {
		log.Debugf("\tTPM Log: %q", c.TpmLog)
	}
	if c.SmbiosTables != "" {
		log.Debugf("\tSMBIOS tables: %q", c.SmbiosTables)
	}

	if len(c.BootOrder) > 0 {
		log.Debugf("\tBoot Order:")
		for _, v := range c.BootOrder {
			log.Debugf("\t\t%q", v)
		}
	}
	if len(c.BootXxxx) > 0 {
		log.Debugf("\tBoot#### vars:")
		for _, v := range c.BootXxxx {
			log.Debugf("\t\t%q", v)
		}
	}
	if c.NoBootVars {
		log.Debugf("\tNoBootVars: true")
	}

	if len(c.Drivers) > 0 {
		log.Debugf("\tDrivers:")
		for _, path := range c.Drivers {
			log.Debugf("\t\t%q", path)
		}
	}
	if len(c.Bootloaders) > 0 {
		log.Debugf("\tBootloaders:")
		for _, path := range c.Bootloaders {
			log.Debugf("\t\t%q", path)
		}
	}

	if c.Config != "" {
		log.Debugf("\tKernel Config: %q", c.Config)
	}
	if c.Kernel != "" {
		log.Debugf("\tKernel: %q", c.Kernel)
	}
	if c.Initrd != "" {
		log.Debugf("\tInitrd: %q", c.Initrd)
	}
	if c.Cmdline != "" {
		log.Debugf("\tCmdline: %q", c.Cmdline)
	}
	if c.Qemu {
		log.Debugf("\tQEMU: true")
	}
	if c.AddZeros != 0 {
		log.Debugf("\tAddZeros: %d", c.AddZeros)
	}
	if c.StripNewline {
		log.Debugf("\tStripNewline: true")
	}
	if c.Gpt != "" {
		log.Debugf("\tGPT: %q", c.Gpt)
	}
	if c.SecureBoot != "" {
		log.Debugf("\tSecureBoot: %q", c.SecureBoot)
	}
	if c.Pk != "" {
		log.Debugf("\tPK: %q", c.Pk)
	}
	if c.Kek != "" {
		log.Debugf("\tKEK: %q", c.Kek)
	}
	if c.Db != "" {
		log.Debugf("\tDB: %q", c.Db)
	}
	if c.Dbx != "" {
		log.Debugf("\tDBX: %q", c.Dbx)
	}
	if c.SbatLevel != "" {
		log.Debugf("\tSBAT Level: %q", c.SbatLevel)
	}

	if c.SmbiosSpec != nil {
		log.Debugf("\tSMBIOS spec: sockets=%d ramSize=%#x product=%q machineVer=%q",
			c.SmbiosSpec.Sockets, c.SmbiosSpec.RamSize,
			c.SmbiosSpec.ProductName, c.SmbiosSpec.MachineVersion)
	}

	if c.DumpPei != "" {
		log.Debugf("\tDump PEI: %q", c.DumpPei)
	}
	if c.DumpDxe != "" {
		log.Debugf("\tDump DXE: %q", c.DumpDxe)
	}
	if c.DumpKernel != "" {
		log.Debugf("\tDump Kernel: %q", c.DumpKernel)
	}
	if c.DumpGpt != "" {
		log.Debugf("\tDump GPT: %q", c.DumpGpt)
	}
	if c.DumpSmbios != "" {
		log.Debugf("\t Dump SMBIOS: %q", c.DumpSmbios)
	}

}

// parseSmbiosSpec returns a populated SmbiosSpec when any --smbios-* flag is set
func parseSmbiosSpec(cmd *cli.Command) (*SmbiosSpec, error) {
	specFlags := []string{
		smbiosSocketsFlag, smbiosRamSizeFlag, smbiosRamBelow4GFlag,
		smbiosManufacturerFlag, smbiosProductFlag, smbiosMachineVersionFlag,
		smbiosProcessorIdFlag, smbiosChassisSecurityFlag,
		smbiosBiosVendorFlag, smbiosBiosVersionFlag, smbiosBiosDateFlag,
	}
	anySet := false
	for _, f := range specFlags {
		if cmd.IsSet(f) {
			anySet = true
			break
		}
	}
	if !anySet {
		return nil, nil
	}

	if !cmd.IsSet(smbiosRamSizeFlag) {
		return nil, fmt.Errorf("--%s is required when any --smbios-* flag is set", smbiosRamSizeFlag)
	}

	spec := SmbiosDefaults()
	ramSize, err := ParseRamSize(cmd.String(smbiosRamSizeFlag))
	if err != nil {
		return nil, fmt.Errorf("invalid --%s: %w", smbiosRamSizeFlag, err)
	}
	spec.RamSize = ramSize

	if cmd.IsSet(smbiosSocketsFlag) {
		spec.Sockets = cmd.Int(smbiosSocketsFlag)
	}
	if cmd.IsSet(smbiosRamBelow4GFlag) {
		v, err := ParseRamSize(cmd.String(smbiosRamBelow4GFlag))
		if err != nil {
			return nil, fmt.Errorf("invalid --%s: %w", smbiosRamBelow4GFlag, err)
		}
		spec.RamBelow4G = v
	}
	if cmd.IsSet(smbiosManufacturerFlag) {
		spec.Manufacturer = cmd.String(smbiosManufacturerFlag)
	}
	if cmd.IsSet(smbiosProductFlag) {
		spec.ProductName = cmd.String(smbiosProductFlag)
	}
	if cmd.IsSet(smbiosMachineVersionFlag) {
		spec.MachineVersion = cmd.String(smbiosMachineVersionFlag)
	}
	if cmd.IsSet(smbiosChassisSecurityFlag) {
		v := cmd.Int(smbiosChassisSecurityFlag)
		if v < 0 || v > 0xff {
			return nil, fmt.Errorf("invalid --%s: %d (must fit in uint8)", smbiosChassisSecurityFlag, v)
		}
		spec.ChassisSecurityStatus = uint8(v)
	}
	if cmd.IsSet(smbiosProcessorIdFlag) {
		id, err := parseHexUint64(cmd.String(smbiosProcessorIdFlag))
		if err != nil {
			return nil, fmt.Errorf("invalid --%s: %w", smbiosProcessorIdFlag, err)
		}
		spec.ProcessorId = id
	}
	if cmd.IsSet(smbiosBiosVendorFlag) {
		spec.BiosVendor = cmd.String(smbiosBiosVendorFlag)
	}
	if cmd.IsSet(smbiosBiosVersionFlag) {
		spec.BiosVersion = cmd.String(smbiosBiosVersionFlag)
	}
	if cmd.IsSet(smbiosBiosDateFlag) {
		spec.BiosDate = cmd.String(smbiosBiosDateFlag)
	}

	return &spec, nil
}

func parseHexUint64(s string) (uint64, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(s) > 16 {
		return 0, fmt.Errorf("too long (max 16 hex digits)")
	}
	raw, err := hex.DecodeString(strings.Repeat("0", 16-len(s)) + s)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(raw), nil
}
