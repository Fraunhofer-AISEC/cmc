// Copyright (c) 2025 Fraunhofer AISEC
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
	EfiHob       string
	BootOrder    []string
	BootXxxx     []string
	NoBootVars   bool
	Drivers      []string
	Bootloaders  []string
	Config       string
	Kernel       string
	Initrd       string
	Cmdline      string
	Qemu         bool
	AddZeros     int
	StripNewline bool
	Gpt          string
	SystemUUID   string
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
}

const (
	ovmfFlag         = "ovmf"
	acpirsdpFlag     = "acpirsdp"
	acpitablesFlag   = "acpitables"
	tableloaderFlag  = "tableloader"
	tpmlogFlag       = "tpmlog"
	efihobFlag       = "efihob"
	bootorderFlag    = "bootorder"
	bootxxxxFlag     = "bootxxxx"
	nobootvarsFlag   = "nobootvars"
	driversFlag      = "drivers"
	bootloadersFlag  = "bootloaders"
	configFlag       = "config"
	kernelFlag       = "kernel"
	initrdFlag       = "initrd"
	cmdlineFlag      = "cmdline"
	qemuFlag         = "qemu"
	addzerosFlag     = "addzeros"
	stripnewlineFlag = "stripnewline"
	gptFlag          = "gpt"
	systemuuidFlag   = "systemuuid"
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
)

var Flags = []cli.Flag{
	&cli.StringFlag{Name: ovmfFlag, Usage: "The filename of the OVMF.fd file to be measured into PCR0/MRTD"},
	&cli.StringFlag{Name: acpirsdpFlag, Usage: "Path to QEMU etc/acpi/rsdp file for PCR1/RTMR0"},
	&cli.StringFlag{Name: acpitablesFlag, Usage: "Path to QEMU etc/acpi/tables file for PCR1/RTMR0"},
	&cli.StringFlag{Name: tableloaderFlag, Usage: "Path to QEMU etc/table-loader file for PCR1/RTMR0"},
	&cli.StringFlag{Name: tpmlogFlag, Usage: "Path to QEMU etc/tpm/log file for PCR1/RTMR0"},
	&cli.StringFlag{Name: efihobFlag, Usage: "Path to an EFI handoff table optionally measured into PCR1/RTMR0"},
	&cli.StringFlag{Name: bootorderFlag, Usage: "Comma-separated list of UEFI boot order numbers to be measured into PCR1/RTMR0"},
	&cli.StringFlag{Name: bootxxxxFlag, Usage: "Comma-separated list of UEFI Boot#### variable data files to be measured into PCR1/RTMR0"},
	&cli.BoolFlag{Name: nobootvarsFlag, Usage: "Do not measure UEFI boot variables into PCR1/RTMR0"},
	&cli.StringFlag{Name: driversFlag, Usage: "Comma-separated list of driver EFI files (PE/COFF or Option ROM format) to be measured into PCR2"},
	&cli.StringFlag{Name: bootloadersFlag, Usage: "Comma-separated list of bootloader EFI images to be measured into PCR4/RTMR1"},
	&cli.StringFlag{Name: kernelFlag, Usage: "Path to a direct boot kernel image (PE/COFF format) measured into PCR4/RTMR1"},
	&cli.StringFlag{Name: configFlag, Usage: "Path to kernel configuration file"},
	&cli.StringFlag{Name: initrdFlag, Usage: "The filename of the initrd/initramfs"},
	&cli.StringFlag{Name: cmdlineFlag, Usage: "Kernel commandline"},
	&cli.BoolFlag{Name: qemuFlag, Usage: "QEMU VM (appends initrd=initrd to kernel cmdline)"},
	&cli.IntFlag{Name: addzerosFlag, Usage: "Add <num> trailing zeros to kernel cmdline", Value: 1},
	&cli.BoolFlag{Name: stripnewlineFlag, Usage: "Strip potential newline character from the cmdline"},
	&cli.StringFlag{Name: gptFlag, Usage: "Path to EFI GPT partition table file to be extended into PCR5"},
	&cli.StringFlag{Name: systemuuidFlag, Usage: "Path to DMI System-UUID file to be extended into PCR6"},
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
	if cmd.IsSet(efihobFlag) {
		c.EfiHob = cmd.String(efihobFlag)
	}

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
	if cmd.IsSet(addzerosFlag) {
		c.AddZeros = cmd.Int(addzerosFlag)
	}
	c.StripNewline = cmd.Bool(stripnewlineFlag)

	if cmd.IsSet(gptFlag) {
		c.Gpt = cmd.String(gptFlag)
	}
	if cmd.IsSet(systemuuidFlag) {
		c.SystemUUID = cmd.String(systemuuidFlag)
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
	if c.EfiHob != "" {
		log.Debugf("\tEFI HOB: %q", c.EfiHob)
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
	if c.SystemUUID != "" {
		log.Debugf("\tSystem UUID: %q", c.SystemUUID)
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
}
