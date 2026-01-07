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

package precomputetpm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/global"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/tcg"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

var (
	log = logrus.WithField("service", "mrtool")
)

type Config struct {
	*tcg.Conf
	SystemUuid     string
	GrubCmds       string
	Path           []string
	MokLists       []string
	ImaPaths       []string
	ImaStrip       string
	ImaTemplate    string
	BootAggregate  []byte
	PrintAggregate bool
}

const (
	systemUuidFlag     = "systemuuid"
	grubcmdsFlag       = "grubcmds"
	pathFlag           = "ima-path"
	imaPathFlag        = "ima-path"
	imaStripFlag       = "ima-strip"
	imaTemplateFlag    = "ima-template"
	bootAggregateFlag  = "boot-aggregate"
	printAggregateFlag = "print-aggregate"
	mokListsFlag       = "moklists"
)

var flags = []cli.Flag{
	&cli.StringFlag{Name: systemUuidFlag, Usage: "Path to GRUB command file for PCR8"},
	&cli.StringFlag{Name: grubcmdsFlag, Usage: "Path to GRUB command file for PCR8"},
	&cli.StringFlag{Name: pathFlag, Usage: "Comma-separated list of folders/files to be extended into PCR9"},
	&cli.StringFlag{
		Name:  imaPathFlag,
		Usage: "comma-separated paths or single files (binaries or config files) to create ima reference values for to be measured into PCR10",
	},
	&cli.StringFlag{
		Name:  imaStripFlag,
		Usage: "Optional ima path prefix which is stripped from the actual path in the output",
	},
	&cli.StringFlag{
		Name:  imaTemplateFlag,
		Usage: "IMA template name (ima-ng or ima-sig)",
	},
	&cli.StringFlag{
		Name:  bootAggregateFlag,
		Usage: "Boot aggregate (PCRs 0-9) passed as a hex-string to be included as a reference value in IMA PCR10",
	},
	&cli.BoolFlag{
		Name:  printAggregateFlag,
		Usage: "Print the aggregated PCR value over the selected PCRs",
	},
	&cli.StringFlag{Name: mokListsFlag, Usage: "Comma-separated list of UEFI MokList variable data files as written to " +
		"/sys/firmware/efi/efivars to be extended into PCR14"},
}

var Command = &cli.Command{
	Name:  "tpm",
	Usage: "Precompute TPM PCR events, final PCR values, or the aggregated PCR value",
	Flags: append(tcg.Flags, flags...),
	Action: func(ctx context.Context, c *cli.Command) error {
		err := run(c)
		if err != nil {
			return fmt.Errorf("failed to precompute tpm pcrs: %w", err)
		}
		return nil
	},
}

func run(cmd *cli.Command) error {

	globConf, err := global.GetConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid global config: %w", err)
	}

	tpmConf, err := getConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid precompute tpm config: %w", err)
	}

	log.Info("Precomputing TPM PCRs...")

	// Precompute all TPM measurements
	pcrs, refvals, err := precompute(globConf.Mrs, tpmConf)
	if err != nil {
		return err
	}

	// Write eventlog to stdout if requested
	if globConf.PrintEventLog {
		data, err := json.MarshalIndent(refvals, "", "     ")
		if err != nil {
			return fmt.Errorf("failed to marshal reference values: %w", err)
		}
		os.Stdout.Write(append(data, []byte("\n")...))
	}

	// Write final extended PCR values to stdout if requested
	if globConf.PrintSummary {
		data, err := json.MarshalIndent(pcrs, "", "     ")
		if err != nil {
			return fmt.Errorf("failed to marshal reference values: %w", err)
		}
		os.Stdout.Write(append(data, []byte("\n")...))
	}

	// Calculate aggregate and write to stdout if requested
	if tpmConf.PrintAggregate {

		aggregate, err := tcg.PrecomputeAggregatePcrValue(pcrs)
		if err != nil {
			return fmt.Errorf("failed to precomptue aggregated PCR value: %w", err)
		}

		data, err := json.MarshalIndent(aggregate, "", "     ")
		if err != nil {
			return fmt.Errorf("failed to marshal reference values: %w", err)
		}

		os.Stdout.Write(append(data, []byte("\n")...))
	}

	log.Info("Finished")

	return nil
}

func getConfig(cmd *cli.Command) (*Config, error) {

	var err error
	c := &Config{}

	c.Conf, err = tcg.GetTcgConf(cmd)
	if err != nil {
		return nil, err
	}

	if cmd.IsSet(systemUuidFlag) {
		c.SystemUuid = cmd.String(systemUuidFlag)
	}
	if cmd.IsSet(grubcmdsFlag) {
		c.GrubCmds = cmd.String(grubcmdsFlag)
	}

	if cmd.IsSet(pathFlag) {
		c.Path = strings.Split(cmd.String(pathFlag), ",")
	}

	if cmd.IsSet(imaPathFlag) {
		c.ImaPaths = strings.Split(cmd.String(imaPathFlag), ",")
	}
	if cmd.IsSet(imaStripFlag) {
		c.ImaStrip = cmd.String(imaStripFlag)
	}
	if cmd.IsSet(imaTemplateFlag) {
		c.ImaTemplate = cmd.String(imaTemplateFlag)
	}
	if cmd.IsSet(bootAggregateFlag) {
		b, err := hex.DecodeString(cmd.String(bootAggregateFlag))
		if err != nil {
			return nil, fmt.Errorf("failed to read boot-aggregate hex string: %w", err)
		}
		c.BootAggregate = b
	}

	c.PrintAggregate = cmd.Bool(printAggregateFlag)

	if cmd.IsSet(mokListsFlag) {
		c.MokLists = strings.Split(cmd.String(mokListsFlag), ",")
	}

	c.print()

	return c, nil
}

func (c *Config) print() {

	log.Debugf("Precompute TPM PCR configuration:")

	c.Conf.Print()

	if c.SystemUuid != "" {
		log.Debugf("\tSystem UUID: %q", c.SystemUuid)
	}

	if c.GrubCmds != "" {
		log.Debugf("\tGRUB cmds: %q", c.GrubCmds)
	}

	if len(c.Path) > 0 {
		log.Debugf("\tPath entries:")
		for _, p := range c.Path {
			log.Debugf("\t\t%q", p)
		}
	}

	log.Debugf("\tima-template  : %q", c.ImaTemplate)
	if len(c.ImaPaths) > 0 {
		log.Debugf("\tIMA Paths     :")
		for _, path := range c.ImaPaths {
			log.Debugf("\t\t%q", path)
		}
	}
	if c.ImaStrip != "" {
		log.Debugf("\tIMA strip     : %q", c.ImaStrip)
	}
	if c.BootAggregate != nil {
		log.Debugf("\tboot-aggregate: %q", hex.EncodeToString(c.BootAggregate))
	}

	log.Debugf("\tprint-aggregate: %v", c.PrintAggregate)

	if len(c.MokLists) > 0 {
		log.Debugf("\tMOK List entries:")
		for _, m := range c.MokLists {
			log.Debugf("\t\t%q", m)
		}
	}

}

func precompute(pcrNums []int, tpmConf *Config) ([]*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	var err error
	refvals := make([]*ar.ReferenceValue, 0)
	pcrs := make([]*ar.ReferenceValue, 0)

	for _, pcrNum := range pcrNums {

		var pcr *ar.ReferenceValue
		var rv []*ar.ReferenceValue

		switch {
		case pcrNum == 0:
			pcr, rv, err = PrecomputePcr0(tpmConf)
		case pcrNum == 1:
			pcr, rv, err = PrecomputePcr1(tpmConf)
		case pcrNum == 2:
			pcr, rv, err = PrecomputePcr2(tpmConf)
		case pcrNum == 3:
			pcr, rv, err = PrecomputePcr3(tpmConf)
		case pcrNum == 4:
			pcr, rv, err = PrecomputePcr4(tpmConf)
		case pcrNum == 5:
			pcr, rv, err = PrecomputePcr5(tpmConf)
		case pcrNum == 6:
			pcr, rv, err = PrecomputePcr6(tpmConf)
		case pcrNum == 7:
			pcr, rv, err = PrecomputePcr7(tpmConf)
		case pcrNum == 8:
			pcr, rv, err = PrecomputePcr8(tpmConf)
		case pcrNum == 9:
			pcr, rv, err = PrecomputePcr9(tpmConf)
		case pcrNum == 10:
			pcr, rv, err = PrecomputePcr10(tpmConf)
		case pcrNum == 11:
			pcr, rv, err = PrecomputePcr11(tpmConf)
		case pcrNum == 12:
			pcr, rv, err = PrecomputePcr12(tpmConf)
		case pcrNum == 13:
			pcr, rv, err = PrecomputePcr14(tpmConf)
		case pcrNum < 24:
			return nil, nil, fmt.Errorf("PCR%v precomputation not yet implemented", pcrNum)
		default:
			return nil, nil, fmt.Errorf("PCR specification does not define PCR%v", pcrNum)
		}

		if err != nil {
			return nil, nil, fmt.Errorf("failed to precompute PCR%v: %w", pcrNum, err)
		}

		if pcr != nil {
			pcrs = append(pcrs, pcr)
		}
		refvals = append(refvals, rv...)
	}

	return pcrs, refvals, nil
}
