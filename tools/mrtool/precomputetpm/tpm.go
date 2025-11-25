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
	Gpt      string
	GrubCmds string
	Path     []string
}

const (
	gptFlag      = "gpt"
	grubcmdsFlag = "grubcmds"
	pathFlag     = "path"
)

var flags = []cli.Flag{
	&cli.StringFlag{Name: gptFlag, Usage: "Path to EFI GPT partition table file to be extended into PCR5"},
	&cli.StringFlag{Name: grubcmdsFlag, Usage: "Path to GRUB command file for PCR8"},
	&cli.StringFlag{Name: pathFlag, Usage: "Comma-separated list of folders/files to be extended into PCR9"},
}

var Command = &cli.Command{
	Name:  "tpm",
	Usage: "Precompute TPM measurement",
	Flags: append(tcg.Flags, flags...),
	Action: func(ctx context.Context, c *cli.Command) error {
		err := run(c)
		if err != nil {
			return fmt.Errorf("failed to precompute tpm pcrs: %w", err)
		}
		return nil
	},
}

func getConfig(cmd *cli.Command) (*Config, error) {

	var err error
	c := &Config{}

	c.Conf, err = tcg.GetTcgConf(cmd)
	if err != nil {
		return nil, err
	}

	if cmd.IsSet(gptFlag) {
		c.Gpt = cmd.String(gptFlag)
	}

	if cmd.IsSet(grubcmdsFlag) {
		c.GrubCmds = cmd.String(grubcmdsFlag)
	}

	if cmd.IsSet(pathFlag) {
		c.Path = strings.Split(cmd.String(pathFlag), ",")
	}

	c.print()

	return c, nil
}

func (c *Config) print() {

	log.Debugf("Precompute TPM PCR configuration:")

	c.Conf.Print()

	if c.GrubCmds != "" {
		log.Debugf("\tGRUB cmds: %q", c.GrubCmds)
	}

	if len(c.Path) > 0 {
		log.Debugf("\tPath entries:")
		for _, p := range c.Path {
			log.Debugf("\t\t%q", p)
		}
	}
	if c.Gpt != "" {
		log.Debugf("\tGPT: %q", c.Gpt)
	}

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

	log.Debug("Precomputing TPM PCRs...")

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

	log.Debug("Finished")

	return nil
}

func precompute(pcrNums []int, tpmConf *Config) ([]*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	refvals := make([]*ar.ReferenceValue, 0)
	pcrs := make([]*ar.ReferenceValue, 0)

	for _, pcrNum := range pcrNums {
		switch {
		case pcrNum == 2:
			pcr, rv, err := PrecomputePcr2(tpmConf)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to precompute PCR%v: %w", pcrNum, err)
			}
			pcrs = append(pcrs, pcr)
			refvals = append(refvals, rv...)
		case pcrNum == 4:
			pcr, rv, err := PrecomputePcr4(tpmConf)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to precompute PCR%v: %w", pcrNum, err)
			}
			pcrs = append(pcrs, pcr)
			refvals = append(refvals, rv...)
		case pcrNum < 24:
			return nil, nil, fmt.Errorf("PCR%v precomputation not yet implemented", pcrNum)
		default:
			return nil, nil, fmt.Errorf("PCR specification does not define PCR%v", pcrNum)
		}
	}

	return pcrs, refvals, nil
}
