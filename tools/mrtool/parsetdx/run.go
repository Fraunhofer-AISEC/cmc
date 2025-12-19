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

package parsetdx

import (
	"context"
	"fmt"
	"os"

	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/global"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

type ParseTdxConf struct {
	Eventlog string
}

const (
	ccEventlogFlag = "eventlog"
)

var (
	log = logrus.WithField("service", "mrtool")
)

var Command = &cli.Command{
	Name:  "tdx",
	Usage: "Parses the Intel TDX Runtime Measurement Registers (RTMRs) from the CC eventlog ACPI table",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  ccEventlogFlag,
			Usage: "ACPI table CCEL event log path",
			Value: DEFAULT_CCEL_ACPI_TABLE,
		},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		err := run(c)
		if err != nil {
			return fmt.Errorf("failed to parse TDX event log: %w", err)
		}
		return nil
	},
}

func run(cmd *cli.Command) error {

	globConf, err := global.GetConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid global config: %w", err)
	}

	tdxConf, err := getConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid tdx config: %w", err)
	}

	err = checkConfig(globConf)
	if err != nil {
		return fmt.Errorf("failed to check IMA config: %w", err)
	}

	log.Info("Parsing TDX RTMRs...")

	data, err := os.ReadFile(tdxConf.Eventlog)
	if err != nil {
		log.Fatalf("Failed to read input file: %v", err)
	}

	err = parseEventlog(data, globConf.PrintEventLog, globConf.PrintSummary, globConf.Mrs)
	if err != nil {
		log.Fatalf("%v", err)
	}

	log.Info("Finished")

	return nil
}

func getConfig(cmd *cli.Command) (*ParseTdxConf, error) {

	c := &ParseTdxConf{
		Eventlog: cmd.String(ccEventlogFlag),
	}
	return c, nil
}

func checkConfig(globConf *global.Config) error {

	if !globConf.PrintEventLog && !globConf.PrintSummary {
		return fmt.Errorf("neither print-eventlog nor print-summary have been provided.  See mrtool parse tdx --help")
	}
	if len(globConf.Mrs) == 0 {
		return fmt.Errorf("no mrs specified. See mrtool parse tdx --help")
	}
	for _, mr := range globConf.Mrs {
		if mr < 1 || mr > 4 {
			return fmt.Errorf("invalid MRS value: %v. Only 1-4 are allowed. See mrtool parse tdx --help", mr)
		}
	}
	return nil
}
