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

package parsetpm

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers/tpmdriver"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/global"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/tcg"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

type ParsePcrsConf struct {
	Eventlog       string
	PrintAggregate bool
	EventData      bool
	Algorithms     []string
}

const (
	DEFAULT_BINARY_BIOS_MEASUREMENTS = "/sys/kernel/security/tpm0/binary_bios_measurements"
)

const (
	tpmEventlogFlag    = "eventlog"
	printAggregateFlag = "print-aggregate"
	eventDataFlag      = "event-data"
	algorithmFlag      = "algorithms"
)

var (
	log = logrus.WithField("service", "mrtool")
)

var Command = &cli.Command{
	Name:  "tpm",
	Usage: "parses the SRTM TPM eventlog from the Linux kernel securityfs binary_bios_measurements",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  tpmEventlogFlag,
			Usage: "TPM eventlog input file",
			Value: DEFAULT_BINARY_BIOS_MEASUREMENTS,
		},
		&cli.BoolFlag{
			Name:  printAggregateFlag,
			Usage: "Print the aggregated PCR value over the selected PCRs",
		},
		&cli.BoolFlag{
			Name:  eventDataFlag,
			Usage: "Additionally add extended event data if available",
		},
		&cli.StringFlag{
			Name: algorithmFlag,
			Usage: "Comma-separated list of PCR Bank hash algorithms to retrieve. " +
				"If not specified, fetches all available PCR banks. Possible: SHA-256, SHA-384",
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		err := run(cmd)
		if err != nil {
			return fmt.Errorf("failed to parse tpm srtm pcrs: %w", err)
		}
		return nil
	},
}

func run(cmd *cli.Command) error {

	globConf, err := global.GetConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid global config: %w", err)
	}

	pcrConf, err := getConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid tdx config: %w", err)
	}

	err = checkConfig(globConf, pcrConf)
	if err != nil {
		return fmt.Errorf("failed to check parse pcrs config: %w", err)
	}

	log.Info("Parsing TPM SRTM PCR eventlog...")

	algs := make([]crypto.Hash, 0, len(pcrConf.Algorithms))
	for _, s := range pcrConf.Algorithms {
		alg, err := internal.HashFromString(s)
		if err != nil {
			return fmt.Errorf("failed to convert hash alg: %w", err)
		}
		algs = append(algs, alg)
		log.Tracef("Added PCR bank hash algorithm %v", s)
	}
	if len(algs) == 0 {
		log.Trace("No algorithms specified: retrieving all available PCR banks")
	}

	refvals, err := tpmdriver.GetBiosMeasurements(pcrConf.Eventlog, pcrConf.EventData, algs)
	if err != nil {
		return fmt.Errorf("failed to read binary bios measurements: %w", err)
	}
	log.Debugf("Collected %v binary bios measurements", len(refvals))

	// Only return requested PCRs
	filteredRefvals := make([]*ar.Component, 0, len(refvals))
	for _, refval := range refvals {
		index, err := refval.GetIndex()
		if err != nil {
			return fmt.Errorf("failed to get index: %w", err)
		}
		if contains(globConf.Mrs, index) {
			filteredRefvals = append(filteredRefvals, &refval)
		}
	}

	// Write eventlog to stdout
	if globConf.PrintEventLog {
		data, err := json.MarshalIndent(filteredRefvals, "", "     ")
		if err != nil {
			return fmt.Errorf("failed to marshal reference values: %w", err)
		}
		os.Stdout.Write(append(data, []byte("\n")...))
	}

	// Calculate summary and write to stdout
	if globConf.PrintSummary {
		pcrValues, err := tcg.PrecomputeFinalPcrValues(filteredRefvals)
		if err != nil {
			return fmt.Errorf("failed to calculate final PCR values")
		}
		data, err := json.MarshalIndent(pcrValues, "", "     ")
		if err != nil {
			return fmt.Errorf("failed to marshal reference values: %w", err)
		}
		os.Stdout.Write(append(data, []byte("\n")...))
	}

	// Calculate aggregate and write to stdout
	if pcrConf.PrintAggregate {
		aggregate, err := tcg.PrecomputeAggregatePcrValue(filteredRefvals)
		if err != nil {
			return fmt.Errorf("failed to calculate aggregate PCR value")
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

func getConfig(cmd *cli.Command) (*ParsePcrsConf, error) {
	c := &ParsePcrsConf{
		Eventlog:       cmd.String(tpmEventlogFlag),
		PrintAggregate: cmd.Bool(printAggregateFlag),
		EventData:      cmd.Bool(eventDataFlag),
	}

	algos := cmd.String(algorithmFlag)
	if algos != "" {
		c.Algorithms = strings.Split(algos, ",")
	}

	c.Print()

	return c, nil
}

func (c *ParsePcrsConf) Print() {
	log.Debugf("Parse TPM Config")
	log.Debugf("\tEventlog : %v\n", c.Eventlog)
	log.Debugf("\tAggregate: %v\n", c.PrintAggregate)
	log.Debugf("\tEventData: %v\n", c.EventData)
	log.Debugf("\tAlgos    : %v\n", c.Algorithms)
}

func checkConfig(globConf *global.Config, parsePcrsConf *ParsePcrsConf) error {

	if !globConf.PrintEventLog && !globConf.PrintSummary && !parsePcrsConf.PrintAggregate {
		return fmt.Errorf("neither eventlog nor summary or aggregate are set. Do nothing")
	}
	for _, mr := range globConf.Mrs {
		if mr > 23 {
			return fmt.Errorf("invalid PCR value: %v. Only 0-23 are allowed", mr)
		}
	}
	return nil
}

func contains(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
