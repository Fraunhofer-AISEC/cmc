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
	"encoding/json"
	"fmt"
	"os"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/global"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/tcg"
	"github.com/Fraunhofer-AISEC/cmc/tpmdriver"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

type ParsePcrsConf struct {
	Eventlog       string
	PrintAggregate bool
	RawEventData   bool
}

const (
	DEFAULT_BINARY_BIOS_MEASUREMENTS = "/sys/kernel/security/tpm0/binary_bios_measurements"
)

const (
	tpmEventlogFlag    = "eventlog"
	printAggregateFlag = "print-aggregate"
	rawEventDataFlag   = "raw-event-data"
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
			Name:  rawEventDataFlag,
			Usage: "Additionally print the raw event data as it was extended if available",
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

	refvals, err := tpmdriver.GetBiosMeasurements(pcrConf.Eventlog, "TPM Reference Value", pcrConf.RawEventData)
	if err != nil {
		log.Warnf("failed to read binary bios measurements: %v. Using final PCR values as measurements",
			err)
	}
	log.Debugf("Collected %v binary bios measurements", len(refvals))

	// Only return requested PCRs
	filteredRefvals := make([]*ar.ReferenceValue, 0, len(refvals))
	for _, refval := range refvals {
		if contains(globConf.Mrs, refval.Index) {
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
		RawEventData:   cmd.Bool(rawEventDataFlag),
	}
	return c, nil
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
