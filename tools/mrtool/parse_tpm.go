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

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/tpmdriver"
	"github.com/urfave/cli/v3"
)

type ParsePcrsConf struct {
	Eventlog       string
	PrintAggregate bool
}

const (
	DEFAULT_BINARY_BIOS_MEASUREMENTS = "/sys/kernel/security/tpm0/binary_bios_measurements"
)

const (
	tpmEventlogFlag    = "eventlog"
	printAggregateFlag = "print-aggregate"
)

func getParsePcrsConf(cmd *cli.Command) (*ParsePcrsConf, error) {
	c := &ParsePcrsConf{
		Eventlog:       cmd.String(tpmEventlogFlag),
		PrintAggregate: cmd.Bool(printAggregateFlag),
	}
	return c, nil
}

func checkParsePcrsConf(globConf *GlobalConfig, parsePcrsConf *ParsePcrsConf) error {

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

var parseTpmPcrCommand = &cli.Command{
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
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		err := ParsePcrs(cmd)
		if err != nil {
			return fmt.Errorf("failed to parse tpm srtm pcrs: %w", err)
		}
		return nil
	},
}

func ParsePcrs(cmd *cli.Command) error {

	globConf, err := getGlobalConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid global config: %w", err)
	}

	pcrConf, err := getParsePcrsConf(cmd)
	if err != nil {
		return fmt.Errorf("invalid tdx config: %w", err)
	}

	err = checkParsePcrsConf(globConf, pcrConf)
	if err != nil {
		return fmt.Errorf("failed to check parse pcrs config: %w", err)
	}

	log.Debug("Parsing tpm srtm pcr eventlog...")

	refvals, err := tpmdriver.GetBiosMeasurements(pcrConf.Eventlog)
	if err != nil {
		log.Warnf("failed to read binary bios measurements: %v. Using final PCR values as measurements",
			err)
	}
	log.Debugf("Collected %v binary bios measurements", len(refvals))

	// Only return requested PCRs
	filteredRefvals := make([]ar.ReferenceValue, 0, len(refvals))
	for _, refval := range refvals {
		if contains(globConf.Mrs, refval.Index) {
			filteredRefvals = append(filteredRefvals, refval)
		}
	}
	refvals = filteredRefvals

	// Write eventlog to stdout
	if globConf.PrintEventLog {
		data, err := json.MarshalIndent(refvals, "", "     ")
		if err != nil {
			return fmt.Errorf("failed to marshal reference values: %w", err)
		}
		os.Stdout.Write(append(data, []byte("\n")...))
	}

	// Calculate summary and write to stdout
	if globConf.PrintSummary {
		pcrValues, err := calculatePcrValues(refvals)
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
		pcrValues, err := calculatePcrValues(refvals)
		if err != nil {
			return fmt.Errorf("failed to calculate final PCR values")
		}
		hash := sha256.New()

		for _, val := range pcrValues {
			hash.Write(val.Sha256)
		}
		aggregateHash := hash.Sum(nil)
		aggregate := ar.ReferenceValue{
			Type:   "TPM PCR Aggregate",
			Index:  0,
			Sha256: aggregateHash,
		}
		data, err := json.MarshalIndent(aggregate, "", "     ")
		if err != nil {
			return fmt.Errorf("failed to marshal reference values: %w", err)
		}
		os.Stdout.Write(append(data, []byte("\n")...))
	}

	log.Debug("Finished")

	return nil
}

func calculatePcrValues(refvals []ar.ReferenceValue) ([]ar.ReferenceValue, error) {

	summaryMap := make(map[int][]byte)

	for _, rv := range refvals {
		old, ok := summaryMap[rv.Index]
		if !ok {
			// Initialize old value with init value (can be different from zero in PCR0)
			summaryMap[rv.Index] = rv.Sha256
			continue
		}
		log.Tracef("extending hash: %v", hex.EncodeToString(old))
		summaryMap[rv.Index] = internal.ExtendSha256(old, rv.Sha256)
		log.Tracef("data          : %v", hex.EncodeToString(rv.Sha256))
		log.Tracef("extended hash : %v", hex.EncodeToString(summaryMap[rv.Index]))
	}

	// Convert map back to slice
	var summaries []ar.ReferenceValue
	for idx, val := range summaryMap {
		summaries = append(summaries, ar.ReferenceValue{
			Type:    "TPM Reference Value",
			SubType: "PCR Summary",
			Index:   idx,
			Sha256:  val,
		})
	}

	// Sort summaries by index
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Index < summaries[j].Index
	})

	return summaries, nil
}
