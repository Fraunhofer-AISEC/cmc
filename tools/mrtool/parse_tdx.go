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
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
	"github.com/urfave/cli/v3"
)

type ParseTdxConf struct {
	Eventlog string
}

const (
	DEFAULT_CCEL_ACPI_TABLE = "/sys/firmware/acpi/tables/data/CCEL"
)

const (
	ccEventlogFlag = "eventlog"
)

var parseTdxMrCommand = &cli.Command{
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
		err := ParseTdxMrs(c)
		if err != nil {
			return fmt.Errorf("failed to parse TDX event log: %w", err)
		}
		return nil
	},
}

func getParseTdxConf(cmd *cli.Command) (*ParseTdxConf, error) {

	c := &ParseTdxConf{
		Eventlog: cmd.String(ccEventlogFlag),
	}
	return c, nil
}

func checkParseTdxConf(globConf *GlobalConfig) error {

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

func ParseTdxMrs(cmd *cli.Command) error {

	globConf, err := getGlobalConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid global config: %w", err)
	}

	tdxConf, err := getParseTdxConf(cmd)
	if err != nil {
		return fmt.Errorf("invalid tdx config: %w", err)
	}

	err = checkParseTdxConf(globConf)
	if err != nil {
		return fmt.Errorf("failed to check IMA config: %w", err)
	}

	log.Debug("Parsing TDX MRs...")

	data, err := os.ReadFile(tdxConf.Eventlog)
	if err != nil {
		log.Fatalf("Failed to read input file: %v", err)
	}

	err = parseEventlog(data, globConf.PrintEventLog, globConf.PrintSummary, globConf.Mrs)
	if err != nil {
		log.Fatalf("%v", err)
	}

	return nil
}

func parseEventlog(data []byte, eventlogFlag, summaryFlag bool, mrs []int) error {
	eventlog, err := tcg.ParseEventLog(data, tcg.ParseOpts{AllowPadding: true})
	if err != nil {
		return fmt.Errorf("failed to parse CC eventlog: %w", err)
	}

	if eventlogFlag {
		err = printEventlog(eventlog, mrs)
		if err != nil {
			return fmt.Errorf("failed to print eventlog: %w", err)
		}
	}

	if summaryFlag {
		err = printSummary(eventlog, mrs)
		if err != nil {
			return fmt.Errorf("failed to print summary: %w", err)
		}
	}

	return nil
}

func printEventlog(l *tcg.EventLog, mrs []int) error {

	refvals := make([]ar.ReferenceValue, 0, len(l.Events(register.HashSHA384)))

	for _, event := range l.Events(register.HashSHA384) {

		if !contains(mrs, int(event.MRIndex())) {
			continue
		}

		index := int(event.MRIndex())

		refval := ar.ReferenceValue{
			Type:        "TDX Reference Value",
			SubType:     fmt.Sprintf("RTMR%v: %v", event.MRIndex()-1, event.Type.String()),
			Sha384:      event.Digest,
			Index:       index,
			Description: internal.FormatRtmrData(event.Data),
		}

		refvals = append(refvals, refval)
	}

	// Marshal eventlog
	data, err := json.MarshalIndent(refvals, "", "     ")
	if err != nil {
		return fmt.Errorf("failed to marshal reference values: %w", err)
	}

	// Write eventlog to stdout
	os.Stdout.Write(append(data, []byte("\n")...))

	return nil
}

func printSummary(l *tcg.EventLog, mrs []int) error {

	rtmrs := map[int][]byte{}
	for _, event := range l.Events(register.HashSHA384) {

		if !contains(mrs, int(event.MRIndex())) {
			continue
		}

		if _, ok := rtmrs[int(event.MRIndex())]; !ok {
			log.Debugf("Initializing RTMR%v", event.MRIndex()-1)
			rtmrs[int(event.MRIndex())] = make([]byte, 48)
		}

		log.Debugf("Extending RTMR%v with %v: %v", event.MRIndex()-1, event.Type, hex.EncodeToString(event.Digest))

		concat := append(rtmrs[int(event.MRIndex())], event.Digest...)
		h := sha512.Sum384(concat)
		rtmrs[int(event.MRIndex())] = h[:]
	}

	summary := make([]ar.ReferenceValue, 0, len(rtmrs))
	for index, rtmr := range rtmrs {
		refval := ar.ReferenceValue{
			Type:    "TDX Reference Value",
			SubType: fmt.Sprintf("RTMR%v", index-1),
			Index:   index,
			Sha384:  rtmr,
		}
		summary = append(summary, refval)
	}

	// Sort summaries by index
	sort.Slice(summary, func(i, j int) bool {
		return summary[i].Index < summary[j].Index
	})

	data, err := json.MarshalIndent(summary, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal eventlog: %w", err)
	}

	os.Stdout.Write(append(data, []byte("\n")...))

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
