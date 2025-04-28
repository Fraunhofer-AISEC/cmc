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
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
	log "github.com/sirupsen/logrus"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

const (
	DEFAULT_CCEL_ACPI_TABLE = "/sys/firmware/acpi/tables/data/CCEL"
)

func main() {

	eventlogFlag := flag.Bool("eventlog", false, "Print the eventlog for the TDX measurement registers")
	summaryFlag := flag.Bool("summary", false, "Print the final values of the TDX measurement registers")
	input := flag.String("input", DEFAULT_CCEL_ACPI_TABLE, "The CC eventlog file to be parsed")
	verbose := flag.Bool("verbose", false, "Print debug output")
	mrsFlag := flag.String("mrs", "1,2,3,4", "The MRS to be parsed as a comma separated list. 1: RTMR0, 2: RTMR1, 3: RTMR2, 4: RTMR3")
	flag.Parse()

	if *verbose {
		log.SetLevel(log.TraceLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	if !*eventlogFlag && !*summaryFlag {
		flag.Usage()
		log.Warnf("Neither eventlog nor summary have been provided. Do nothing")
		return
	}

	mrs := make([]int, 0)
	tmp := strings.Split(*mrsFlag, ",")
	for _, m := range tmp {
		mr, err := strconv.Atoi(m)
		if err != nil {
			log.Fatalf("Failed to convert MRS value: %v", err)
		}
		if mr < 1 || mr > 4 {
			flag.Usage()
			log.Fatalf("Invalid MRS value: %v. Only 1, 2, 3, and 4 are allowed", m)
		}
		mrs = append(mrs, mr)
	}

	if *input == "" {
		flag.Usage()
		log.Fatalf("CC eventlog input file has not been provided")
	}

	data, err := os.ReadFile(*input)
	if err != nil {
		log.Fatalf("Failed to read input file: %v", err)
	}

	err = parseEventlog(data, *eventlogFlag, *summaryFlag, mrs)
	if err != nil {
		log.Fatalf("%v", err)
	}

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

	data, err := json.MarshalIndent(refvals, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal eventlog: %w", err)
	}

	fmt.Printf("%v\n", string(data))

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

	data, err := json.MarshalIndent(summary, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal eventlog: %w", err)
	}

	fmt.Printf("%v\n", string(data))

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
