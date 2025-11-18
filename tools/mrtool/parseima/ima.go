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

package parseima

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/ima"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/global"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

type ParseImaPcrConf struct {
	Eventlog string
}

const (
	DEFAULT_BINARY_RUNTIME_MEASUREMENTS = "/sys/kernel/security/ima/binary_runtime_measurements"
)

const (
	imaEventlogFlag = "eventlog"
)

var (
	log = logrus.WithField("service", "mrtool")
)

func getParseImaPcrConf(cmd *cli.Command) (*ParseImaPcrConf, error) {
	c := &ParseImaPcrConf{
		Eventlog: cmd.String(imaEventlogFlag),
	}
	return c, nil
}

func checkParseImaPcrConf(globConf *global.Config) error {

	if !globConf.PrintEventLog && !globConf.PrintSummary {
		return fmt.Errorf("neither eventlog nor summary have been provided. See mrtool parse ima --help")
	}
	if len(globConf.Mrs) != 1 {
		return fmt.Errorf("unexpected number of PCRs: %v. See mrtool parse ima --help", len(globConf.Mrs))
	}
	if globConf.Mrs[0] > 23 {
		return fmt.Errorf("unexpected PCR index %v. See mrtool parse ima --help", globConf.Mrs[0])
	}
	return nil
}

var Command = &cli.Command{
	Name:  "ima",
	Usage: "Parses the Linux kernel's Integrity Measurement Architecture (IMA) eventlog from the securityfs and prints the output",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  imaEventlogFlag,
			Usage: "ima eventlog input file",
			Value: DEFAULT_BINARY_RUNTIME_MEASUREMENTS,
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		err := ParseImaPcr(cmd)
		if err != nil {
			return fmt.Errorf("failed to parse ima pcr: %w", err)
		}
		return nil
	},
}

func ParseImaPcr(cmd *cli.Command) error {

	globConf, err := global.GetConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid global config: %w", err)
	}

	pcrConf, err := getParseImaPcrConf(cmd)
	if err != nil {
		return fmt.Errorf("invalid tdx config: %w", err)
	}

	err = checkParseImaPcrConf(globConf)
	if err != nil {
		return fmt.Errorf("failed to check IMA config: %w", err)
	}

	log.Debugf("Parsing ima tpm pcr eventlog %q...", pcrConf.Eventlog)

	events, err := ima.GetImaRuntimeDigests(pcrConf.Eventlog)
	if err != nil {
		return fmt.Errorf("failed to parse ima runtime digestes: %w", err)
	}

	refvals := make([]ar.ReferenceValue, 0, len(events))
	for _, event := range events {
		refval := ar.ReferenceValue{
			Type:        "TPM Reference Value",
			SubType:     filepath.Base(event.EventName),
			Index:       globConf.Mrs[0],
			Sha256:      event.Sha256,
			Description: event.EventName,
			EventData:   event.EventData,
			Optional:    true,
		}
		refvals = append(refvals, refval)
	}

	// Marshal eventlog
	data, err := json.MarshalIndent(refvals, "", "     ")
	if err != nil {
		return fmt.Errorf("failed to marshal reference values: %w", err)
	}

	// Write eventlog to stdout
	if globConf.PrintEventLog {
		os.Stdout.Write(append(data, []byte("\n")...))
	}

	return nil
}
