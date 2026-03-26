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
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/publish"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

var (
	logLevels = map[string]logrus.Level{
		"panic": logrus.PanicLevel,
		"fatal": logrus.FatalLevel,
		"error": logrus.ErrorLevel,
		"warn":  logrus.WarnLevel,
		"info":  logrus.InfoLevel,
		"debug": logrus.DebugLevel,
		"trace": logrus.TraceLevel,
	}

	log = logrus.WithField("service", "ocsfgen")
)

type Config struct {
	Mrs           []int  `json:"mrs"`
	LogLevel      string `json:"logLevel"`
	PrintEventLog bool   `json:"eventLog"`
	PrintSummary  bool   `json:"summary"`
}

const (
	logLevelFlag = "log-level"
	inputFlag    = "in"
)

func main() {
	cmd := &cli.Command{
		Name:  "ocsfgen",
		Usage: "A tool to generate OCSF detection findings based on attestation results",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  logLevelFlag,
				Usage: fmt.Sprintf("set log level. Possible: %v", strings.Join(maps.Keys(logLevels), ",")),
			},
			&cli.StringFlag{
				Name:     inputFlag,
				Usage:    "Input file containing the attestation report",
				Required: true,
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

	err := cmd.Run(context.Background(), os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func run(cmd *cli.Command) error {

	if cmd.IsSet(logLevelFlag) {
		logLevel := cmd.String(logLevelFlag)
		if logLevel != "" {
			l, ok := logLevels[strings.ToLower(logLevel)]
			if !ok {
				log.Warnf("LogLevel %v does not exist. Default to info level", logLevel)
				l = logrus.InfoLevel
			}
			logrus.SetLevel(l)
		} else {
			logrus.SetLevel(logrus.InfoLevel)
		}
	}

	inputFile := cmd.String(inputFlag)
	if inputFile == "" {
		cli.ShowAppHelpAndExit(cmd, 1)
	}

	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	result := new(attestationreport.AttestationResult)
	err = json.Unmarshal(data, result)
	if err != nil {
		return fmt.Errorf("failed to unmarshal attestation result: %w", err)
	}

	findings := publish.CreateDetectionFindings(result)

	out, err := json.Marshal(findings)
	if err != nil {
		return fmt.Errorf("failed to marshal OCSF detection findings: %w", err)
	}

	os.Stdout.Write(out)

	return nil
}
