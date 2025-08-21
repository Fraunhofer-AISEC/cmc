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
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

type GlobalConfig struct {
	Mrs           []int  `json:"mrs"`
	LogLevel      string `json:"logLevel"`
	PrintEventLog bool   `json:"eventLog"`
	PrintSummary  bool   `json:"summary"`
}

const (
	mrsFlag      = "mrs"
	logLevelFlag = "log-level"
	eventlogFlag = "print-eventlog"
	summaryFlag  = "print-summary"
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

	log = logrus.WithField("service", "mrtool")
)

func getGlobalConfig(cmd *cli.Command) (*GlobalConfig, error) {

	c := &GlobalConfig{}

	if cmd.IsSet(mrsFlag) {
		mrs, err := StrToInt(strings.Split(cmd.String(mrsFlag), ","))
		if err != nil {
			return nil, fmt.Errorf("failed to convert PCRs: %w", err)
		}
		c.Mrs = mrs
	}
	if cmd.IsSet(logLevelFlag) {
		c.LogLevel = cmd.String(logLevelFlag)
	}
	c.PrintEventLog = cmd.Bool(eventlogFlag)
	if cmd.IsSet(summaryFlag) {
		c.PrintSummary = cmd.Bool(summaryFlag)
	}

	if c.LogLevel != "" {
		l, ok := logLevels[strings.ToLower(c.LogLevel)]
		if !ok {
			log.Warnf("LogLevel %v does not exist. Default to info level", c.LogLevel)
			l = logrus.InfoLevel
		}
		logrus.SetLevel(l)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	printGlobalConfig(c)

	return c, nil
}

func printGlobalConfig(c *GlobalConfig) {
	log.Debugf("Global Config")
	log.Debugf("\tMRs      : %v\n", c.Mrs)
	log.Debugf("\tLogLevel : %v\n", c.LogLevel)
	log.Debugf("\tEventLog : %v\n", c.PrintEventLog)
	log.Debugf("\tSummary  : %v\n", c.PrintSummary)
}

func main() {
	cmd := &cli.Command{
		Name: "mrtool",
		Usage: "A tool to precompute and parse measurement registers (TPM PCRs, Intel TDX MRTD/RTMRs, AMD SEV-SNP MR) " +
			"to be used as reference values for attesting (confidential) virtual machines",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  mrsFlag,
				Usage: "measurement registers",
			},
			&cli.StringFlag{
				Name:  logLevelFlag,
				Usage: fmt.Sprintf("set log level. Possible: %v", strings.Join(maps.Keys(logLevels), ",")),
			},
			&cli.BoolFlag{
				Name:  eventlogFlag,
				Usage: "print event log",
				Value: true,
			},
			&cli.BoolFlag{
				Name:  summaryFlag,
				Usage: "print summary",
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "parse",
				Usage: "parse measurements",
				Commands: []*cli.Command{
					parseTpmPcrCommand,
					parseTdxMrCommand,
					parseImaPcrCommand,
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					return cli.ShowSubcommandHelp(c)
				},
			},
			{
				Name:  "precompute",
				Usage: "precompute measurements",
				Commands: []*cli.Command{
					precomputeTpmPcrsCommand,
					precomputeSnpMrCommand,
					precomputeTdxMrCommand,
					precomputeImaPcrCommand,
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					return cli.ShowSubcommandHelp(c)
				},
			},
		},
	}

	err := cmd.Run(context.Background(), os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func StrToInt(strs []string) ([]int, error) {
	ints := make([]int, len(strs))
	for i, s := range strs {
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("invalid number %q: %w", s, err)
		}
		ints[i] = n
	}
	return ints, nil
}
