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

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/internal/config"
)

// binaryName selects the config file and data folder of the binary
const binaryName = "cmcbackend"

func main() {

	cmd := &cli.Command{
		Name:    binaryName,
		Usage:   "CMC backend server for storing and providing attestation-results",
		Version: internal.GetVersionInfo().String(),
		Flags:   config.AllFlags(binaryName, &Config{}),
		Action:  serve,
		Commands: []*cli.Command{
			{
				Name:  "config",
				Usage: "Inspect the configuration without starting the server",
				Commands: []*cli.Command{
					{
						Name:   "validate",
						Usage:  "Load and validate the configuration, exit code 0 if it is valid",
						Action: validateConfig,
					},
					{
						Name:   "print",
						Usage:  "Print the effective configuration, with secrets redacted",
						Action: printEffectiveConfig,
					},
				},
			},
		},
	}

	// Errors are printed directly rather than logged, so that the multi-line
	// report of a bad configuration stays readable
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(_ context.Context, cmd *cli.Command) error {

	c, err := config.New[Config](cmd, binaryName)
	if err != nil {
		return err
	}
	if err := c.Log.Setup(); err != nil {
		return err
	}
	c.resolve()
	config.LogEffective(cmd, binaryName, c)
	if err := config.DirsOf(binaryName).Create(); err != nil {
		return err
	}

	log.Infof("Starting cmc-backend %v", internal.GetVersionInfo())

	s, err := newServer(c)
	if err != nil {
		return err
	}
	s.serve()

	return nil
}

func validateConfig(_ context.Context, cmd *cli.Command) error {
	if _, err := config.New[Config](cmd, binaryName); err != nil {
		return err
	}
	fmt.Println("configuration is valid")
	return nil
}

func printEffectiveConfig(_ context.Context, cmd *cli.Command) error {
	c, err := config.New[Config](cmd, binaryName)
	if err != nil {
		return err
	}
	c.resolve()
	s, err := config.Redacted(c)
	if err != nil {
		return err
	}
	fmt.Println(s)
	return nil
}
