// Copyright (c) 2021 - 2026 Fraunhofer AISEC
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

func main() {
	cmd := &cli.Command{
		Name:    "estserver",
		Usage:   "EST provisioning server with attestation support",
		Version: internal.GetVersionInfo().String(),
		Flags:   flags(),
		Action:  serve,
		Commands: []*cli.Command{
			{
				Name:  "config",
				Usage: "inspect the configuration without starting the server",
				Commands: []*cli.Command{
					{
						Name:   "validate",
						Usage:  "load and validate the configuration, without any side effects",
						Action: validateConfig,
					},
					{
						Name:   "print",
						Usage:  "print the effective configuration as JSON, secrets redacted",
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

func serve(ctx context.Context, cmd *cli.Command) error {

	c, err := getConfig(cmd)
	if err != nil {
		return err
	}

	if err := setupLogging(c); err != nil {
		return err
	}
	printConfig(c)

	log.Infof("Starting EST server %v", internal.GetVersionInfo())

	if err := c.resolve(); err != nil {
		return err
	}

	s, err := NewServer(c)
	if err != nil {
		return err
	}

	return s.Serve()
}

func validateConfig(ctx context.Context, cmd *cli.Command) error {

	if _, err := getConfig(cmd); err != nil {
		return err
	}

	fmt.Println("configuration is valid")

	return nil
}

func printEffectiveConfig(ctx context.Context, cmd *cli.Command) error {

	c, err := getConfig(cmd)
	if err != nil {
		return err
	}

	s, err := config.Redacted(c)
	if err != nil {
		return err
	}

	fmt.Println(s)

	return nil
}
