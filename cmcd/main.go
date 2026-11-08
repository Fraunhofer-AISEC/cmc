// Copyright (c) 2021 Fraunhofer AISEC
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

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"github.com/Fraunhofer-AISEC/cmc/api"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/internal/config"
)

var (
	log = logrus.WithField("service", "cmcd")
)

func main() {
	cmd := &cli.Command{
		Name:    "cmcd",
		Usage:   "generates and verifies TPM, AMD SEV-SNP, Intel TDX, as well as SGX attestation evidence",
		Version: collectVersion(),
		Flags:   config.AllFlags(&Config{}),
		Action:  serve,
		Commands: []*cli.Command{
			{
				Name:  "config",
				Usage: "Inspect the configuration without starting the cmcd",
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

	c, err := config.New[Config](cmd)
	if err != nil {
		return err
	}
	if err := c.Log.Setup(); err != nil {
		return err
	}
	config.LogEffective("cmcd", c)

	log.Infof("Running cmcd %v", internal.GetVersionInfo())

	// The API is validated as part of the configuration
	name, addr, _ := internal.ParseApiEndpoint(c.Api.Endpoint)

	rootCas, err := internal.ReadCerts(c.Trust.RootCas)
	if err != nil {
		return fmt.Errorf("failed to read trusted root CA certificates: %w", err)
	}

	cmcInst, err := cmc.NewCmc(&c.Cmc, rootCas, c.Trust.AllowSystemCerts)
	if err != nil {
		return err
	}

	if err := notifySystemd(); err != nil {
		return err
	}

	return servers[name].Serve(addr, cmcInst)
}

func validateConfig(_ context.Context, cmd *cli.Command) error {
	if _, err := config.New[Config](cmd); err != nil {
		return err
	}
	fmt.Println("configuration is valid")
	return nil
}

func printEffectiveConfig(_ context.Context, cmd *cli.Command) error {
	c, err := config.New[Config](cmd)
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

func collectVersion() string {
	return fmt.Sprintf("%v, cmcd api version %v",
		internal.GetVersionInfo().String(),
		api.GetVersion())
}
