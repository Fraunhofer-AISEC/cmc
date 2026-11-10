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
	log = logrus.WithField("service", binaryName)
)

// binaryName selects the config file and data folder of the binary
const binaryName = "cmcd"

func main() {
	cmd := &cli.Command{
		Name:    binaryName,
		Usage:   "generates and verifies TPM, AMD SEV-SNP, Intel TDX, as well as SGX attestation evidence",
		Version: collectVersion(),
		Flags:   config.AllFlags(binaryName, &Config{}),
		Action:  serve,
		Commands: []*cli.Command{
			config.Command[Config](binaryName, nil),
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
	config.LogEffective(cmd, binaryName, c, true)
	if err := config.DirsOf(binaryName).Create(); err != nil {
		return err
	}

	log.Infof("Running cmcd %v", internal.GetVersionInfo())

	// The API is validated as part of the configuration
	name, addr, _ := internal.ParseApiEndpoint(c.Api.Endpoint)

	rootCas, err := internal.ReadCerts(c.Trust.RootCas)
	if err != nil {
		return fmt.Errorf("trust.root_cas: failed to read trusted root CAs: %w", err)
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

func collectVersion() string {
	return fmt.Sprintf("%v, cmcd api version %v",
		internal.GetVersionInfo().String(),
		api.GetVersion())
}
