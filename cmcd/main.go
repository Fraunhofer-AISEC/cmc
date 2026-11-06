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
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"github.com/Fraunhofer-AISEC/cmc/api"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

var (
	log = logrus.WithField("service", "cmcd")
)

func main() {
	cmd := &cli.Command{
		Name:    "cmcd",
		Usage:   "generates and verifies TPM, AMD SEV-SNP, Intel TDX, as well as SGX attestation evidence",
		Version: collectVersion(),
		Flags:   Flags,
		Action: func(ctx context.Context, cmd *cli.Command) error {
			c, err := GetConfig(cmd)
			if err != nil {
				return err
			}

			log.Infof("Running cmcd %v", internal.GetVersionInfo())

			cmcApi, addr, err := internal.ParseApiEndpoint(c.Cmc)
			if err != nil {
				return cli.Exit(err, 1)
			}
			server, ok := servers[cmcApi]
			if !ok {
				return cli.Exit(fmt.Sprintf("API %q is not implemented, available: %v", cmcApi,
					strings.Join(availableApis(), ", ")), 1)
			}

			cmcInst, err := cmc.NewCmc(&c.Config)
			if err != nil {
				return err
			}

			err = notifySystemd()
			if err != nil {
				return err
			}

			return server.Serve(addr, cmcInst)
		},
	}

	err := cmd.Run(context.Background(), os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func collectVersion() string {
	return fmt.Sprintf("%v, cmcd api version %v",
		internal.GetVersionInfo().String(),
		api.GetVersion())
}
