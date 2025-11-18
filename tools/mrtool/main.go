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
	"os"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/global"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/parseima"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/parsetdx"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/parsetpm"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/precomputeima"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/precomputesnp"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/precomputetdx"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/precomputetpm"
)

var (
	log = logrus.WithField("service", "mrtool")
)

func main() {
	cmd := &cli.Command{
		Name: "mrtool",
		Usage: "A tool to precompute and parse measurement registers (TPM PCRs, Intel TDX MRTD/RTMRs, AMD SEV-SNP MR) " +
			"to be used as reference values for attesting (confidential) virtual machines",
		Flags: global.Flags,
		Commands: []*cli.Command{
			{
				Name:  "parse",
				Usage: "parse measurements",
				Commands: []*cli.Command{
					parsetpm.Command,
					parsetdx.Command,
					parseima.Command,
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					return cli.ShowSubcommandHelp(c)
				},
			},
			{
				Name:  "precompute",
				Usage: "precompute measurements",
				Commands: []*cli.Command{
					precomputetpm.Command,
					precomputesnp.Command,
					precomputetdx.Command,
					precomputeima.Command,
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
