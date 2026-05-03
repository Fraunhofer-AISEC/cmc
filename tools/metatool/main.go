// Copyright (c) 2026 Fraunhofer AISEC
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
	"log"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/convert"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/create/imagedesc"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/create/manifest"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/create/manifestdesc"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/create/sgxpolicy"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/create/snppolicy"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/create/snpversion"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/create/tdxpolicy"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/global"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/sign"
)

func main() {
	cmd := &cli.Command{
		Name:  "metatool",
		Usage: "A tool to create, sign, and convert attestation metadata (manifests, image descriptions, manifest descriptions)",
		Flags: global.Flags,
		Commands: []*cli.Command{
			{
				Name:  "create",
				Usage: "create metadata objects",
				Commands: []*cli.Command{
					manifest.Command,
					manifestdesc.Command,
					imagedesc.Command,
					snppolicy.Command,
					snpversion.Command,
					tdxpolicy.Command,
					sgxpolicy.Command,
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					return cli.ShowSubcommandHelp(c)
				},
			},
			sign.Command,
			convert.Command,
		},
	}

	err := cmd.Run(context.Background(), os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
