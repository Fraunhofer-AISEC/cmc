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

package snppolicy

import (
	"context"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/create"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/global"
)

var log = logrus.WithField("service", "metatool")

const (
	reportMinFlag    = "report-min-version"
	reportMaxFlag    = "report-max-version"
	singleSocketFlag = "single-socket"
	debugFlag        = "debug"
	migrationFlag    = "migration"
	smtFlag          = "smt"
	abiMajorFlag     = "abi-major"
	abiMinorFlag     = "abi-minor"
	versionsFlag     = "versions"
)

var Command = &cli.Command{
	Name:  "snp-policy",
	Usage: "create an AMD SEV-SNP policy",
	Flags: append(create.OutputFlags,
		&cli.UintFlag{
			Name:  reportMinFlag,
			Usage: "minimum attestation report version",
		},
		&cli.UintFlag{
			Name:  reportMaxFlag,
			Usage: "maximum attestation report version",
		},
		&cli.BoolFlag{
			Name:  singleSocketFlag,
			Usage: "require single socket",
		},
		&cli.BoolFlag{
			Name:  debugFlag,
			Usage: "allow debug mode",
		},
		&cli.BoolFlag{
			Name:  migrationFlag,
			Usage: "allow migration",
		},
		&cli.BoolFlag{
			Name:  smtFlag,
			Usage: "allow SMT",
		},
		&cli.UintFlag{
			Name:  abiMajorFlag,
			Usage: "minimum ABI major version",
		},
		&cli.UintFlag{
			Name:  abiMinorFlag,
			Usage: "minimum ABI minor version",
		},
		&cli.StringFlag{
			Name:  versionsFlag,
			Usage: "paths to SNP version JSON files (created with 'create snp-version'), comma-separated",
		},
	),
	Action: func(ctx context.Context, cmd *cli.Command) error {
		_, err := global.GetConfig(cmd)
		if err != nil {
			return fmt.Errorf("failed to get global config: %w", err)
		}

		log.Info("Creating SNP policy")

		p := ar.SnpPolicy{
			ReportMinVersion: uint32(cmd.Uint(reportMinFlag)),
			ReportMaxVersion: uint32(cmd.Uint(reportMaxFlag)),
			GuestPolicy: ar.SnpGuestPolicy{
				Type:         "SNP Policy",
				SingleSocket: cmd.Bool(singleSocketFlag),
				Debug:        cmd.Bool(debugFlag),
				Migration:    cmd.Bool(migrationFlag),
				Smt:          cmd.Bool(smtFlag),
				AbiMajor:     uint8(cmd.Uint(abiMajorFlag)),
				AbiMinor:     uint8(cmd.Uint(abiMinorFlag)),
			},
		}

		if cmd.IsSet(versionsFlag) {
			for path := range strings.SplitSeq(cmd.String(versionsFlag), ",") {
				v, err := create.LoadJSON[ar.SnpVersion](path)
				if err != nil {
					return fmt.Errorf("failed to load SNP version from %v: %w", path, err)
				}
				p.VersionPolicy = append(p.VersionPolicy, *v)
			}
		}

		return create.Output(cmd, &p)
	},
}
