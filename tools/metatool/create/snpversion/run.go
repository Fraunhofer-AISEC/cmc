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

package snpversion

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/create"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/global"
)

const (
	nameFlag     = "name"
	fwBuildFlag  = "fw-build"
	fwMajorFlag  = "fw-major"
	fwMinorFlag  = "fw-minor"
	tcbFmcFlag   = "tcb-fmc"
	tcbBlFlag    = "tcb-bl"
	tcbTeeFlag   = "tcb-tee"
	tcbSnpFlag   = "tcb-snp"
	tcbUcodeFlag = "tcb-ucode"
)

var Command = &cli.Command{
	Name:  "snp-version",
	Usage: "create an AMD SEV-SNP version policy entry",
	Flags: append(create.OutputFlags,
		&cli.StringFlag{
			Name:     nameFlag,
			Usage:    "processor code name (e.g. milan, genoa, turin)",
			Required: true,
		},
		&cli.UintFlag{
			Name:  fwBuildFlag,
			Usage: "firmware build number",
		},
		&cli.UintFlag{
			Name:  fwMajorFlag,
			Usage: "firmware major version",
		},
		&cli.UintFlag{
			Name:  fwMinorFlag,
			Usage: "firmware minor version",
		},
		&cli.UintFlag{
			Name:  tcbFmcFlag,
			Usage: "TCB FMC version",
		},
		&cli.UintFlag{
			Name:  tcbBlFlag,
			Usage: "TCB bootloader version",
		},
		&cli.UintFlag{
			Name:  tcbTeeFlag,
			Usage: "TCB TEE version",
		},
		&cli.UintFlag{
			Name:  tcbSnpFlag,
			Usage: "TCB SNP version",
		},
		&cli.UintFlag{
			Name:  tcbUcodeFlag,
			Usage: "TCB microcode version",
		},
	),
	Action: func(ctx context.Context, cmd *cli.Command) error {
		_, err := global.GetConfig(cmd)
		if err != nil {
			return fmt.Errorf("failed to get global config: %w", err)
		}

		v := ar.SnpVersion{
			Name: cmd.String(nameFlag),
			Fw: ar.SnpFw{
				Build: uint8(cmd.Uint(fwBuildFlag)),
				Major: uint8(cmd.Uint(fwMajorFlag)),
				Minor: uint8(cmd.Uint(fwMinorFlag)),
			},
			Tcb: ar.SnpTcb{
				Fmc:   uint8(cmd.Uint(tcbFmcFlag)),
				Bl:    uint8(cmd.Uint(tcbBlFlag)),
				Tee:   uint8(cmd.Uint(tcbTeeFlag)),
				Snp:   uint8(cmd.Uint(tcbSnpFlag)),
				Ucode: uint8(cmd.Uint(tcbUcodeFlag)),
			},
		}

		return create.Output(cmd, &v)
	},
}
