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

package tdxpolicy

import (
	"context"
	"encoding/hex"
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
	quoteVersionFlag  = "quote-version"
	mrOwnerFlag       = "mr-owner"
	mrOwnerConfigFlag = "mr-owner-config"
	mrConfigIdFlag    = "mr-config-id"
	xfamFlag          = "xfam"
	debugFlag         = "debug"
	septVEDisableFlag = "sept-ve-disable"
	pksFlag           = "pks"
	klFlag            = "kl"
	acceptedTcbFlag   = "accepted-tcb-statuses"
)

var Command = &cli.Command{
	Name:  "tdx-policy",
	Usage: "create an Intel TDX policy",
	Flags: append(create.OutputFlags,
		&cli.UintFlag{
			Name:  quoteVersionFlag,
			Usage: "TDX quote version",
		},
		&cli.StringFlag{
			Name:  mrOwnerFlag,
			Usage: "MR owner (hex string)",
		},
		&cli.StringFlag{
			Name:  mrOwnerConfigFlag,
			Usage: "MR owner config (hex string)",
		},
		&cli.StringFlag{
			Name:  mrConfigIdFlag,
			Usage: "MR config ID (hex string)",
		},
		&cli.StringFlag{
			Name:  xfamFlag,
			Usage: "XFAM value (hex string)",
		},
		&cli.BoolFlag{
			Name:  debugFlag,
			Usage: "allow debug mode",
		},
		&cli.BoolFlag{
			Name:  septVEDisableFlag,
			Usage: "SEPT VE disable",
		},
		&cli.BoolFlag{
			Name:  pksFlag,
			Usage: "PKS support",
		},
		&cli.BoolFlag{
			Name:  klFlag,
			Usage: "KL support",
		},
		&cli.StringFlag{
			Name:  acceptedTcbFlag,
			Usage: "accepted TCB statuses, comma-separated",
		},
	),
	Action: func(ctx context.Context, cmd *cli.Command) error {
		_, err := global.GetConfig(cmd)
		if err != nil {
			return fmt.Errorf("failed to get global config: %w", err)
		}

		log.Info("Creating TDX policy")

		p := ar.TdxPolicy{
			QuoteVersion: uint16(cmd.Uint(quoteVersionFlag)),
			TdAttributes: ar.TDAttributes{
				Debug:         cmd.Bool(debugFlag),
				SeptVEDisable: cmd.Bool(septVEDisableFlag),
				Pks:           cmd.Bool(pksFlag),
				Kl:            cmd.Bool(klFlag),
			},
		}

		if cmd.IsSet(mrOwnerFlag) {
			p.TdId.MrOwner, err = hex.DecodeString(cmd.String(mrOwnerFlag))
			if err != nil {
				return fmt.Errorf("failed to decode --mr-owner hex: %w", err)
			}
		}
		if cmd.IsSet(mrOwnerConfigFlag) {
			p.TdId.MrOwnerConfig, err = hex.DecodeString(cmd.String(mrOwnerConfigFlag))
			if err != nil {
				return fmt.Errorf("failed to decode --mr-owner-config hex: %w", err)
			}
		}
		if cmd.IsSet(mrConfigIdFlag) {
			p.TdId.MrConfigId, err = hex.DecodeString(cmd.String(mrConfigIdFlag))
			if err != nil {
				return fmt.Errorf("failed to decode --mr-config-id hex: %w", err)
			}
		}
		if cmd.IsSet(xfamFlag) {
			p.Xfam, err = hex.DecodeString(cmd.String(xfamFlag))
			if err != nil {
				return fmt.Errorf("failed to decode --xfam hex: %w", err)
			}
		}
		if cmd.IsSet(acceptedTcbFlag) {
			p.AcceptedTcbStatuses = strings.Split(cmd.String(acceptedTcbFlag), ",")
		}

		return create.Output(cmd, &p)
	},
}
