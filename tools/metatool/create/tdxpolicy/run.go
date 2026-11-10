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
	xfamIgnoreFlag    = "xfam-ignore-mask"
	debugFlag         = "debug"
	septVEDisableFlag = "sept-ve-disable"
	pksFlag           = "pks"
	klFlag            = "kl"
	acceptedTcbFlag   = "accepted-tcb-statuses"
)

const xfamLen = 8

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
		&cli.StringSliceFlag{
			Name:  xfamFlag,
			Usage: "allowed XFAM values (hex strings), comma-separated",
		},
		&cli.StringFlag{
			Name:  xfamIgnoreFlag,
			Usage: "XFAM bits to ignore during verification (hex string)",
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
		for _, x := range cmd.StringSlice(xfamFlag) {
			xfam, err := hex.DecodeString(x)
			if err != nil {
				return fmt.Errorf("failed to decode --xfam hex: %w", err)
			}
			if len(xfam) != xfamLen {
				return fmt.Errorf("invalid --xfam length %v (expected %v bytes)", len(xfam), xfamLen)
			}
			p.Xfam = append(p.Xfam, xfam)
		}
		if cmd.IsSet(xfamIgnoreFlag) {
			p.XfamIgnoreMask, err = hex.DecodeString(cmd.String(xfamIgnoreFlag))
			if err != nil {
				return fmt.Errorf("failed to decode --xfam-ignore-mask hex: %w", err)
			}
			if len(p.XfamIgnoreMask) != xfamLen {
				return fmt.Errorf("invalid --xfam-ignore-mask length %v (expected %v bytes)",
					len(p.XfamIgnoreMask), xfamLen)
			}
		}
		if cmd.IsSet(acceptedTcbFlag) {
			p.AcceptedTcbStatuses = strings.Split(cmd.String(acceptedTcbFlag), ",")
		}

		return create.Output(cmd, &p)
	},
}
