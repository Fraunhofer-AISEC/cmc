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

package sgxpolicy

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/urfave/cli/v3"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/create"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/global"
)

const (
	quoteVersionFlag = "quote-version"
	mrSignerFlag     = "mr-signer"
	isvSvnFlag       = "isv-svn"
	inittedFlag      = "initted"
	debugFlag        = "debug"
	mode64BitFlag    = "mode64bit"
	provisionKeyFlag = "provision-key"
	eInitTokenFlag   = "einit-token"
	kssFlag          = "kss"
	legacyFlag       = "legacy"
	avxFlag          = "avx"
	acceptedTcbFlag  = "accepted-tcb-statuses"
)

var Command = &cli.Command{
	Name:  "sgx-policy",
	Usage: "create an Intel SGX policy",
	Flags: append(create.OutputFlags,
		&cli.UintFlag{
			Name:  quoteVersionFlag,
			Usage: "SGX quote version",
		},
		&cli.StringFlag{
			Name:  mrSignerFlag,
			Usage: "MR signer hash (hex string)",
		},
		&cli.UintFlag{
			Name:  isvSvnFlag,
			Usage: "ISV security version number",
		},
		&cli.BoolFlag{
			Name:  inittedFlag,
			Usage: "enclave initialized",
		},
		&cli.BoolFlag{
			Name:  debugFlag,
			Usage: "allow debug mode",
		},
		&cli.BoolFlag{
			Name:  mode64BitFlag,
			Usage: "64-bit mode",
		},
		&cli.BoolFlag{
			Name:  provisionKeyFlag,
			Usage: "provision key access",
		},
		&cli.BoolFlag{
			Name:  eInitTokenFlag,
			Usage: "EINIT token key access",
		},
		&cli.BoolFlag{
			Name:  kssFlag,
			Usage: "KSS support",
		},
		&cli.BoolFlag{
			Name:  legacyFlag,
			Usage: "legacy mode",
		},
		&cli.BoolFlag{
			Name:  avxFlag,
			Usage: "AVX support",
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

		p := ar.SgxPolicy{
			QuoteVersion: uint16(cmd.Uint(quoteVersionFlag)),
			IsvSvn:       uint16(cmd.Uint(isvSvnFlag)),
			Attributes: ar.SGXAttributes{
				Initted:      cmd.Bool(inittedFlag),
				Debug:        cmd.Bool(debugFlag),
				Mode64Bit:    cmd.Bool(mode64BitFlag),
				ProvisionKey: cmd.Bool(provisionKeyFlag),
				EInitToken:   cmd.Bool(eInitTokenFlag),
				Kss:          cmd.Bool(kssFlag),
				Legacy:       cmd.Bool(legacyFlag),
				Avx:          cmd.Bool(avxFlag),
			},
		}

		if cmd.IsSet(mrSignerFlag) {
			p.MrSigner, err = hex.DecodeString(cmd.String(mrSignerFlag))
			if err != nil {
				return fmt.Errorf("failed to decode --mr-signer hex: %w", err)
			}
		}
		if cmd.IsSet(acceptedTcbFlag) {
			p.AcceptedTcbStatuses = strings.Split(cmd.String(acceptedTcbFlag), ",")
		}

		return create.Output(cmd, &p)
	},
}
