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

package sign

import (
	"context"
	"fmt"
	"os"

	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/global"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

var log = logrus.WithField("service", "metatool")

const (
	inFlag   = "in"
	outFlag  = "out"
	keysFlag = "keys"
	x5csFlag = "x5cs"
)

var Command = &cli.Command{
	Name:  "sign",
	Usage: "sign metadata with private keys and certificate chains",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     inFlag,
			Usage:    "path to input metadata as JSON or CBOR to be signed",
			Required: true,
		},
		&cli.StringFlag{
			Name:     outFlag,
			Usage:    "path to the output file to save signed metadata",
			Required: true,
		},
		&cli.StringFlag{
			Name:     keysFlag,
			Usage:    "paths to keys in PEM format, comma-separated",
			Required: true,
		},
		&cli.StringFlag{
			Name:     x5csFlag,
			Usage:    "paths to PEM encoded x509 certificate chains. Chains colon-separated, certs within a chain comma-separated (e.g. leaf1,intermediate1,ca1:leaf2,intermediate2,ca2)",
			Required: true,
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		_, err := global.GetConfig(cmd)
		if err != nil {
			return fmt.Errorf("failed to get global config: %w", err)
		}

		data, err := os.ReadFile(cmd.String(inFlag))
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}

		keysPem, err := LoadKeys(cmd.String(keysFlag))
		if err != nil {
			return fmt.Errorf("failed to load keys: %w", err)
		}

		chainsPem, err := LoadCertChains(cmd.String(x5csFlag))
		if err != nil {
			return fmt.Errorf("failed to load certificate chains: %w", err)
		}

		signedData, err := Sign(data, keysPem, chainsPem)
		if err != nil {
			return fmt.Errorf("failed to sign data: %w", err)
		}

		outFile := cmd.String(outFlag)
		log.Infof("Writing %v", outFile)
		err = os.WriteFile(outFile, signedData, 0644)
		if err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}

		return nil
	},
}
