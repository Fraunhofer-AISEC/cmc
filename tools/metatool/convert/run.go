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

package convert

import (
	"context"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/global"
)

var log = logrus.WithField("service", "metatool")

const (
	inFlag      = "in"
	outFlag     = "out"
	outformFlag = "outform"
)

var Command = &cli.Command{
	Name:  "convert",
	Usage: "convert metadata between JSON and CBOR formats",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     inFlag,
			Usage:    "path to JSON or CBOR metadata",
			Required: true,
		},
		&cli.StringFlag{
			Name:     outFlag,
			Usage:    "path to output file for converted metadata",
			Required: true,
		},
		&cli.StringFlag{
			Name:     outformFlag,
			Usage:    "output format (json or cbor)",
			Required: true,
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		_, err := global.GetConfig(cmd)
		if err != nil {
			return fmt.Errorf("failed to get global config: %w", err)
		}

		log.Infof("Converting %v to %v", cmd.String(inFlag), cmd.String(outformFlag))

		data, err := os.ReadFile(cmd.String(inFlag))
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}

		raw, err := Convert(data, cmd.String(outformFlag))
		if err != nil {
			return fmt.Errorf("failed to convert: %w", err)
		}

		outFile := cmd.String(outFlag)
		log.Infof("Writing %v", outFile)
		err = os.WriteFile(outFile, raw, 0644)
		if err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}

		return nil
	},
}
