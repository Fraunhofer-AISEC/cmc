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

package measure

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"github.com/Fraunhofer-AISEC/cmc/tools/ctrtool/global"
)

var log = logrus.WithField("service", "ctrtool")

const (
	bundleFlag = "bundle"
	nameFlag   = "name"
)

var Command = &cli.Command{
	Name:  "measure",
	Usage: "Compute reference value for an OCI runtime bundle",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     bundleFlag,
			Usage:    "path to OCI runtime bundle directory (containing rootfs/ and config.json)",
			Required: true,
		},
		&cli.StringFlag{
			Name:  nameFlag,
			Usage: "component name for the reference value",
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		_, err := global.GetConfig(cmd)
		if err != nil {
			return fmt.Errorf("failed to get global config: %w", err)
		}

		err = MeasureBundle(cmd.String(bundleFlag), cmd.String(nameFlag))
		if err != nil {
			return fmt.Errorf("failed to measure bundle: %w", err)
		}

		return nil
	},
}
