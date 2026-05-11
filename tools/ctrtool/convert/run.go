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
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"github.com/Fraunhofer-AISEC/cmc/tools/ctrtool/global"
)

var log = logrus.WithField("service", "ctrtool")

const (
	inFlag             = "in"
	outFlag            = "out"
	apparmorFlag       = "apparmor"
	cpusFlag           = "cpus"
	additionalGidsFlag = "additional-gids"
)

var Command = &cli.Command{
	Name:  "convert",
	Usage: "convert OCI image to OCI runtime bundle",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     inFlag,
			Usage:    "path to OCI image",
			Required: true,
		},
		&cli.StringFlag{
			Name:     outFlag,
			Usage:    "OCI runtime bundle output directory",
			Required: true,
		},
		&cli.BoolFlag{
			Name:  apparmorFlag,
			Usage: "set the docker-default AppArmor profile in the generated spec",
		},
		&cli.IntFlag{
			Name:  cpusFlag,
			Usage: "number of CPUs on the target host (for thermal_throttle masked paths)",
			Value: 0,
		},
		&cli.StringFlag{
			Name:  additionalGidsFlag,
			Usage: "comma-separated supplementary GIDs for the container process",
			Value: "0",
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		_, err := global.GetConfig(cmd)
		if err != nil {
			return fmt.Errorf("failed to get global config: %w", err)
		}

		gids, err := parseGIDs(cmd.String(additionalGidsFlag))
		if err != nil {
			return fmt.Errorf("failed to parse --%s: %w", additionalGidsFlag, err)
		}

		opts := ConvertOpts{
			AppArmor:       cmd.Bool(apparmorFlag),
			CPUs:           int(cmd.Int(cpusFlag)),
			AdditionalGIDs: gids,
		}
		err = Convert(cmd.String(inFlag), cmd.String(outFlag), opts)
		if err != nil {
			return fmt.Errorf("failed to convert: %w", err)
		}

		return nil
	},
}

func parseGIDs(s string) ([]uint32, error) {
	var gids []uint32
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid GID %q: %w", part, err)
		}
		gids = append(gids, uint32(v))
	}
	if len(gids) == 0 {
		return nil, fmt.Errorf("at least one GID is required")
	}
	return gids, nil
}
