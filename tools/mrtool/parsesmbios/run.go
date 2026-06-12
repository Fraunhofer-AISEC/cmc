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

package parsesmbios

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/tcg"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

const (
	smbiosTablesFlag = "smbios-tables"
	jsonFlag         = "json"
)

var log = logrus.WithField("service", "mrtool")

var Command = &cli.Command{
	Name:  "smbios",
	Usage: "parse an etc/smbios/smbios-tables blob and dump its structures",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     smbiosTablesFlag,
			Usage:    "Path to the etc/smbios/smbios-tables blob to decode",
			Required: true,
		},
		&cli.BoolFlag{
			Name:  jsonFlag,
			Usage: "Emit machine-readable JSON instead of a text dump",
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		if err := run(cmd); err != nil {
			return fmt.Errorf("failed to parse smbios: %w", err)
		}
		return nil
	},
}

func run(cmd *cli.Command) error {
	path := cmd.String(smbiosTablesFlag)
	blob, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %q: %w", path, err)
	}
	log.Debugf("Parsing SMBIOS blob from %v (len %v)", path, len(blob))

	structs, err := tcg.ParseSmbiosStructures(blob)
	if err != nil {
		return err
	}

	if cmd.Bool(jsonFlag) {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(structs)
	}

	for _, s := range structs {
		fmt.Print(s.String())
	}
	return nil
}
