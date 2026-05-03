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

package manifestdesc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/create"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/global"
)

const (
	inFlag          = "in"
	nameFlag        = "name"
	descriptionFlag = "description"
	manifestFlag    = "manifest"
	ociRulesFlag    = "oci-rules"
)

var Command = &cli.Command{
	Name:  "manifest-description",
	Usage: "create a manifest description metadata object",
	Flags: append(create.OutputFlags,
		&cli.StringFlag{
			Name:  inFlag,
			Usage: "path to an existing manifest description JSON file to use as base (optional)",
		},
		&cli.StringFlag{
			Name:  nameFlag,
			Usage: "manifest description name",
		},
		&cli.StringFlag{
			Name:  descriptionFlag,
			Usage: "manifest description text",
		},
		&cli.StringFlag{
			Name:  manifestFlag,
			Usage: "name of the manifest this description refers to",
		},
		&cli.StringFlag{
			Name:  ociRulesFlag,
			Usage: "path to a JSON file containing OCI rules",
		},
	),
	Action: func(ctx context.Context, cmd *cli.Command) error {
		_, err := global.GetConfig(cmd)
		if err != nil {
			return fmt.Errorf("failed to get global config: %w", err)
		}

		md, err := buildManifestDescription(cmd)
		if err != nil {
			return err
		}

		return create.Output(cmd, md)
	},
}

func buildManifestDescription(cmd *cli.Command) (*ar.ManifestDescription, error) {
	md := &ar.ManifestDescription{}

	if cmd.IsSet(inFlag) {
		data, err := os.ReadFile(cmd.String(inFlag))
		if err != nil {
			return nil, fmt.Errorf("failed to read input file: %w", err)
		}
		if err := json.Unmarshal(data, md); err != nil {
			return nil, fmt.Errorf("failed to parse input file: %w", err)
		}
	}

	md.Type = ar.TYPE_MANIFEST_DESCRIPTION

	if cmd.IsSet(nameFlag) {
		md.Name = cmd.String(nameFlag)
	}
	if cmd.IsSet(descriptionFlag) {
		md.Description = cmd.String(descriptionFlag)
	}
	if cmd.IsSet(manifestFlag) {
		md.Manifest = cmd.String(manifestFlag)
	}
	if cmd.IsSet(ociRulesFlag) {
		data, err := os.ReadFile(cmd.String(ociRulesFlag))
		if err != nil {
			return nil, fmt.Errorf("failed to read OCI rules file: %w", err)
		}
		var rules map[string]any
		if err := json.Unmarshal(data, &rules); err != nil {
			return nil, fmt.Errorf("failed to parse OCI rules: %w", err)
		}
		md.OciRules = rules
	}

	return md, nil
}
