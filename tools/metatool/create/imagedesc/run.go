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

package imagedesc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/create"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/global"
)

var log = logrus.WithField("service", "metatool")

const (
	inFlag           = "in"
	nameFlag         = "name"
	versionFlag      = "version"
	descriptionFlag  = "description"
	notBeforeFlag    = "not-before"
	notAfterFlag     = "not-after"
	locationFlag     = "location"
	descriptionsFlag = "descriptions"
	addDescFlag      = "add-description"
)

var Command = &cli.Command{
	Name:  "image-description",
	Usage: "create an image description metadata object",
	Flags: append(create.OutputFlags,
		&cli.StringFlag{
			Name:  inFlag,
			Usage: "path to an existing image description JSON file to use as base (optional)",
		},
		&cli.StringFlag{
			Name:  nameFlag,
			Usage: "image description name",
		},
		&cli.StringFlag{
			Name:  versionFlag,
			Usage: "image description version",
		},
		&cli.StringFlag{
			Name:  descriptionFlag,
			Usage: "image description text",
		},
		&cli.StringFlag{
			Name:  notBeforeFlag,
			Usage: "validity not before",
		},
		&cli.StringFlag{
			Name:  notAfterFlag,
			Usage: "validity not after",
		},
		&cli.StringFlag{
			Name:  locationFlag,
			Usage: "image location",
		},
		&cli.StringFlag{
			Name:  descriptionsFlag,
			Usage: "paths to manifest description JSON files, comma-separated",
		},
		&cli.StringFlag{
			Name:  addDescFlag,
			Usage: "path to a manifest description JSON file to add/replace in an existing image description",
		},
	),
	Action: func(ctx context.Context, cmd *cli.Command) error {
		_, err := global.GetConfig(cmd)
		if err != nil {
			return fmt.Errorf("failed to get global config: %w", err)
		}

		log.Infof("Creating image description '%v'", cmd.String(nameFlag))

		id, err := buildImageDescription(cmd)
		if err != nil {
			return err
		}

		return create.Output(cmd, id)
	},
}

func buildImageDescription(cmd *cli.Command) (*ar.Metadata, error) {
	m := &ar.Metadata{}

	if cmd.IsSet(inFlag) {
		data, err := os.ReadFile(cmd.String(inFlag))
		if err != nil {
			return nil, fmt.Errorf("failed to read input file: %w", err)
		}
		if err := json.Unmarshal(data, m); err != nil {
			return nil, fmt.Errorf("failed to parse input file: %w", err)
		}
	}

	m.Type = ar.TYPE_IMAGE_DESCRIPTION

	if cmd.IsSet(nameFlag) {
		m.Name = cmd.String(nameFlag)
	}
	if cmd.IsSet(versionFlag) {
		m.Version = cmd.String(versionFlag)
	}
	if cmd.IsSet(descriptionFlag) {
		m.Description = cmd.String(descriptionFlag)
	}
	if cmd.IsSet(notBeforeFlag) || cmd.IsSet(notAfterFlag) {
		if m.Validity == nil {
			m.Validity = &ar.Validity{}
		}
		if cmd.IsSet(notBeforeFlag) {
			m.Validity.NotBefore = cmd.String(notBeforeFlag)
		}
		if cmd.IsSet(notAfterFlag) {
			m.Validity.NotAfter = cmd.String(notAfterFlag)
		}
	}
	if cmd.IsSet(locationFlag) {
		m.Location = cmd.String(locationFlag)
	}

	if cmd.IsSet(descriptionsFlag) {
		descs, err := loadManifestDescriptions(cmd.String(descriptionsFlag))
		if err != nil {
			return nil, err
		}
		m.Descriptions = descs
	}

	if cmd.IsSet(addDescFlag) {
		desc, err := loadManifestDescription(cmd.String(addDescFlag))
		if err != nil {
			return nil, err
		}
		m.Descriptions = addOrReplaceDescription(m.Descriptions, *desc)
	}

	return m, nil
}

func loadManifestDescriptions(paths string) ([]ar.ManifestDescription, error) {
	var descs []ar.ManifestDescription
	for path := range strings.SplitSeq(paths, ",") {
		md, err := loadManifestDescription(path)
		if err != nil {
			return nil, err
		}
		descs = append(descs, *md)
	}
	return descs, nil
}

func loadManifestDescription(path string) (*ar.ManifestDescription, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest description file %v: %w", path, err)
	}
	md := &ar.ManifestDescription{}
	if err := json.Unmarshal(data, md); err != nil {
		return nil, fmt.Errorf("failed to parse manifest description from %v: %w", path, err)
	}
	return md, nil
}

func addOrReplaceDescription(descs []ar.ManifestDescription, newDesc ar.ManifestDescription) []ar.ManifestDescription {
	for i, d := range descs {
		if d.Name == newDesc.Name {
			descs[i] = newDesc
			return descs
		}
	}
	return append(descs, newDesc)
}
