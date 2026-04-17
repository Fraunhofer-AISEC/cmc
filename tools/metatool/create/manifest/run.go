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

package manifest

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
	inFlag          = "in"
	nameFlag        = "name"
	versionFlag     = "version"
	descriptionFlag = "description"
	notBeforeFlag   = "not-before"
	notAfterFlag    = "not-after"
	devCommonFlag   = "developer-common-name"
	baseLayersFlag  = "base-layers"
	certLevelFlag   = "cert-level"
	caFingerprtFlag = "ca-fingerprints"
	detailsFlag     = "details"
	sbomFlag        = "sbom"
	sbomFormatFlag  = "sbom-format"
	componentsFlag  = "components"
	specVersionFlag = "spec-version"
	sbomVersionFlag = "sbom-version"
	snpPolicyFlag   = "snp-policy"
	tdxPolicyFlag   = "tdx-policy"
	sgxPolicyFlag   = "sgx-policy"
	omspFlag        = "omsp"
)

var Command = &cli.Command{
	Name:  "manifest",
	Usage: "create a manifest metadata object",
	Flags: append(create.OutputFlags,
		&cli.StringFlag{
			Name:  inFlag,
			Usage: "path to an existing manifest JSON/CBOR file to use as base (optional)",
		},
		&cli.StringFlag{
			Name:  nameFlag,
			Usage: "manifest name (e.g. de.test.rtm)",
		},
		&cli.StringFlag{
			Name:  versionFlag,
			Usage: "manifest version (e.g. 2024-01-01T00:00:00Z)",
		},
		&cli.StringFlag{
			Name:  descriptionFlag,
			Usage: "manifest description",
		},
		&cli.StringFlag{
			Name:  notBeforeFlag,
			Usage: "validity not before (e.g. 2024-01-01T00:00:00Z)",
		},
		&cli.StringFlag{
			Name:  notAfterFlag,
			Usage: "validity not after (e.g. 2026-01-01T00:00:00Z)",
		},
		&cli.StringFlag{
			Name:  devCommonFlag,
			Usage: "developer common name",
		},
		&cli.StringFlag{
			Name:  baseLayersFlag,
			Usage: "base layer names, comma-separated",
		},
		&cli.IntFlag{
			Name:  certLevelFlag,
			Usage: "certification level",
		},
		&cli.StringFlag{
			Name:  caFingerprtFlag,
			Usage: "CA fingerprints, comma-separated",
		},
		&cli.StringFlag{
			Name:  detailsFlag,
			Usage: "details as key=value pairs, comma-separated (e.g. kernel=6.1,os=Ubuntu)",
		},
		&cli.StringFlag{
			Name:  sbomFlag,
			Usage: "path to a complete SBOM JSON file",
		},
		&cli.StringFlag{
			Name:  sbomFormatFlag,
			Usage: "SBOM format when using --components (currently: cyclonedx)",
		},
		&cli.StringFlag{
			Name:  componentsFlag,
			Usage: "path to a JSON file containing a component array, or a JSON array string directly",
		},
		&cli.StringFlag{
			Name:  specVersionFlag,
			Usage: "SBOM spec version (default: 1.7, used with --sbom-format)",
			Value: "1.7",
		},
		&cli.IntFlag{
			Name:  sbomVersionFlag,
			Usage: "SBOM version number (default: 1, used with --sbom-format)",
			Value: 1,
		},
		&cli.StringFlag{
			Name:  snpPolicyFlag,
			Usage: "path to a JSON file containing an SNP policy",
		},
		&cli.StringFlag{
			Name:  tdxPolicyFlag,
			Usage: "path to a JSON file containing a TDX policy",
		},
		&cli.StringFlag{
			Name:  sgxPolicyFlag,
			Usage: "path to a JSON file containing an SGX policy",
		},
		&cli.StringFlag{
			Name:  omspFlag,
			Usage: "URL for server endpoint offering manifest revocation information in form of OMSP responses",
		},
	),
	Action: func(ctx context.Context, cmd *cli.Command) error {
		_, err := global.GetConfig(cmd)
		if err != nil {
			return fmt.Errorf("failed to get global config: %w", err)
		}

		log.Infof("Creating manifest '%v'", cmd.String(nameFlag))

		m, err := buildManifest(cmd)
		if err != nil {
			return err
		}

		return create.Output(cmd, m)
	},
}

func buildManifest(cmd *cli.Command) (*ar.Metadata, error) {
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

	m.Type = ar.TYPE_MANIFEST

	if cmd.IsSet(nameFlag) {
		m.Name = cmd.String(nameFlag)
	}
	if cmd.IsSet(versionFlag) {
		m.Version = cmd.String(versionFlag)
	}
	if cmd.IsSet(descriptionFlag) {
		m.Description = cmd.String(descriptionFlag)
	}
	if cmd.IsSet(notBeforeFlag) {
		m.Validity.NotBefore = cmd.String(notBeforeFlag)
	}
	if cmd.IsSet(notAfterFlag) {
		m.Validity.NotAfter = cmd.String(notAfterFlag)
	}
	if cmd.IsSet(devCommonFlag) {
		m.DevCommonName = cmd.String(devCommonFlag)
	}
	if cmd.IsSet(baseLayersFlag) {
		m.BaseLayers = strings.Split(cmd.String(baseLayersFlag), ",")
	}
	if cmd.IsSet(certLevelFlag) {
		m.CertLevel = int(cmd.Int(certLevelFlag))
	}
	if cmd.IsSet(caFingerprtFlag) {
		m.CaFingerprints = strings.Split(cmd.String(caFingerprtFlag), ",")
	}
	if cmd.IsSet(detailsFlag) {
		details := make(map[string]any)
		for kv := range strings.SplitSeq(cmd.String(detailsFlag), ",") {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) == 2 {
				details[parts[0]] = parts[1]
			}
		}
		m.Details = details
	}

	if err := buildSbom(cmd, m); err != nil {
		return nil, err
	}

	if cmd.IsSet(snpPolicyFlag) {
		p, err := create.LoadJSON[ar.SnpPolicy](cmd.String(snpPolicyFlag))
		if err != nil {
			return nil, fmt.Errorf("failed to load SNP policy: %w", err)
		}
		m.SnpPolicy = p
	}
	if cmd.IsSet(tdxPolicyFlag) {
		p, err := create.LoadJSON[ar.TdxPolicy](cmd.String(tdxPolicyFlag))
		if err != nil {
			return nil, fmt.Errorf("failed to load TDX policy: %w", err)
		}
		m.TdxPolicy = p
	}
	if cmd.IsSet(sgxPolicyFlag) {
		p, err := create.LoadJSON[ar.SgxPolicy](cmd.String(sgxPolicyFlag))
		if err != nil {
			return nil, fmt.Errorf("failed to load SGX policy: %w", err)
		}
		m.SgxPolicy = p
	}
	if cmd.IsSet(omspFlag) && cmd.String(omspFlag) != "" {
		m.OmspServer = cmd.String(omspFlag)
	}

	return m, nil
}

func buildSbom(cmd *cli.Command, m *ar.Metadata) error {
	if cmd.IsSet(sbomFlag) {
		data, err := os.ReadFile(cmd.String(sbomFlag))
		if err != nil {
			return fmt.Errorf("failed to read SBOM file: %w", err)
		}
		sbom := &ar.Sbom{}
		if err := json.Unmarshal(data, sbom); err != nil {
			return fmt.Errorf("failed to parse SBOM: %w", err)
		}
		m.Sbom = sbom
		return nil
	}

	if cmd.IsSet(sbomFormatFlag) || cmd.IsSet(componentsFlag) {
		if !cmd.IsSet(componentsFlag) {
			return fmt.Errorf("--components is required when using --sbom-format")
		}

		components, err := loadComponents(cmd.String(componentsFlag))
		if err != nil {
			return fmt.Errorf("failed to load components: %w", err)
		}

		sbomFormat := cmd.String(sbomFormatFlag)
		if sbomFormat == "" {
			sbomFormat = "CycloneDX"
		}

		m.Sbom = &ar.Sbom{
			BomFormat:   sbomFormat,
			SpecVersion: cmd.String(specVersionFlag),
			Version:     int(cmd.Int(sbomVersionFlag)),
			Components:  components,
		}
	}

	return nil
}

func loadComponents(source string) ([]ar.Component, error) {
	var data []byte

	if fileData, err := os.ReadFile(source); err == nil {
		data = fileData
	} else {
		data = []byte(source)
	}

	var components []ar.Component
	if err := json.Unmarshal(data, &components); err != nil {
		return nil, fmt.Errorf("failed to parse components JSON: %w", err)
	}
	return components, nil
}
