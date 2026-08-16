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

package precomputeswima

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/global"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/precomputetpm"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

var (
	log = logrus.WithField("service", "mrtool")
)

type Config struct {
	ImaPaths          []string
	ImaStrip          string
	ImaPrepend        string
	ImaTemplate       string
	Pcr               int
	BuildrootManifest string
	PackageFileList   string
}

const (
	imaPathFlag           = "ima-path"
	imaStripFlag          = "ima-strip"
	imaPrependFlag        = "ima-prepend"
	imaTemplateFlag       = "ima-template"
	pcrFlag               = "pcr"
	buildrootManifestFlag = "buildroot-manifest"
	packageFileListFlag   = "package-file-list"
)

var flags = []cli.Flag{
	&cli.StringFlag{
		Name:  imaPathFlag,
		Usage: "comma-separated paths or single files (binaries or config files) to create IMA reference values for",
	},
	&cli.StringFlag{
		Name:  imaStripFlag,
		Usage: "Optional ima path prefix which is stripped from the actual path in the output",
	},
	&cli.StringFlag{
		Name:  imaPrependFlag,
		Usage: "Optional ima path segment which is prepended to the actual path in the output",
	},
	&cli.StringFlag{
		Name:  imaTemplateFlag,
		Usage: "IMA template name (ima-ng or ima-sig)",
		Value: "ima-sig",
	},
	&cli.IntFlag{
		Name:  pcrFlag,
		Usage: "PCR index tag emitted on the reference values (default 10 to match the Linux IMA convention)",
		Value: 10,
	},
	&cli.StringFlag{
		Name:  buildrootManifestFlag,
		Usage: "Path to a buildroot manifest CSV file to augment reference values with package URLs and versions",
	},
	&cli.StringFlag{
		Name:  packageFileListFlag,
		Usage: "Path to a buildroot packages-file-list.txt for mapping file names to package names (requires --buildroot-manifest)",
	},
}

var Command = &cli.Command{
	Name:  "swima",
	Usage: "Precompute standalone software-signed IMA reference values (TRUST_ANCHOR_SWIMA)",
	Flags: flags,
	Action: func(ctx context.Context, c *cli.Command) error {
		if err := run(c); err != nil {
			return fmt.Errorf("failed to precompute swima refvals: %w", err)
		}
		return nil
	},
}

func run(cmd *cli.Command) error {

	globConf, err := global.GetConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid global config: %w", err)
	}

	cfg, err := getConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid precompute swima config: %w", err)
	}

	if len(cfg.ImaPaths) == 0 {
		return fmt.Errorf("no --ima-path provided")
	}

	log.Infof("Precomputing SWIMA reference values for %v path(s)...", len(cfg.ImaPaths))

	refvals, err := precomputetpm.PerformImaPrecomputation(
		ar.TRUST_ANCHOR_SWIMA,
		cfg.Pcr,
		nil, // no boot aggregate: standalone SWIMA has no TPM PCR to seed
		cfg.ImaPaths,
		cfg.ImaStrip,
		cfg.ImaPrepend,
		cfg.ImaTemplate,
	)
	if err != nil {
		return fmt.Errorf("failed to precompute IMA refvals: %w", err)
	}

	if cfg.BuildrootManifest != "" {
		manifest, err := precomputetpm.ParseBuildrootManifest(cfg.BuildrootManifest)
		if err != nil {
			return fmt.Errorf("failed to parse buildroot manifest: %w", err)
		}
		var pathToPackage map[string]string
		if cfg.PackageFileList != "" {
			pathToPackage, err = precomputetpm.ParsePackageFileList(cfg.PackageFileList)
			if err != nil {
				return fmt.Errorf("failed to parse package file list: %w", err)
			}
		}
		precomputetpm.AugmentRefvals(refvals, manifest, pathToPackage)
	}

	if globConf.PrintEventLog {
		data, err := json.MarshalIndent(refvals, "", "     ")
		if err != nil {
			return fmt.Errorf("failed to marshal reference values: %w", err)
		}
		os.Stdout.Write(append(data, byte('\n')))
	}

	log.Info("Finished")
	return nil
}

func getConfig(cmd *cli.Command) (*Config, error) {
	c := &Config{
		ImaTemplate: cmd.String(imaTemplateFlag),
		Pcr:         int(cmd.Int(pcrFlag)),
	}
	if cmd.IsSet(imaPathFlag) {
		c.ImaPaths = strings.Split(cmd.String(imaPathFlag), ",")
	}
	if cmd.IsSet(imaStripFlag) {
		c.ImaStrip = cmd.String(imaStripFlag)
	}
	if cmd.IsSet(imaPrependFlag) {
		c.ImaPrepend = cmd.String(imaPrependFlag)
	}
	if cmd.IsSet(buildrootManifestFlag) {
		c.BuildrootManifest = cmd.String(buildrootManifestFlag)
	}
	if cmd.IsSet(packageFileListFlag) {
		c.PackageFileList = cmd.String(packageFileListFlag)
	}
	if c.PackageFileList != "" && c.BuildrootManifest == "" {
		return nil, fmt.Errorf("--package-file-list requires --buildroot-manifest")
	}
	return c, nil
}
