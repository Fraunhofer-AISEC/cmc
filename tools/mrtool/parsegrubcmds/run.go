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

package parsegrubcmds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers/tpmdriver"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/parsetpm"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

const (
	eventlogFlag = "eventlog"

	grubPcr = 8
)

// Event data prefixes GRUB prepends to the measured string. The prefix is part of the event
// data but not of the digest
var grubPrefixes = []string{
	"grub_cmd: ",
	"kernel_cmdline: ",
	"module_cmdline: ",
}

var log = logrus.WithField("service", "mrtool")

var Command = &cli.Command{
	Name: "grubcmds",
	Usage: "extracts the strings GRUB measured into PCR8 from the TPM eventlog as JSON list " +
		"to be used with precompute tpm --grubcmds",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  eventlogFlag,
			Usage: "TPM eventlog input file",
			Value: parsetpm.DEFAULT_BINARY_BIOS_MEASUREMENTS,
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		if err := run(cmd); err != nil {
			return fmt.Errorf("failed to parse grub commands: %w", err)
		}
		return nil
	},
}

func run(cmd *cli.Command) error {

	eventlog := cmd.String(eventlogFlag)
	log.Debugf("Parsing GRUB commands from %v", eventlog)

	refvals, err := tpmdriver.GetBiosMeasurements(eventlog, true, false, nil)
	if err != nil {
		return fmt.Errorf("failed to read binary bios measurements: %w", err)
	}

	cmds := make([]string, 0)
	for _, refval := range refvals {
		index, err := refval.GetIndex()
		if err != nil {
			return fmt.Errorf("failed to get index: %w", err)
		}
		if index != grubPcr || refval.Name != "EV_IPL" {
			continue
		}
		cmd, err := grubCmd(&refval)
		if err != nil {
			return err
		}
		cmds = append(cmds, cmd)
	}
	log.Debugf("Extracted %v GRUB commands", len(cmds))

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(cmds)
}

// grubCmd returns the measured string of a GRUB EV_IPL event and verifies it against the
// event digests
func grubCmd(refval *ar.Component) (string, error) {

	if refval.EventData == nil {
		return "", fmt.Errorf("PCR%v EV_IPL event without event data", grubPcr)
	}
	data := bytes.TrimSuffix(refval.EventData.RawData, []byte{0})

	var cmd string
	found := false
	for _, prefix := range grubPrefixes {
		if s, ok := strings.CutPrefix(string(data), prefix); ok {
			cmd = s
			found = true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("PCR%v EV_IPL event %q has no known GRUB prefix", grubPcr,
			refval.Description)
	}

	for _, h := range refval.Hashes {
		alg, err := internal.HashFromString(h.Alg)
		if err != nil {
			return "", fmt.Errorf("failed to convert hash alg: %w", err)
		}
		digest, err := internal.Hash(alg, []byte(cmd))
		if err != nil {
			return "", fmt.Errorf("failed to hash: %w", err)
		}
		if !bytes.Equal(digest, h.Content) {
			return "", fmt.Errorf("%v digest of GRUB command %q does not match event digest",
				h.Alg, cmd)
		}
	}

	return cmd, nil
}
