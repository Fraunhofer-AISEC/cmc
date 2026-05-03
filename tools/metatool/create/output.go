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

package create

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/tools/metatool/sign"
)

var log = logrus.WithField("service", "metatool")

const (
	OutFlag    = "out"
	FormatFlag = "format"
	SignFlag   = "sign"
	KeysFlag   = "keys"
	X5csFlag   = "x5cs"
)

var OutputFlags = []cli.Flag{
	&cli.StringFlag{
		Name:  OutFlag,
		Usage: "path to the output file (stdout if omitted)",
	},
	&cli.StringFlag{
		Name:  FormatFlag,
		Usage: "output format: json or cbor (default: json)",
		Value: "json",
	},
	&cli.BoolFlag{
		Name:  SignFlag,
		Usage: "sign the output",
	},
	&cli.StringFlag{
		Name:  KeysFlag,
		Usage: "paths to signing keys in PEM format, comma-separated (required with --sign)",
	},
	&cli.StringFlag{
		Name:  X5csFlag,
		Usage: "paths to PEM encoded x509 certificate chains, colon-separated (required with --sign)",
	},
}

func Marshal(v any, format string) ([]byte, error) {
	if strings.EqualFold(format, "cbor") {
		s, err := ar.NewCborSerializer()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize cbor serializer: %w", err)
		}
		data, err := s.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal cbor: %w", err)
		}
		return data, nil
	}

	data, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal json: %w", err)
	}
	return data, nil
}

func SignOutput(cmd *cli.Command, data []byte) ([]byte, error) {
	if !cmd.IsSet(KeysFlag) {
		return nil, fmt.Errorf("--keys is required when using --sign")
	}
	if !cmd.IsSet(X5csFlag) {
		return nil, fmt.Errorf("--x5cs is required when using --sign")
	}

	keysPem, err := sign.LoadKeys(cmd.String(KeysFlag))
	if err != nil {
		return nil, fmt.Errorf("failed to load keys: %w", err)
	}

	chainsPem, err := sign.LoadCertChains(cmd.String(X5csFlag))
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate chains: %w", err)
	}

	signed, err := sign.Sign(data, keysPem, chainsPem)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signed, nil
}

func WriteOutput(cmd *cli.Command, data []byte) error {
	if cmd.IsSet(OutFlag) {
		outFile := cmd.String(OutFlag)
		log.Infof("Writing %v", outFile)
		if err := os.WriteFile(outFile, data, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		return nil
	}

	fmt.Print(string(data))
	return nil
}

func LoadJSON[T any](path string) (*T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %v: %w", path, err)
	}
	v := new(T)
	if err := json.Unmarshal(data, v); err != nil {
		return nil, fmt.Errorf("failed to parse JSON from %v: %w", path, err)
	}
	return v, nil
}

func Output(cmd *cli.Command, v any) error {
	output, err := Marshal(v, cmd.String(FormatFlag))
	if err != nil {
		return err
	}

	if cmd.Bool(SignFlag) {
		output, err = SignOutput(cmd, output)
		if err != nil {
			return err
		}
	}

	return WriteOutput(cmd, output)
}
