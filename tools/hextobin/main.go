// Copyright(c) 2025 Fraunhofer AISEC
// Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the License); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an AS IS BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"

	"github.com/urfave/cli/v3"
)

const (
	inFlag    = "in"
	outFlag   = "out"
	startFlag = "start"
	endFlag   = "end"
)

func main() {
	cmd := &cli.Command{
		Name:  "hextobin",
		Usage: "Convert a hex-encoded input file to a binary output file",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     inFlag,
				Usage:    "hex input file",
				Required: true,
			},
			&cli.StringFlag{
				Name:     outFlag,
				Usage:    "binary output file",
				Required: true,
			},
			&cli.StringFlag{
				Name:  startFlag,
				Usage: "start delimiter (optional; requires -end when set)",
			},
			&cli.StringFlag{
				Name:  endFlag,
				Usage: "end delimiter (optional; requires -start when set)",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return run(cmd)
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(cmd *cli.Command) error {
	inputFile := cmd.String(inFlag)
	outputFile := cmd.String(outFlag)
	startDelim := cmd.String(startFlag)
	endDelim := cmd.String(endFlag)

	if startDelim != "" && endDelim == "" {
		return fmt.Errorf("start delimiter set but no end delimiter specified")
	}
	if startDelim == "" && endDelim != "" {
		return fmt.Errorf("end delimiter set but no start delimiter specified")
	}

	in, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file %v: %w", inputFile, err)
	}

	hexStr := strings.Map(func(r rune) rune {
		if unicode.IsGraphic(r) {
			return r
		}
		return -1
	}, string(in))

	if startDelim != "" {
		fmt.Printf("Extracting string between '%v' and '%v'\n", startDelim, endDelim)
		hexStr = Split(hexStr, startDelim, endDelim)
	}

	bin, err := decodeHex(hexStr)
	if err != nil {
		return fmt.Errorf("failed to decode string: %w", err)
	}

	if err := os.WriteFile(outputFile, bin, 0644); err != nil {
		return fmt.Errorf("failed to write output file %v: %w", outputFile, err)
	}
	return nil
}

func Split(str, before, after string) string {
	a := strings.SplitAfterN(str, before, 2)
	b := strings.SplitAfterN(a[len(a)-1], after, 2)
	if len(b) == 1 {
		return b[0]
	}
	return b[0][0 : len(b[0])-len(after)]
}

func decodeHex(input string) ([]byte, error) {
	// Remove 0x or 0X prefixes
	re := regexp.MustCompile(`(?i)0x`)
	clean := re.ReplaceAllString(input, "")

	// Remove anything that's not a hex digit
	re = regexp.MustCompile(`[^0-9a-fA-F]`)
	clean = re.ReplaceAllString(clean, "")

	return hex.DecodeString(clean)
}
