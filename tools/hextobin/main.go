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
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"unicode"
)

func main() {
	inputFile := flag.String("in", "", "hex input file")
	outputFile := flag.String("out", "", "binary output file")
	startDelim := flag.String("start", "", "start delimiter")
	endDelim := flag.String("end", "", "end delimiter")
	flag.Parse()

	if *inputFile == "" {
		fmt.Println("Input file not specified")
		return
	}
	if *outputFile == "" {
		fmt.Println("Output file not specified")
		return
	}
	if *startDelim != "" && *endDelim == "" {
		fmt.Println("Start delimiter, bot no end delimiter specified")
		return
	}
	if *startDelim == "" && *endDelim != "" {
		fmt.Println("End delimiter, but no start delimiter specified")
		return
	}

	in, err := os.ReadFile(*inputFile)
	if err != nil {
		fmt.Printf("Failed to read input file %v: %v\n", *inputFile, err)
		return
	}

	hexStr := strings.Map(func(r rune) rune {
		if unicode.IsGraphic(r) {
			return r
		}
		return -1
	}, string(in))

	if *startDelim != "" {

		fmt.Printf("Extracting string between '%v' and '%v'\n", *startDelim, *endDelim)

		hexStr = Split(hexStr, *startDelim, *endDelim)
	}

	bin, err := hex.DecodeString(hexStr)
	if err != nil {
		fmt.Printf("Failed to decode string: %v\n", err)
	}

	err = os.WriteFile(*outputFile, bin, 0644)
	if err != nil {
		fmt.Printf("Failed to write output file %v: %v\n", outputFile, err)
		return
	}
}

func Split(str, before, after string) string {
	a := strings.SplitAfterN(str, before, 2)
	b := strings.SplitAfterN(a[len(a)-1], after, 2)
	if len(b) == 1 {
		return b[0]
	}
	return b[0][0 : len(b[0])-len(after)]
}
