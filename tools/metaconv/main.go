// Copyright(c) 2021 Fraunhofer AISEC
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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fxamacker/cbor/v2"
	log "github.com/sirupsen/logrus"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

func main() {
	log.SetLevel(log.TraceLevel)

	inputFile := flag.String("in", "", "Path to JSON or CBOR metadata")
	outputFile := flag.String("out", "", "Path to output file for converted metadata")
	outForm := flag.String("outform", "", "Output format (JSON or CBOR)")
	flag.Parse()

	if *inputFile == "" {
		log.Error("input file file not specified")
		flag.Usage()
		return
	}
	if *outputFile == "" {
		log.Error("output file file not specified")
		flag.Usage()
		return
	}
	if *outForm == "" {
		log.Error("output format not specified")
		flag.Usage()
		return
	}

	// Load metadata
	log.Debugf("Reading input file %v", *inputFile)
	data, err := os.ReadFile(*inputFile)
	if err != nil {
		log.Fatalf("Failed to read metadata file %v", *inputFile)
	}

	raw, err := convert(data, *outForm)
	if err != nil {
		log.Fatalf("Failed to convert: %v", err)
	}

	log.Tracef("Writing output file %v", *outputFile)
	err = os.WriteFile(*outputFile, raw, 0644)
	if err != nil {
		log.Fatalf("Failed to write file: %v", err)
	}
}

func convert(input []byte, outform string) ([]byte, error) {
	// Initialize serializers: detect input format
	var si ar.Serializer
	if json.Valid(input) {
		si = ar.JsonSerializer{}
	} else if err := cbor.Valid(input); err == nil {
		si = ar.CborSerializer{}
	} else {
		return nil, errors.New("failed to detect serialization (only JSON and CBOR are supported)")
	}

	// Initialize serializers: use specified output format
	var so ar.Serializer
	if strings.EqualFold(outform, "json") {
		so = ar.JsonSerializer{}
	} else if strings.EqualFold(outform, "cbor") {
		so = ar.CborSerializer{}
	} else {
		return nil, fmt.Errorf("output format %v not supported (only JSON and CBOR are supported)",
			outform)
	}

	// Convert serialized input to go representation
	m := new(ar.Metadata)
	err := si.Unmarshal(input, m)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %v", err)
	}

	// Convert go representation to serialized output
	output, err := so.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal: %v", err)
	}

	return output, nil
}
