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
	"flag"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

func convert(data []byte, v any, si ar.Serializer, so ar.Serializer) ([]byte, error) {
	err := si.Unmarshal(data, v)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %v", err)
	}
	raw, err := so.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal: %v", err)
	}
	return raw, nil
}

func main() {
	log.SetLevel(log.TraceLevel)

	inputFile := flag.String("in", "", "Path to metadata as JSON or CBOR to be signed")
	outputFile := flag.String("out", "", "Path to the output file to save signed metadata")
	inFormat := flag.String("format", "", "Input format (JSON or CBOR)")
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
	if *inFormat == "" {
		log.Error("input format not specified")
		flag.Usage()
		return
	}

	// Load metadata
	log.Debugf("Reading input file %v", *inputFile)
	data, err := os.ReadFile(*inputFile)
	if err != nil {
		log.Fatalf("failed to read metadata file %v", *inputFile)
	}

	// Initialize serializers
	var si ar.Serializer
	var so ar.Serializer
	if strings.EqualFold(*inFormat, "json") {
		si = ar.JsonSerializer{}
		so = ar.CborSerializer{}
	} else if strings.EqualFold(*inFormat, "cbor") {
		si = ar.CborSerializer{}
		so = ar.JsonSerializer{}
	} else {
		log.Fatalf("Serializer %v not supported (only JSON and CBOR are supported)", *inFormat)
	}

	t := new(ar.Type)
	err = si.Unmarshal(data, t)
	if err != nil {
		log.Fatalf("failed to unmarshal: %v", err)
	}

	var raw []byte
	switch t.Type {
	case "App Manifest":
		log.Debug("Found App Manifest")
		var m ar.AppManifest
		raw, err = convert(data, &m, si, so)
		if err != nil {
			log.Fatalf("Failed to convert: %v", err)
		}
	case "OS Manifest":
		log.Debug("Found OS Manifest")
		var m ar.OsManifest
		raw, err = convert(data, &m, si, so)
		if err != nil {
			log.Fatalf("Failed to convert: %v", err)
		}

	case "RTM Manifest":
		log.Debug("Found RTM Manifest")
		var m ar.RtmManifest
		raw, err = convert(data, &m, si, so)
		if err != nil {
			log.Fatalf("Failed to convert: %v", err)
		}

	case "Device Description":
		log.Debug("Found Device Description")
		var d ar.DeviceDescription
		raw, err = convert(data, &d, si, so)
		if err != nil {
			log.Fatalf("Failed to convert: %v", err)
		}

	case "Company Description":
		log.Debug("Found Company Description")
		var d ar.CompanyDescription
		raw, err = convert(data, &d, si, so)
		if err != nil {
			log.Fatalf("Failed to convert: %v", err)
		}

	case "Device Config":
		log.Debug("Found Device Config")
		var d ar.DeviceConfig
		raw, err = convert(data, &d, si, so)
		if err != nil {
			log.Fatalf("Failed to convert: %v", err)
		}

	default:
		log.Fatalf("Type %v not supported", t.Type)

	}

	log.Tracef("Writing output file %v", *outputFile)
	err = os.WriteFile(*outputFile, raw, 0644)
	if err != nil {
		log.Fatalf("Failed to write file: %v", err)
	}
}
