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

	inputFile := flag.String("in", "", "Path to metadata as JSON or CBOR to be signed")
	outputFile := flag.String("out", "", "Path to the output file to save signed metadata")
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

func convert(data []byte, outform string) ([]byte, error) {
	// Initialize serializers: detect input format
	var si ar.Serializer
	if json.Valid(data) {
		si = ar.JsonSerializer{}
	} else if err := cbor.Valid(data); err == nil {
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

	info := new(ar.BasicInfo)
	err := si.Unmarshal(data, info)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}

	var raw []byte
	switch info.Type {
	case "App Manifest":
		log.Debug("Found App Manifest")
		var m ar.AppManifest
		raw, err = convertInternal(data, &m, si, so)
		if err != nil {
			return nil, fmt.Errorf("failed to convert: %w", err)
		}
	case "OS Manifest":
		log.Debug("Found OS Manifest")
		var m ar.OsManifest
		raw, err = convertInternal(data, &m, si, so)
		if err != nil {
			return nil, fmt.Errorf("failed to convert: %w", err)
		}

	case "RTM Manifest":
		log.Debug("Found RTM Manifest")
		var m ar.RtmManifest
		raw, err = convertInternal(data, &m, si, so)
		if err != nil {
			return nil, fmt.Errorf("failed to convert: %w", err)
		}

	case "Device Description":
		log.Debug("Found Device Description")
		var d ar.DeviceDescription
		raw, err = convertInternal(data, &d, si, so)
		if err != nil {
			return nil, fmt.Errorf("failed to convert: %w", err)
		}

	case "Company Description":
		log.Debug("Found Company Description")
		var d ar.CompanyDescription
		raw, err = convertInternal(data, &d, si, so)
		if err != nil {
			return nil, fmt.Errorf("failed to convert: %w", err)
		}

	case "Device Config":
		log.Debug("Found Device Config")
		var d ar.DeviceConfig
		raw, err = convertInternal(data, &d, si, so)
		if err != nil {
			return nil, fmt.Errorf("failed to convert: %w", err)
		}

	default:
		return nil, fmt.Errorf("type %v not supported", info.Type)
	}

	return raw, nil
}

func convertInternal(data []byte, v any, si ar.Serializer, so ar.Serializer) ([]byte, error) {
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
