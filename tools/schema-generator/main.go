// Copyright(c) 2024 Fraunhofer AISEC
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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"golang.org/x/exp/maps"

	log "github.com/sirupsen/logrus"

	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"

	"github.com/invopop/jsonschema"
)

var (
	packages = map[string][]any{
		"attestationreport": {
			ar.AttestationReport{},
			ar.VerificationResult{},
			ar.MeasureEvent{},
		},
		"api": {
			api.AttestationRequest{},
			api.AttestationResponse{},
			api.VerificationRequest{},
			api.VerificationResponse{},
			api.TLSSignRequest{},
			api.TLSSignResponse{},
			api.TLSCertRequest{},
			api.TLSCertResponse{},
			api.PeerCacheRequest{},
			api.PeerCacheResponse{},
			api.MeasureRequest{},
			api.MeasureResponse{},
			api.SocketError{},
			api.PSSOptions{},
		},
		"attestedtls": {
			atls.AtlsHandshakeRequest{},
			atls.AtlsHandshakeResponse{},
			atls.AtlsHandshakeComplete{},
		},
	}
)

func main() {
	log.SetLevel(log.TraceLevel)

	pkg := flag.String("package", "",
		fmt.Sprintf("The golang package to generate JSON Schema definitions for. Possible: %v", maps.Keys(packages)))

	out := flag.String("out", "output", "The directory the schema definitions shall be written to")

	flag.Parse()

	// Create sub-directory for the package
	dir := filepath.Join(*out, *pkg)

	objects, ok := packages[*pkg]
	if !ok {
		log.Fatalf("Target '%v' not found", *pkg)
	}

	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		log.Fatalf("Error creating directory: %v\n", err)
	}

	r := &jsonschema.Reflector{
		ExpandedStruct:            false,
		Anonymous:                 true,
		DoNotReference:            false,
		AllowAdditionalProperties: true,
	}

	for _, o := range objects {
		schema := r.Reflect(o)
		data, err := json.MarshalIndent(schema, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal: %v", err)
		}

		f := filepath.Join(dir, fmt.Sprintf("%v.json", getName(o)))

		err = os.WriteFile(f, data, 0644)
		if err != nil {
			log.Fatalf("Failed to write file: %v", err)
		}
	}

}

func getName(v interface{}) string {
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t.Name()
}
