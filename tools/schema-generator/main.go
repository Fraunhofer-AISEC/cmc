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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"golang.org/x/exp/maps"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"

	"github.com/invopop/jsonschema"
)

var (
	packages = map[string][]any{
		"attestationreport": {
			ar.AttestationReport{},
			ar.AttestationResult{},
			ar.Component{},
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

const (
	packageFlag = "package"
	outFlag     = "out"
)

func main() {
	log.SetLevel(log.TraceLevel)

	cmd := &cli.Command{
		Name:  "schema-generator",
		Usage: "Generate JSON Schema definitions for CMC Go packages",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  packageFlag,
				Usage: fmt.Sprintf("Go package to generate JSON Schema definitions for. Possible: %v", maps.Keys(packages)),
			},
			&cli.StringFlag{
				Name:  outFlag,
				Usage: "directory to write schema definitions to",
				Value: "output",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return run(cmd)
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

func run(cmd *cli.Command) error {
	pkg := cmd.String(packageFlag)
	out := cmd.String(outFlag)

	objects, ok := packages[pkg]
	if !ok {
		return fmt.Errorf("target %q not found", pkg)
	}

	dir := filepath.Join(out, pkg)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	r := &jsonschema.Reflector{
		ExpandedStruct:             false,
		Anonymous:                  true,
		DoNotReference:             false,
		AllowAdditionalProperties:  true,
		RequiredFromJSONSchemaTags: true,
	}

	for _, o := range objects {
		schema := r.Reflect(o)
		data, err := json.MarshalIndent(schema, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal: %w", err)
		}

		f := filepath.Join(dir, fmt.Sprintf("%v.json", getName(o)))
		if err := os.WriteFile(f, data, 0644); err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
	}

	return nil
}

func getName(v interface{}) string {
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t.Name()
}
