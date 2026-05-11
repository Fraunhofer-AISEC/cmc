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

package measure

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/opencontainers/runtime-spec/specs-go"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	m "github.com/Fraunhofer-AISEC/cmc/measure"
)

// MeasureBundle computes reference values from an OCI runtime bundle
// (rootfs/ + config.json) and prints the resulting ar.Component as JSON.
func MeasureBundle(bundleDir, name string) error {
	configPath := filepath.Join(bundleDir, "config.json")
	rootfsDir := filepath.Join(bundleDir, "rootfs")

	configRaw, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config.json: %w", err)
	}

	// config.json is already normalized by the convert command — hash directly.
	hasher := sha256.New()
	hasher.Write(configRaw)
	configHash := hasher.Sum(nil)

	rootfsHash, err := m.GetRootfsMeasurement(rootfsDir)
	if err != nil {
		return fmt.Errorf("measure rootfs: %w", err)
	}

	var spec specs.Spec
	if err := json.Unmarshal(configRaw, &spec); err != nil {
		return fmt.Errorf("unmarshal config.json: %w", err)
	}

	component := ar.Component{
		Type: ar.TYPE_APP,
		Name: name,
		Hashes: []ar.ReferenceHash{
			{
				Alg:     "SHA-256",
				Content: rootfsHash,
			},
		},
		CtrData: &ar.CtrData{
			ConfigSha256: configHash,
			RootfsSha256: rootfsHash,
			OciSpec:      &spec,
		},
		Optional: true,
		Properties: []ar.Property{
			{Name: ar.PROPERTY_TRUST_ANCHOR, Value: ar.TRUST_ANCHOR_SW},
		},
	}

	out, err := json.MarshalIndent(component, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal component: %w", err)
	}

	fmt.Println(string(out))

	log.Debugf("SHA-256 config.json: %x", configHash)
	log.Debugf("SHA-256 rootfs     : %x", rootfsHash)

	return nil
}
