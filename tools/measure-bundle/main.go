// Copyright (c) 2024 Fraunhofer AISEC
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

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	m "github.com/Fraunhofer-AISEC/cmc/measure"
)

var (
	log = logrus.WithField("service", "containerd-shim-linux-cmc")
)

func main() {

	// Parse parameters
	c, err := getConfig()
	if err != nil {
		log.Fatalf("Failed to get config: %v", err)
	}

	logrus.SetLevel(c.logLevel)
	log.Debug("Running measure-bundle")

	// Print
	log.Debugf("Config path: %v", c.config)
	log.Debugf("Rootfs path: %v", c.rootfs)
	log.Debugf("Arguments  : %v", c.args)

	// Record the measurement via the cmcd measure interface
	ctrConfig, err := os.ReadFile(c.config)
	if err != nil {
		log.Fatalf("Failed to read container config: %v", err)
	}

	configHash, _, _, err := m.GetSpecMeasurement("mycontainer", ctrConfig)
	if err != nil {
		log.Fatalf("Failed to measure config: %v", err)
	}

	rootfsHash, err := m.GetRootfsMeasurement(c.rootfs)
	if err != nil {
		log.Fatalf("Failed to measure rootfs: %v", err)
	}
	log.Debug("Generating reference values..")

	// TODO decide on format for reference container reference values (config + rootfs)
	// For now: just the hashes

	// Generate reference value array
	refs := make([]ar.ReferenceValue, 0)

	// Fill reference values
	// TODO make trust anchor and PCR configurable
	pcr := 11
	configRef := ar.ReferenceValue{
		Type:     "TPM Reference Value",
		Name:     "OCI Runtime Config",
		Sha256:   configHash,
		Pcr:      &pcr,
		Optional: true,
	}
	refs = append(refs, configRef)

	rootfsRef := ar.ReferenceValue{
		Type:     "TPM Reference Value",
		Name:     "OCI Runtime Rootfs",
		Sha256:   rootfsHash,
		Pcr:      &pcr,
		Optional: true,
	}
	refs = append(refs, rootfsRef)

	// Marshal reference value array
	refData, err := json.MarshalIndent(refs, "", "    ")
	if err != nil {
		log.Fatalf("Failed to marshal reference values: %v", err)
	}

	fmt.Printf("%v\n", string(refData))

	log.Debugf("Finished measure-bundle")
}
