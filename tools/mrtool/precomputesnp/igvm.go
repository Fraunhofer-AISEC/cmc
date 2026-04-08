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

package precomputesnp

import (
	"fmt"
	"os"
)

func performIgvmPrecomputation(config *PrecomputeSnpConf) ([]byte, error) {
	log.Debug("Precomputing SNP measurement registers with IGVM...")

	// read the ovmf data
	igvmData, err := os.ReadFile(config.IgvmFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read ofmv file: %w", err)
	}
	log.Debugf("OVMF data size: %d", len(igvmData))

	// TODO perform computation

	return nil, fmt.Errorf("not implemented yet")
}
