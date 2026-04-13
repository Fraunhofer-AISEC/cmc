// Copyright (c) 2021 Fraunhofer AISEC
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

package cmc

import (
	"fmt"
)

func UpdateCerts(cmc *Cmc) error {

	if cmc == nil {
		return fmt.Errorf("internal error: cmc is nil")
	}

	for _, driver := range cmc.Drivers {
		err := driver.UpdateCerts()
		if err != nil {
			return fmt.Errorf("failed to update %v driver certificates: %w", driver.Name(), err)
		}
	}

	return nil
}

func UpdateMetadata(cmc *Cmc) error {

	if cmc == nil {
		return fmt.Errorf("internal error: cmc is nil")
	}

	// Read metadata from the file system
	metadata, err := GetMetadata(cmc.MetadataLocation, cmc.Cache, cmc.EstTlsCas, cmc.EstTlsSysRoots,
		cmc.HashAlg)
	if err != nil {
		return fmt.Errorf("failed to get metadata: %v", err)
	}

	cmc.UpdateMetadata(metadata)

	log.Debugf("Updated metadata. New number of metadata items: %v", len(metadata))

	return nil
}
