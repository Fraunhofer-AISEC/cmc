// Copyright (c) 2025 Fraunhofer AISEC
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

package precomputetdx

import (
	"crypto/sha512"
	"fmt"
	"os"

	"github.com/Fraunhofer-AISEC/cmc/internal"
)

func CalculateAcpiTables(digest []byte, index int, acpiRspd, acpiTables, tableLoader, tpmLog string) ([]byte, error) {
	// EV_PLATFORM_CONFIG_FLAGS: etc/table-loader
	if tableLoader != "" {
		data, err := os.ReadFile(tableLoader)
		if err != nil {
			return nil, fmt.Errorf("Failed to read table loader file: %w", err)
		}
		if len(data) > 0 {
			hash := sha512.Sum384(data)
			digest = internal.ExtendSha384(digest, hash[:])
		}
	}

	// EV_PLATFORM_CONFIG_FLAGS: etc/acpi/rsdp
	if acpiRspd != "" {
		data, err := os.ReadFile(acpiRspd)
		if err != nil {
			return nil, fmt.Errorf("Failed to read ACPI RSPD file: %w", err)
		}
		if len(data) > 0 {
			hash := sha512.Sum384(data)
			digest = internal.ExtendSha384(digest, hash[:])
		}
	}

	// EV_PLATFORM_CONFIG_FLAGS: etc/tpm/log
	if tpmLog != "" {
		data, err := os.ReadFile(tpmLog)
		if err != nil {
			return nil, fmt.Errorf("Failed to read TPM log file: %w", err)
		}
		if len(data) > 0 {
			hash := sha512.Sum384(data)
			digest = internal.ExtendSha384(digest, hash[:])
		}
	}

	// EV_PLATFORM_CONFIG_FLAGS: etc/acpi/tables
	if acpiTables != "" {
		data, err := os.ReadFile(acpiTables)
		if err != nil {
			return nil, fmt.Errorf("Failed to read ACPI tables file: %w", err)
		}
		if len(data) > 0 {
			hash := sha512.Sum384(data)
			digest = internal.ExtendSha384(digest, hash[:])
		}
	}

	return digest, nil
}
