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

package tcg

import (
	"crypto"
	"fmt"
	"os"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

func CalculateAcpiTables(alg crypto.Hash, digest []byte, refvals []*ar.ReferenceValue, index int, acpiRspd, acpiTables, tableLoader, tpmLog string) ([]byte, []*ar.ReferenceValue, error) {
	// EV_PLATFORM_CONFIG_FLAGS: etc/table-loader
	if tableLoader != "" {
		data, err := os.ReadFile(tableLoader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read table loader file: %w", err)
		}
		if len(data) > 0 {
			hash, err := internal.Hash(alg, data)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to compute table loader hash: %w", err)
			}

			digest, err = internal.Extend(alg, digest, hash[:])
			if err != nil {
				return nil, nil, fmt.Errorf("failed to extend hash: %w", err)
			}

			refvals = append(refvals, &ar.ReferenceValue{
				Type:        "TDX Reference Value",
				SubType:     "EV_PLATFORM_CONFIG_FLAGS",
				Index:       index,
				Sha384:      hash[:],
				Description: fmt.Sprintf("%v: etc/table-loader", IndexToMr(index)),
			})
		}
	}

	// EV_PLATFORM_CONFIG_FLAGS: etc/acpi/rsdp
	if acpiRspd != "" {
		data, err := os.ReadFile(acpiRspd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read ACPI RSPD file: %w", err)
		}
		if len(data) > 0 {
			hash, err := internal.Hash(alg, data)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to compute ACPI RSPD hash: %w", err)
			}

			digest, err = internal.Extend(alg, digest, hash[:])
			if err != nil {
				return nil, nil, fmt.Errorf("failed to extend hash: %w", err)
			}

			refvals = append(refvals, &ar.ReferenceValue{
				Type:        "TDX Reference Value",
				SubType:     "EV_PLATFORM_CONFIG_FLAGS",
				Index:       index,
				Sha384:      hash[:],
				Description: fmt.Sprintf("%v: etc/acpi/rsdp", IndexToMr(index)),
			})
		}
	}

	// EV_PLATFORM_CONFIG_FLAGS: etc/tpm/log
	if tpmLog != "" {
		data, err := os.ReadFile(tpmLog)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read TPM log file: %w", err)
		}
		if len(data) > 0 {
			hash, err := internal.Hash(alg, data)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to compute TPM log hash: %w", err)
			}

			digest, err = internal.Extend(alg, digest, hash[:])
			if err != nil {
				return nil, nil, fmt.Errorf("failed to extend hash: %w", err)
			}

			refvals = append(refvals, &ar.ReferenceValue{
				Type:        "TDX Reference Value",
				SubType:     "EV_PLATFORM_CONFIG_FLAGS",
				Index:       index,
				Sha384:      hash[:],
				Description: fmt.Sprintf("%v: etc/tpm/log", IndexToMr(index)),
			})
		}
	}

	// EV_PLATFORM_CONFIG_FLAGS: etc/acpi/tables
	if acpiTables != "" {
		data, err := os.ReadFile(acpiTables)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read ACPI tables file: %w", err)
		}
		if len(data) > 0 {
			hash, err := internal.Hash(alg, data)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to compute ACPI tables hash: %w", err)
			}

			digest, err = internal.Extend(alg, digest, hash[:])
			if err != nil {
				return nil, nil, fmt.Errorf("failed to extend hash: %w", err)
			}

			refvals = append(refvals, &ar.ReferenceValue{
				Type:        "TDX Reference Value",
				SubType:     "EV_PLATFORM_CONFIG_FLAGS",
				Index:       index,
				Sha384:      hash[:],
				Description: fmt.Sprintf("%v: etc/acpi/tables", IndexToMr(index)),
			})
		}
	}

	return digest, refvals, nil
}
