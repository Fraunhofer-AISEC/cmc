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
	"path/filepath"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/cgo"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/tcg"
)

const (
	EFI_CALLING_EFI_APPLICATION        = "Calling EFI Application from Boot Option"
	EFI_RETURNING_FROM_EFI_APPLICATION = "Returning from EFI Application from Boot Option"
	EFI_EXIT_BOOT_SERVICES_INVOCATION  = "Exit Boot Services Invocation"
	EFI_EXIT_BOOT_SERVICES_FAILED      = "Exit Boot Services Returned with Failure"
	EFI_EXIT_BOOT_SERVICES_SUCCEEDED   = "Exit Boot Services Returned with Success"
)

/**
 * Calculates RTMR0
 *
 * RTMR0 contains the following artifacts:
 * - EFI TD handoff block
 * - EFI Configuration FV
 * - EFI Secure Boot variables
 * - QEMU FW Cfg Files as passed to OVMF
 * - EFI Boot variables
 */
func PrecomputeRtmr0(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	log.Debugf("Precomputing RTMR0...")
	rtmr := make([]byte, sha512.Size384)

	// Measure EFI TD Handoff Block: UEFI Platform Initialization Specification, Vol. 3, Chapter 5 5 HOB Code Definitions
	tbHob, err := CreateTbHob()
	if err != nil {
		return nil, nil, err
	}
	tbHobHash := sha512.Sum384(tbHob)
	rtmr = internal.ExtendSha384(rtmr, tbHobHash[:])

	// Configuration Firmware Volume (CFV)
	if c.Ovmf != "" {
		data, err := os.ReadFile(c.Ovmf)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read file: %w", err)
		}

		cfvHash, err := measureCfv(data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure ovmf: %w", err)
		}

		rtmr = internal.ExtendSha384(rtmr, cfvHash[:])
	}

	// Measure UEFI Secure Boot Variables: SecureBoot, PK, KEK, db, dbx
	rtmr, err = MeasureSecureBootVariables(rtmr, c.SecureBoot, c.Pk, c.Kek, c.Db, c.Dbx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure secure boot variables: %w", err)
	}

	// EV_SEPARATOR
	evSeparator := []byte{0x00, 0x00, 0x00, 0x00}
	evHash := sha512.Sum384(evSeparator)
	rtmr = internal.ExtendSha384(rtmr, evHash[:])

	// EV_PLATFORM_CONFIG_FLAGS: ACPI tables
	rtmr, err = CalculateAcpiTables(rtmr, INDEX_RTMR0, c.AcpiRsdp, c.AcpiTables, c.TableLoader, c.TpmLog)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate acpi tables: %w", err)
	}

	// EV_EFI_VARIABLE_BOOT boot variables
	rtmr, err = CalculateEfiBootVars(rtmr, INDEX_RTMR0, c.BootOrder, c.BootXxxx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate EFI boot variables: %w", err)
	}

	// Terminating EV_SEPARATOR is extended only in edk2-stable202408.01
	if c.OvmfVersion == "edk2-stable202408.01" {
		// EV_SEPARATOR
		rtmr = internal.ExtendSha384(rtmr, evHash[:])
	}

	return nil, nil, nil
}

func PrecomputeRtmr1(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	log.Debugf("Precomputing RTMR1...")

	rtmr := make([]byte, 48)
	refvals := make([]*ar.ReferenceValue, 0)

	// EV_EFI_BOOT_SERVICES_APPLICATION: Measure kernel if present
	if c.Kernel != "" {
		data, err := os.ReadFile(c.Kernel)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read file: %w", err)
		}

		// Manipulate real-mode kernel header with configuration constants set by the
		// bootloader: https://docs.kernel.org/arch/x86/boot.html
		if c.Config != "" {
			hdr, err := tcg.LoadKernelSetupHeader(c.Config)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read file: %w", err)
			}

			err = tcg.PrepareKernel(data, hdr)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to prepare kernel: %w", err)
			}
		}

		hash, err := cgo.MeasurePeImage(cgo.SHA384, data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure PE image: %w", err)
		}

		refvals = append(refvals, &ar.ReferenceValue{
			Type:        "TDX Reference Value",
			SubType:     "EV_EFI_BOOT_SERVICES_APPLICATION",
			Index:       INDEX_RTMR1,
			Sha384:      hash[:],
			Description: fmt.Sprintf("RTMR1: %v", filepath.Base(c.Kernel)),
		})
		rtmr = internal.ExtendSha384(rtmr, hash[:])

		if c.DumpKernel != "" {
			err = os.WriteFile(c.DumpKernel, data, 0644)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to write kernel: %w", err)
			}
		}
	} else {
		log.Warnf("No kernel specified. Omitting kernel")
	}

	// EV_EFI_ACTION
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf 10.4.4
	h1 := sha512.Sum384([]byte(EFI_CALLING_EFI_APPLICATION))
	refvals = append(refvals, &ar.ReferenceValue{
		Type:        "TDX Reference Value",
		SubType:     "EV_EFI_ACTION",
		Index:       INDEX_RTMR1,
		Sha384:      h1[:],
		Description: fmt.Sprintf("RTMR1: %v", EFI_CALLING_EFI_APPLICATION),
	})
	rtmr = internal.ExtendSha384(rtmr, h1[:])

	// EV_SEPARATOR (extended only in some OVMF versions)
	if !strings.EqualFold(c.OvmfVersion, "edk2-stable202408.01") {
		sep := []byte{0x0, 0x0, 0x0, 0x0}
		hashSep := sha512.Sum384(sep)
		refvals = append(refvals, &ar.ReferenceValue{
			Type:        "TPM Reference Value",
			SubType:     "EV_SEPARATOR",
			Index:       INDEX_RTMR1,
			Sha384:      hashSep[:],
			Description: "RTMR1: HASH(0000)",
		})
		rtmr = internal.ExtendSha384(rtmr, hashSep[:])
	}

	// EV_EFI_ACTION
	h2 := sha512.Sum384([]byte(EFI_EXIT_BOOT_SERVICES_INVOCATION))
	refvals = append(refvals, &ar.ReferenceValue{
		Type:        "TDX Reference Value",
		SubType:     "EV_EFI_ACTION",
		Index:       INDEX_RTMR1,
		Sha384:      h2[:],
		Description: fmt.Sprintf("RTMR1: %v", EFI_EXIT_BOOT_SERVICES_INVOCATION),
	})
	rtmr = internal.ExtendSha384(rtmr, h2[:])

	// EV_EFI_ACTION
	h3 := sha512.Sum384([]byte(EFI_EXIT_BOOT_SERVICES_SUCCEEDED))
	refvals = append(refvals, &ar.ReferenceValue{
		Type:        "TDX Reference Value",
		SubType:     "EV_EFI_ACTION",
		Index:       INDEX_RTMR1,
		Sha384:      h3[:],
		Description: fmt.Sprintf("RTMR1: %v", EFI_EXIT_BOOT_SERVICES_SUCCEEDED),
	})
	rtmr = internal.ExtendSha384(rtmr, h3[:])

	// Create RTMR1 final reference value
	rtmrSummary := &ar.ReferenceValue{
		Type:        "TDX Reference Value",
		SubType:     "RTMR Summary",
		Description: "RTMR1",
		Index:       1,
		Sha384:      rtmr,
	}

	return rtmrSummary, refvals, nil

}
