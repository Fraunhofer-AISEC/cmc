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
	"crypto"
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
	refvals := make([]*ar.ReferenceValue, 0)

	// Measure EFI TD Handoff Block: UEFI Platform Initialization Specification, Vol. 3, Chapter 5 5 HOB Code Definitions
	tbHob, err := CreateTbHob()
	if err != nil {
		return nil, nil, err
	}
	tbHobHash := sha512.Sum384(tbHob)

	rtmr = internal.ExtendSha384(rtmr, tbHobHash[:])
	refvals = append(refvals, &ar.ReferenceValue{
		Type:        "TDX Reference Value",
		SubType:     "EV_EFI_HANDOFF_TABLES",
		Index:       tcg.INDEX_RTMR0,
		Sha384:      tbHobHash[:],
		Description: "RTMR0: TD Hob passed from host VMM to guest firmware",
	})

	// Configuration Firmware Volume (CFV)
	if c.Ovmf != "" {
		data, err := os.ReadFile(c.Ovmf)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read file: %w", err)
		}

		cfvHash, err := MeasureCfv(data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure ovmf: %w", err)
		}

		rtmr = internal.ExtendSha384(rtmr, cfvHash[:])
		refvals = append(refvals, &ar.ReferenceValue{
			Type:        "TDX Reference Value",
			SubType:     "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
			Index:       tcg.INDEX_RTMR0,
			Sha384:      cfvHash[:],
			Description: "RTMR0: Configuration Firmware Volume",
		})
	}

	// Measure UEFI Secure Boot Variables: SecureBoot, PK, KEK, db, dbx
	rtmr, refvals, err = tcg.MeasureSecureBootVariables(crypto.SHA384, tcg.TDX, rtmr, refvals,
		tcg.INDEX_RTMR0, c.SecureBoot, c.Pk, c.Kek, c.Db, c.Dbx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure secure boot variables: %w", err)
	}

	// EV_SEPARATOR
	evSeparator := []byte{0x00, 0x00, 0x00, 0x00}
	evHash := sha512.Sum384(evSeparator)

	rtmr = internal.ExtendSha384(rtmr, evHash[:])
	refvals = append(refvals, &ar.ReferenceValue{
		Type:        "TDX Reference Value",
		SubType:     "EV_SEPARATOR",
		Index:       tcg.INDEX_RTMR0,
		Sha384:      evHash[:],
		Description: "RTMR0: HASH(00000000)",
	})

	// EV_PLATFORM_CONFIG_FLAGS: ACPI tables
	rtmr, refvals, err = tcg.CalculateAcpiTables(crypto.SHA384, tcg.TDX, rtmr, refvals,
		tcg.INDEX_RTMR0, c.AcpiRsdp, c.AcpiTables, c.TableLoader, c.TpmLog)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate acpi tables: %w", err)
	}

	// EV_EFI_VARIABLE_BOOT boot variables
	rtmr, refvals, err = tcg.MeasureEfiBootVars(crypto.SHA384, tcg.TDX, rtmr, refvals,
		tcg.INDEX_RTMR0, c.BootOrder, c.BootXxxx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate EFI boot variables: %w", err)
	}

	// EV_EFI_VARIABLE_AUTHORITY: SbatLevel
	if c.SbatLevel != "" {
		rtmr, refvals, err = tcg.MeasureSbatLevel(crypto.SHA384, tcg.TDX, rtmr, refvals,
			tcg.INDEX_RTMR0, c.SbatLevel)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure SbatLevel: %w", err)
		}
	}

	// Terminating EV_SEPARATOR is extended only in edk2-stable202408.01
	if c.OvmfVersion == "edk2-stable202408.01" {
		// EV_SEPARATOR
		rtmr = internal.ExtendSha384(rtmr, evHash[:])
		refvals = append(refvals, &ar.ReferenceValue{
			Type:        "TDX Reference Value",
			SubType:     "EV_SEPARATOR",
			Index:       tcg.INDEX_RTMR0,
			Sha384:      evHash[:],
			Description: "RTMR0: HASH(00000000)",
		})
	}

	// Create RTMR0 final reference value
	rtmrSummary := &ar.ReferenceValue{
		Type:        "TDX Reference Value",
		SubType:     "RTMR Summary",
		Description: "RTMR0",
		Index:       tcg.INDEX_RTMR0,
		Sha384:      rtmr,
	}

	return rtmrSummary, refvals, nil
}

/**
 * Calculates RTMR1
 *
 * RTMR1 contains the Linux kernel PE/COFF image measurement as well as some boot strings.
 */
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
			Index:       tcg.INDEX_RTMR1,
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
		return nil, nil, fmt.Errorf("kernel must be specified for RTMR1")
	}

	// EV_EFI_ACTION
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf 10.4.4
	h1 := sha512.Sum384([]byte(EFI_CALLING_EFI_APPLICATION))
	refvals = append(refvals, &ar.ReferenceValue{
		Type:        "TDX Reference Value",
		SubType:     "EV_EFI_ACTION",
		Index:       tcg.INDEX_RTMR1,
		Sha384:      h1[:],
		Description: fmt.Sprintf("RTMR1: %v", EFI_CALLING_EFI_APPLICATION),
	})
	rtmr = internal.ExtendSha384(rtmr, h1[:])

	// EV_SEPARATOR (extended only in some OVMF versions)
	if !strings.EqualFold(c.OvmfVersion, "edk2-stable202408.01") {
		sep := []byte{0x0, 0x0, 0x0, 0x0}
		hashSep := sha512.Sum384(sep)
		refvals = append(refvals, &ar.ReferenceValue{
			Type:        "TDX Reference Value",
			SubType:     "EV_SEPARATOR",
			Index:       tcg.INDEX_RTMR1,
			Sha384:      hashSep[:],
			Description: "RTMR1: HASH(00000000)",
		})
		rtmr = internal.ExtendSha384(rtmr, hashSep[:])
	}

	// EV_EFI_GPT_EVENT
	// Calculate UEFI GPT partition table if provided. The raw disk data can be
	// provided, the function will find the GPT partition table if present
	if c.Gpt != "" {
		hash, description, err := tcg.MeasureGptFromFile(sha512.New384(), c.Gpt, c.DumpGpt)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure GPT: %w", err)
		}

		refvals = append(refvals, &ar.ReferenceValue{
			Type:        "TDX Reference Value",
			SubType:     "EV_EFI_GPT_EVENT",
			Index:       tcg.INDEX_RTMR1,
			Sha384:      hash[:],
			Description: description,
		})
		rtmr = internal.ExtendSha384(rtmr, hash[:])
	}

	// EV_EFI_BOOT_SERVICES_APPLICATION: Measure bootloaders if present
	for _, f := range c.Bootloaders {

		data, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read file: %w", err)
		}

		hash, err := cgo.MeasurePeImage(cgo.SHA384, data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure PE image: %w", err)
		}

		refvals = append(refvals, &ar.ReferenceValue{
			Type:        "TDX Reference Value",
			SubType:     "EV_EFI_BOOT_SERVICES_APPLICATION",
			Index:       tcg.INDEX_RTMR1,
			Sha384:      hash[:],
			Description: filepath.Base(f),
		})
		rtmr = internal.ExtendSha384(rtmr, hash[:])
	}

	// EV_EFI_ACTION
	h2 := sha512.Sum384([]byte(EFI_EXIT_BOOT_SERVICES_INVOCATION))
	refvals = append(refvals, &ar.ReferenceValue{
		Type:        "TDX Reference Value",
		SubType:     "EV_EFI_ACTION",
		Index:       tcg.INDEX_RTMR1,
		Sha384:      h2[:],
		Description: fmt.Sprintf("RTMR1: %v", EFI_EXIT_BOOT_SERVICES_INVOCATION),
	})
	rtmr = internal.ExtendSha384(rtmr, h2[:])

	// EV_EFI_ACTION
	h3 := sha512.Sum384([]byte(EFI_EXIT_BOOT_SERVICES_SUCCEEDED))
	refvals = append(refvals, &ar.ReferenceValue{
		Type:        "TDX Reference Value",
		SubType:     "EV_EFI_ACTION",
		Index:       tcg.INDEX_RTMR1,
		Sha384:      h3[:],
		Description: fmt.Sprintf("RTMR1: %v", EFI_EXIT_BOOT_SERVICES_SUCCEEDED),
	})
	rtmr = internal.ExtendSha384(rtmr, h3[:])

	// Create RTMR1 final reference value
	rtmrSummary := &ar.ReferenceValue{
		Type:        "TDX Reference Value",
		SubType:     "RTMR Summary",
		Description: "RTMR1",
		Index:       tcg.INDEX_RTMR1,
		Sha384:      rtmr,
	}

	return rtmrSummary, refvals, nil
}

/**
 * Calculates RTMR2
 *
 * RTMR2 contains the Linux kernel command line.
 */
func PrecomputeRtmr2(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {
	log.Debugf("Precomputing RTMR2...")

	rtmr := make([]byte, sha512.Size384)
	refvals := make([]*ar.ReferenceValue, 0)

	rtmr, refvals, err := tcg.MeasureCmdline(crypto.SHA384, tcg.TDX, rtmr, refvals, tcg.INDEX_RTMR2,
		c.Cmdline, "EV_EVENT_TAG", c.AddZeros, c.StripNewline, false)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure cmdline: %w", err)
	}

	// Create RTMR2 final reference value
	rtmrSummary := &ar.ReferenceValue{
		Type:        "TDX Reference Value",
		SubType:     "RTMR Summary",
		Description: "RTMR2",
		Index:       tcg.INDEX_RTMR2,
		Sha384:      rtmr,
	}

	return rtmrSummary, refvals, nil
}

/**
 * Calculates RTMR3
 *
 * RTMR3 is currently empty.
 */
func PrecomputeRtmr3(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {
	log.Debugf("Precomputing RTMR3...")

	rtmr := make([]byte, sha512.Size384)
	refvals := make([]*ar.ReferenceValue, 0)

	// Create RTMR3 final reference value
	rtmrSummary := &ar.ReferenceValue{
		Type:        "TDX Reference Value",
		SubType:     "RTMR Summary",
		Description: "RTMR3",
		Index:       tcg.INDEX_RTMR3,
		Sha384:      rtmr,
	}

	return rtmrSummary, refvals, nil
}
