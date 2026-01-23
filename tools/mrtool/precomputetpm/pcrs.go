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

package precomputetpm

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/cgo"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/tcg"
)

type DriverFileType int

const (
	Unknown DriverFileType = iota
	PECOFF
	OptionROM
)

func PrecomputePcr0(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	var err error
	pcr := make([]byte, 32)
	refvals := make([]*ar.ReferenceValue, 0)

	// EV_S_CRTM_VERSION
	// For VMs, this is usually { 0x0, 0x0 }
	var rv *ar.ReferenceValue
	rv, pcr, err = tcg.CreateExtendRefval(crypto.SHA256, tcg.TPM, 0, pcr, []byte{0x0, 0x0},
		"EV_S_CRTM_VERSION", "CRTM Version String")
	if err != nil {
		return nil, nil, fmt.Errorf("faied to measure CRTM version: %w", err)
	}
	refvals = append(refvals, rv)

	// EV_EFI_PLATFORM_FIRMWARE_BLOB
	pcr, refvals, err = tcg.MeasureOvmf(crypto.SHA256, tcg.TPM, pcr, refvals, 0, c.Ovmf)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure OVMF: %w", err)
	}

	// EV_SEPARATOR
	sep := []byte{0x0, 0x0, 0x0, 0x0}
	hashSep := sha256.Sum256(sep)
	refvals = append(refvals, &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "EV_SEPARATOR",
		Index:       0,
		Sha256:      hashSep[:],
		Description: "HASH(0000)",
	})
	pcr = internal.ExtendSha256(pcr, hashSep[:])

	// Create final reference value
	pcrSummary := &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "PCR Summary",
		Description: "PCR0",
		Index:       0,
		Sha256:      pcr,
	}

	return pcrSummary, refvals, nil
}

func PrecomputePcr1(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	var err error
	pcr := make([]byte, 32)
	refvals := make([]*ar.ReferenceValue, 0)

	// EV_PLATFORM_CONFIG_FLAGS: ACPI tables
	pcr, refvals, err = tcg.CalculateAcpiTables(crypto.SHA256, tcg.TPM, pcr, refvals,
		1, c.AcpiRsdp, c.AcpiTables, c.TableLoader, c.TpmLog)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate acpi tables: %w", err)
	}

	// EV_EFI_HANDOFF_TABLES
	if c.EfiHob != "" {
		pcr, refvals, err = tcg.MeasureFile(crypto.SHA256, tcg.TPM, "EV_EFI_HANDOFF_TABLES", pcr, refvals, 1, c.EfiHob)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure EFI HOB file: %w", err)
		}

	}

	// EV_EFI_VARIABLE_BOOT: boot variables
	pcr, refvals, err = tcg.MeasureEfiBootVars(crypto.SHA256, tcg.TPM, pcr, refvals,
		1, c.BootOrder, c.BootXxxx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate EFI boot variables: %w", err)
	}

	// EV_SEPARATOR
	sep := []byte{0x0, 0x0, 0x0, 0x0}
	hashSep := sha256.Sum256(sep)
	refvals = append(refvals, &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "EV_SEPARATOR",
		Index:       1,
		Sha256:      hashSep[:],
		Description: "HASH(0000)",
	})
	pcr = internal.ExtendSha256(pcr, hashSep[:])

	// Create final reference value
	pcrSummary := &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "PCR Summary",
		Description: "PCR1",
		Index:       1,
		Sha256:      pcr,
	}

	return pcrSummary, refvals, nil
}

func PrecomputePcr2(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	pcr := make([]byte, 32)
	refvals := make([]*ar.ReferenceValue, 0)

	// EV_EFI_BOOT_SERVICES_DRIVER
	for _, f := range c.Drivers {

		log.Tracef("Precomputing driver %q", f)

		t, err := detectDriverFileType(f)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to detect driver file type: %w", err)
		}

		var data []byte
		if t == OptionROM {
			data, err = ExtractPeImage(f)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to extract PE image from option ROM file: %w", err)
			}
		} else {
			data, err = os.ReadFile(f)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read file: %w", err)
			}
		}

		hash, err := cgo.MeasurePeImage(cgo.SHA256, data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure PE image: %w", err)
		}

		refvals = append(refvals, &ar.ReferenceValue{
			Type:        "TPM Reference Value",
			SubType:     "EV_EFI_BOOT_SERVICES_DRIVER",
			Index:       2,
			Sha256:      hash[:],
			Description: filepath.Base(f),
		})
		pcr = internal.ExtendSha256(pcr, hash[:])
	}

	// EV_SEPARATOR
	sep := []byte{0x0, 0x0, 0x0, 0x0}
	hashSep := sha256.Sum256(sep)
	refvals = append(refvals, &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "EV_SEPARATOR",
		Index:       2,
		Sha256:      hashSep[:],
		Description: "HASH(0000)",
	})
	pcr = internal.ExtendSha256(pcr, hashSep[:])

	// Create final reference value
	pcrSummary := &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "PCR Summary",
		Description: "PCR2",
		Index:       2,
		Sha256:      pcr,
	}

	return pcrSummary, refvals, nil
}

func PrecomputePcr3(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	pcr := make([]byte, 32)
	refvals := make([]*ar.ReferenceValue, 0)

	// EV_SEPARATOR
	sep := []byte{0x0, 0x0, 0x0, 0x0}
	hashSep := sha256.Sum256(sep)
	refvals = append(refvals, &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "EV_SEPARATOR",
		Index:       3,
		Sha256:      hashSep[:],
		Description: "HASH(0000)",
	})
	pcr = internal.ExtendSha256(pcr, hashSep[:])

	// Create final reference value
	pcrSummary := &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "PCR Summary",
		Description: "PCR2",
		Index:       3,
		Sha256:      pcr,
	}

	return pcrSummary, refvals, nil
}

func PrecomputePcr4(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	pcr := make([]byte, 32)
	refvals := make([]*ar.ReferenceValue, 0)

	// EV_EFI_BOOT_SERVICES_APPLICATION: Measure bootloaders if present
	for _, f := range c.Bootloaders {

		data, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read file: %w", err)
		}

		hash, err := cgo.MeasurePeImage(cgo.SHA256, data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure PE image: %w", err)
		}

		refvals = append(refvals, &ar.ReferenceValue{
			Type:        "TPM Reference Value",
			SubType:     "EV_EFI_BOOT_SERVICES_APPLICATION",
			Index:       4,
			Sha256:      hash[:],
			Description: filepath.Base(f),
		})
		pcr = internal.ExtendSha256(pcr, hash[:])
	}

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

		hash, err := cgo.MeasurePeImage(cgo.SHA256, data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure PE image: %w", err)
		}

		refvals = append(refvals, &ar.ReferenceValue{
			Type:        "TPM Reference Value",
			SubType:     "EV_EFI_BOOT_SERVICES_APPLICATION",
			Index:       4,
			Sha256:      hash[:],
			Description: filepath.Base(c.Kernel),
		})
		pcr = internal.ExtendSha256(pcr, hash[:])

		if c.DumpKernel != "" {
			err = os.WriteFile(c.DumpKernel, data, 0644)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to write kernel: %w", err)
			}
		}
	}

	// EV_EFI_ACTION: "Calling EFI Application from Boot Option"
	// TCG PCClient Firmware Spec: https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf 10.4.4
	actionData := []byte("Calling EFI Application from Boot Option")
	actionHash := sha256.Sum256(actionData)
	refvals = append(refvals, &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "EV_EFI_ACTION",
		Index:       4,
		Sha256:      actionHash[:],
		Description: "Calling EFI Application from Boot Option",
	})
	pcr = internal.ExtendSha256(pcr, actionHash[:])

	// EV_SEPARATOR
	sep := []byte{0x0, 0x0, 0x0, 0x0}
	hashSep := sha256.Sum256(sep)
	refvals = append(refvals, &ar.ReferenceValue{
		Type:    "TPM Reference Value",
		SubType: "EV_SEPARATOR",
		Index:   4,
		Sha256:  hashSep[:],
	})
	pcr = internal.ExtendSha256(pcr, hashSep[:])

	// Create final reference value
	pcrSummary := &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "PCR Summary",
		Description: "PCR4",
		Index:       4,
		Sha256:      pcr,
	}

	return pcrSummary, refvals, nil
}

func PrecomputePcr5(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	pcr := make([]byte, 32)
	refvals := make([]*ar.ReferenceValue, 0)

	// EV_SEPARATOR
	sep := []byte{0x0, 0x0, 0x0, 0x0}
	hashSep := sha256.Sum256(sep)
	refvals = append(refvals, &ar.ReferenceValue{
		Type:    "TPM Reference Value",
		SubType: "EV_SEPARATOR",
		Index:   5,
		Sha256:  hashSep[:],
	})
	pcr = internal.ExtendSha256(pcr, hashSep[:])

	// EV_EFI_GPT
	// Calculate UEFI GPT partition table if provided. The raw disk data can be
	// provided, the function will find the GPT partition table if present
	if c.Gpt != "" {
		hash, description, err := tcg.MeasureGptFromFile(sha256.New(), c.Gpt, c.DumpGpt)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure GPT: %w", err)
		}

		refvals = append(refvals, &ar.ReferenceValue{
			Type:        "TPM Reference Value",
			SubType:     "EV_EFI_GPT_EVENT",
			Index:       5,
			Sha256:      hash[:],
			Description: description,
		})
		pcr = internal.ExtendSha256(pcr, hash[:])
	}

	// EV_EVENT_TAG
	// Bootloader configuration files if present (e.g, systemd-boot loader.conf)
	for _, conf := range c.LoaderConfs {

		data, err := os.ReadFile(conf)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read bootloader file: %w", err)
		}

		hash := sha256.Sum256(data)
		refvals = append(refvals, &ar.ReferenceValue{
			Type:    "TPM Reference Value",
			SubType: "EV_EVENT_TAG",
			Index:   5,
			Sha256:  hash[:],
		})
		pcr = internal.ExtendSha256(pcr, hash[:])
	}

	// EV_EFI_ACTION "Exit Boot Services Invocation"
	actionData1 := []byte("Exit Boot Services Invocation")
	actionHash1 := sha256.Sum256(actionData1)
	refvals = append(refvals, &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "EV_EFI_ACTION",
		Index:       5,
		Sha256:      actionHash1[:],
		Description: "Exit Boot Services Invocation",
	})
	pcr = internal.ExtendSha256(pcr, actionHash1[:])

	// EV_EFI_ACTION "Exit Boot Services Returned with Success"
	actionData2 := []byte("Exit Boot Services Returned with Success")
	actionHash2 := sha256.Sum256(actionData2)
	refvals = append(refvals, &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "EV_EFI_ACTION",
		Index:       5,
		Sha256:      actionHash2[:],
		Description: "Exit Boot Services Returned with Success",
	})
	pcr = internal.ExtendSha256(pcr, actionHash2[:])

	// Create final reference value
	pcrSummary := &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "PCR Summary",
		Description: "PCR5",
		Index:       5,
		Sha256:      pcr,
	}

	return pcrSummary, refvals, nil
}

func PrecomputePcr6(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	pcr := make([]byte, 32)
	refvals := make([]*ar.ReferenceValue, 0)

	// EV_COMPACT_HASH
	if c.SystemUuid != "" {

		uuid, err := os.ReadFile(c.SystemUuid)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read UUID file: %w", err)
		}

		// Strip newline if present
		uuid = bytes.TrimRight(uuid, "\n")

		uuidString := string(uuid)

		// UUID is measured uppercase
		uuidString = strings.ToUpper(uuidString)

		// Prepend "UUID: "
		uuidString = fmt.Sprintf("UUID: %s", uuidString)

		log.Debugf("Hashing UUID: %q", uuidString)

		hash := sha256.Sum256([]byte(uuidString))
		refvals = append(refvals, &ar.ReferenceValue{
			Type:    "TPM Reference Value",
			SubType: "EV_COMPACT_HASH",
			Index:   6,
			Sha256:  hash[:],
		})
		pcr = internal.ExtendSha256(pcr, hash[:])
	}

	// EV_SEPARATOR
	sep := []byte{0x0, 0x0, 0x0, 0x0}
	hashSep := sha256.Sum256(sep)
	refvals = append(refvals, &ar.ReferenceValue{
		Type:    "TPM Reference Value",
		SubType: "EV_SEPARATOR",
		Index:   6,
		Sha256:  hashSep[:],
	})
	pcr = internal.ExtendSha256(pcr, hashSep[:])

	// Create final reference value
	pcrSummary := &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "PCR Summary",
		Description: "PCR6",
		Index:       6,
		Sha256:      pcr,
	}

	return pcrSummary, refvals, nil
}

func PrecomputePcr7(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	var err error
	pcr := make([]byte, 32)
	refvals := make([]*ar.ReferenceValue, 0)

	pcr, refvals, err = tcg.MeasureSecureBootVariables(crypto.SHA256, tcg.TPM, pcr, refvals, 7, c.SecureBoot, c.Pk, c.Kek, c.Db, c.Dbx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure secure boot variables: %w", err)
	}

	// EV_SEPARATOR
	sep := []byte{0x0, 0x0, 0x0, 0x0}
	hashSep := sha256.Sum256(sep)
	refvals = append(refvals, &ar.ReferenceValue{
		Type:    "TPM Reference Value",
		SubType: "EV_SEPARATOR",
		Index:   7,
		Sha256:  hashSep[:],
	})
	pcr = internal.ExtendSha256(pcr, hashSep[:])

	if c.SbatLevel != "" {
		pcr, refvals, err = tcg.MeasureSbatLevel(crypto.SHA256, tcg.TPM, pcr, refvals, 7, c.SbatLevel)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure SbatLevel: %w", err)
		}
	}

	// Create final reference value
	pcrSummary := &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "PCR Summary",
		Description: "PCR7",
		Index:       7,
		Sha256:      pcr,
	}

	return pcrSummary, refvals, nil
}

func PrecomputePcr8(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	pcr := make([]byte, 32)
	refvals := make([]*ar.ReferenceValue, 0)

	if c.GrubCmds != "" {

		file, err := os.Open(c.GrubCmds)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open grub cmds file: %w", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Bytes()

			var rv *ar.ReferenceValue
			rv, pcr, err = tcg.CreateExtendRefval(crypto.SHA256, tcg.TPM, 8, pcr, line,
				"EV_IPL", string(line))
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create reference values: %w", err)
			}
			refvals = append(refvals, rv)
		}

		if err := scanner.Err(); err != nil {
			return nil, nil, fmt.Errorf("failed to scan grub commands file: %w", err)
		}
	}

	// Create final reference value
	pcrSummary := &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "PCR Summary",
		Description: "PCR8",
		Index:       8,
		Sha256:      pcr,
	}

	return pcrSummary, refvals, nil
}

func PrecomputePcr9(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	var err error
	pcr := make([]byte, 32)
	refvals := make([]*ar.ReferenceValue, 0)

	if len(c.Path) > 0 {
		pcr, refvals, err = tcg.MeasureFiles(crypto.SHA256, tcg.TPM, pcr, refvals, 9, c.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure files: %w", err)
		}
	}

	if c.Cmdline != "" {
		pcr, refvals, err = tcg.MeasureCmdline(crypto.SHA256, tcg.TPM, pcr, refvals, 9,
			c.Cmdline, "EV_EVENT_TAG", c.AddZeros, c.StripNewline, (c.Qemu && (c.Initrd != "")))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure cmdline: %w", err)
		}
	}

	if c.Initrd != "" {
		pcr, refvals, err = tcg.MeasureFile(crypto.SHA256, tcg.TPM, "EV_EVENT_TAG", pcr, refvals, 9, c.Initrd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure initrd: %w", err)
		}
	}

	// Create final reference value
	pcrSummary := &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "PCR Summary",
		Description: "PCR9",
		Index:       9,
		Sha256:      pcr,
	}

	return pcrSummary, refvals, nil
}

func PrecomputePcr10(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	refvals, err := performImaPrecomputation(10, c.BootAggregate, c.ImaPaths, c.ImaStrip, c.ImaPrepend, c.ImaTemplate)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to precompute IMA refvals: %w", err)
	}

	// For PCR10, calculating the final PCR value does not make sense, as the order of
	// measurements cannot be predicted
	return nil, refvals, nil
}

func PrecomputePcr11(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	var err error
	pcr := make([]byte, 32)
	refvals := make([]*ar.ReferenceValue, 0)

	if len(c.Path) > 0 {
		pcr, refvals, err = tcg.MeasureFiles(crypto.SHA256, tcg.TPM, pcr, refvals, 11, c.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure files: %w", err)
		}
	}

	if c.Cmdline != "" {
		pcr, refvals, err = tcg.MeasureCmdlineNarrow(crypto.SHA256, tcg.TPM, pcr, refvals, 11,
			c.Cmdline, "EV_IPL", c.AddZeros, c.StripNewline, (c.Qemu && (c.Initrd != "")))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure cmdline: %w", err)
		}
	}

	if c.Initrd != "" {
		pcr, refvals, err = tcg.MeasureFile(crypto.SHA256, tcg.TPM, "EV_EVENT_TAG", pcr, refvals, 11, c.Initrd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure initrd: %w", err)
		}
	}

	// Create final reference value
	pcrSummary := &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "PCR Summary",
		Description: "PCR11",
		Index:       11,
		Sha256:      pcr,
	}

	return pcrSummary, refvals, nil
}

func PrecomputePcr12(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	var err error
	pcr := make([]byte, 32)
	refvals := make([]*ar.ReferenceValue, 0)

	if c.Cmdline != "" {
		pcr, refvals, err = tcg.MeasureCmdline(crypto.SHA256, tcg.TPM, pcr, refvals, 12,
			c.Cmdline, "EV_IPL", c.AddZeros, c.StripNewline, (c.Qemu && (c.Initrd != "")))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure cmdline: %w", err)
		}
	}

	// Create final reference value
	pcrSummary := &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "PCR Summary",
		Description: "PCR12",
		Index:       12,
		Sha256:      pcr,
	}

	return pcrSummary, refvals, nil
}

func PrecomputePcr14(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	var err error
	pcr := make([]byte, 32)
	refvals := make([]*ar.ReferenceValue, 0)

	// EV_IPL: EFI MOK-Lists
	pcr, refvals, err = tcg.MeasureMoklists(crypto.SHA256, tcg.TPM, pcr, refvals, 14, c.MokLists)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure MOK lists: %w", err)
	}

	// Create final reference value
	pcrSummary := &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "PCR Summary",
		Description: "PCR14",
		Index:       14,
		Sha256:      pcr,
	}

	return pcrSummary, refvals, nil
}
