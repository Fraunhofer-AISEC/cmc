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
	"bytes"
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

		hash, err := cgo.MeasurePeImage(cgo.SHA384, data)
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
	for _, bl := range c.Bootloaders {

		data, err := os.ReadFile(bl)
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
		Index:   5,
		Sha256:  hashSep[:],
	})
	pcr = internal.ExtendSha256(pcr, hashSep[:])

	// Create final reference value
	pcrSummary := &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "PCR Summary",
		Description: "PCR6",
		Index:       5,
		Sha256:      pcr,
	}

	return pcrSummary, refvals, nil
}
