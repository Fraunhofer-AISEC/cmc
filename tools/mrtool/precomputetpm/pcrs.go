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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/tcg"
)

func newComponent(ta string, index int, name string, hashes []ar.ReferenceHash, desc string,
) *ar.Component {
	c := &ar.Component{
		Type:        ar.CycloneDxType(ta, index),
		Name:        name,
		Hashes:      hashes,
		Description: desc,
	}
	c.SetTrustAnchor(ta)
	c.SetIndex(index)
	return c
}

// hashExtend hashes the specified data with the configured PCR bank hash algorithm, creates a
// reference value for the resulting digest and extends the PCR with it
func (c *Config) hashExtend(pcr []byte, refvals []*ar.Component, index int, name string,
	data []byte, desc string,
) ([]byte, []*ar.Component, error) {

	digest, err := internal.Hash(c.HashAlg, data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash: %w", err)
	}

	return c.extendDigest(pcr, refvals, index, name, digest, desc)
}

// extendDigest creates a reference value for the specified digest and extends the PCR with it
func (c *Config) extendDigest(pcr []byte, refvals []*ar.Component, index int, name string,
	digest []byte, desc string,
) ([]byte, []*ar.Component, error) {

	refvals = append(refvals, newComponent(ar.TRUST_ANCHOR_TPM, index, name,
		[]ar.ReferenceHash{{Alg: c.HashAlg.String(), Content: digest}}, desc))

	pcr, err := internal.Extend(c.HashAlg, pcr, digest)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extend: %w", err)
	}

	return pcr, refvals, nil
}

// pcrSummary creates the reference value for the final PCR value
func (c *Config) pcrSummary(index int, pcr []byte) *ar.Component {
	return newComponent(ar.TRUST_ANCHOR_TPM, index, ar.TYPE_PCR_SUMMARY,
		[]ar.ReferenceHash{{Alg: c.HashAlg.String(), Content: pcr}},
		fmt.Sprintf("PCR%v", index))
}

type DriverFileType int

const (
	Unknown DriverFileType = iota
	PECOFF
	OptionROM
)

func PrecomputePcr0(c *Config) (*ar.Component, []*ar.Component, error) {

	var err error
	pcr := make([]byte, c.HashAlg.Size())
	refvals := make([]*ar.Component, 0)

	// EV_S_CRTM_VERSION
	// For VMs, this is usually { 0x0, 0x0 }
	var rv *ar.Component
	rv, pcr, err = tcg.CreateExtendRefval(c.HashAlg, tcg.TPM, 0, pcr, []byte{0x0, 0x0},
		"EV_S_CRTM_VERSION", "CRTM Version String")
	if err != nil {
		return nil, nil, fmt.Errorf("faied to measure CRTM version: %w", err)
	}
	refvals = append(refvals, rv)

	// EV_EFI_PLATFORM_FIRMWARE_BLOB
	pcr, refvals, err = tcg.MeasureOvmf(c.HashAlg, tcg.TPM, pcr, refvals, 0, c.Ovmf)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure OVMF: %w", err)
	}

	// EV_SEPARATOR
	pcr, refvals, err = c.hashExtend(pcr, refvals, 0, "EV_SEPARATOR",
		[]byte{0x0, 0x0, 0x0, 0x0}, "HASH(0000)")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure EV_SEPARATOR: %w", err)
	}

	// Create final reference value
	pcrSummary := c.pcrSummary(0, pcr)

	return pcrSummary, refvals, nil
}

func PrecomputePcr1(c *Config) (*ar.Component, []*ar.Component, error) {

	var err error
	pcr := make([]byte, c.HashAlg.Size())
	refvals := make([]*ar.Component, 0)

	// EV_PLATFORM_CONFIG_FLAGS: ACPI tables
	pcr, refvals, err = tcg.CalculateAcpiTables(c.HashAlg, tcg.TPM, pcr, refvals,
		1, c.AcpiRsdp, c.AcpiTables, c.TableLoader, c.TpmLog)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate acpi tables: %w", err)
	}

	// SMBIOS tables recorded as EV_EFI_HANDOFF_TABLES.
	var smbiosBlob []byte
	switch {
	// Capture mode: the input is /sys/firmware/dmi/tables/DMI dumped from a reference VM
	case c.SmbiosTables != "":
		smbiosBlob, err = os.ReadFile(c.SmbiosTables)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read SMBIOS tables: %w", err)
		}
	// Spec mode: encode the table from the spec, matching what OVMF would install
	case c.SmbiosSpec != nil:
		smbiosBlob, err = tcg.BuildSmbiosTable(*c.SmbiosSpec)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encode SMBIOS spec: %w", err)
		}
	}
	if smbiosBlob != nil {
		filtered, err := tcg.FilterSmbiosForMeasurement(smbiosBlob)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to filter SMBIOS tables: %w", err)
		}
		var rv *ar.Component
		rv, pcr, err = tcg.CreateExtendRefval(c.HashAlg, tcg.TPM, 1, pcr,
			filtered, "EV_EFI_HANDOFF_TABLES", "smbios-tables")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure SMBIOS tables: %w", err)
		}
		refvals = append(refvals, rv)

		if c.DumpSmbios != "" {
			if err := os.WriteFile(c.DumpSmbios, filtered, 0644); err != nil {
				return nil, nil, fmt.Errorf("failed to write smbios dump: %w", err)
			}
		}
	}

	// EV_EFI_VARIABLE_BOOT: boot variables. Some firmwares, such as OpenHCL, do not measure boot
	// variables
	if !c.NoBootVars {
		pcr, refvals, err = tcg.MeasureEfiBootVars(c.HashAlg, tcg.TPM, pcr, refvals,
			1, c.BootOrder, c.BootXxxx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to calculate EFI boot variables: %w", err)
		}
	}

	// EV_SEPARATOR
	pcr, refvals, err = c.hashExtend(pcr, refvals, 1, "EV_SEPARATOR",
		[]byte{0x0, 0x0, 0x0, 0x0}, "HASH(0000)")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure EV_SEPARATOR: %w", err)
	}

	// Create final reference value
	pcrSummary := c.pcrSummary(1, pcr)

	return pcrSummary, refvals, nil
}

func PrecomputePcr2(c *Config) (*ar.Component, []*ar.Component, error) {

	var err error
	pcr := make([]byte, c.HashAlg.Size())
	refvals := make([]*ar.Component, 0)

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

		hash, err := tcg.MeasurePeCoff(c.HashAlg, data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure PE image: %w", err)
		}

		pcr, refvals, err = c.extendDigest(pcr, refvals, 2, "EV_EFI_BOOT_SERVICES_DRIVER",
			hash, filepath.Base(f))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure driver %v: %w", f, err)
		}
	}

	// EV_SEPARATOR
	pcr, refvals, err = c.hashExtend(pcr, refvals, 2, "EV_SEPARATOR",
		[]byte{0x0, 0x0, 0x0, 0x0}, "HASH(0000)")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure EV_SEPARATOR: %w", err)
	}

	// Create final reference value
	pcrSummary := c.pcrSummary(2, pcr)

	return pcrSummary, refvals, nil
}

func PrecomputePcr3(c *Config) (*ar.Component, []*ar.Component, error) {

	var err error
	pcr := make([]byte, c.HashAlg.Size())
	refvals := make([]*ar.Component, 0)

	// EV_SEPARATOR
	pcr, refvals, err = c.hashExtend(pcr, refvals, 3, "EV_SEPARATOR",
		[]byte{0x0, 0x0, 0x0, 0x0}, "HASH(0000)")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure EV_SEPARATOR: %w", err)
	}

	// Create final reference value
	pcrSummary := c.pcrSummary(3, pcr)

	return pcrSummary, refvals, nil
}

func PrecomputePcr4(c *Config) (*ar.Component, []*ar.Component, error) {

	var err error
	pcr := make([]byte, c.HashAlg.Size())
	refvals := make([]*ar.Component, 0)

	// EV_EFI_BOOT_SERVICES_APPLICATION: Measure bootloaders if present
	for _, f := range c.Bootloaders {

		data, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read file: %w", err)
		}

		hash, err := tcg.MeasurePeCoff(c.HashAlg, data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure PE image: %w", err)
		}

		pcr, refvals, err = c.extendDigest(pcr, refvals, 4, "EV_EFI_BOOT_SERVICES_APPLICATION",
			hash, filepath.Base(f))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure bootloader %v: %w", f, err)
		}
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

		hash, err := tcg.MeasurePeCoff(c.HashAlg, data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure PE image: %w", err)
		}

		pcr, refvals, err = c.extendDigest(pcr, refvals, 4, "EV_EFI_BOOT_SERVICES_APPLICATION",
			hash, filepath.Base(c.Kernel))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure kernel: %w", err)
		}

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
	pcr, refvals, err = c.hashExtend(pcr, refvals, 4, "EV_EFI_ACTION", actionData,
		string(actionData))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure EV_EFI_ACTION: %w", err)
	}

	// EV_SEPARATOR
	pcr, refvals, err = c.hashExtend(pcr, refvals, 4, "EV_SEPARATOR",
		[]byte{0x0, 0x0, 0x0, 0x0}, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure EV_SEPARATOR: %w", err)
	}

	// Create final reference value
	pcrSummary := c.pcrSummary(4, pcr)

	return pcrSummary, refvals, nil
}

func PrecomputePcr5(c *Config) (*ar.Component, []*ar.Component, error) {

	var err error
	pcr := make([]byte, c.HashAlg.Size())
	refvals := make([]*ar.Component, 0)

	// EV_SEPARATOR
	pcr, refvals, err = c.hashExtend(pcr, refvals, 5, "EV_SEPARATOR",
		[]byte{0x0, 0x0, 0x0, 0x0}, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure EV_SEPARATOR: %w", err)
	}

	// EV_EFI_GPT
	// Calculate UEFI GPT partition table if provided. The raw disk data can be
	// provided, the function will find the GPT partition table if present
	if c.Gpt != "" {
		hash, description, err := tcg.MeasureGptFromFile(c.HashAlg.New(), c.Gpt, c.DumpGpt)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure GPT: %w", err)
		}

		pcr, refvals, err = c.extendDigest(pcr, refvals, 5, "EV_EFI_GPT_EVENT", hash, description)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure GPT: %w", err)
		}
	}

	// EV_EVENT_TAG
	// Bootloader configuration files if present (e.g, systemd-boot loader.conf)
	for _, conf := range c.LoaderConfs {

		data, err := os.ReadFile(conf)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read bootloader file: %w", err)
		}

		pcr, refvals, err = c.hashExtend(pcr, refvals, 5, "EV_EVENT_TAG", data, "")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure bootloader config %v: %w", conf, err)
		}
	}

	// EV_EFI_ACTION "Exit Boot Services Invocation"
	actionData1 := []byte("Exit Boot Services Invocation")
	pcr, refvals, err = c.hashExtend(pcr, refvals, 5, "EV_EFI_ACTION", actionData1,
		string(actionData1))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure EV_EFI_ACTION: %w", err)
	}

	// EV_EFI_ACTION "Exit Boot Services Returned with Success"
	actionData2 := []byte("Exit Boot Services Returned with Success")
	pcr, refvals, err = c.hashExtend(pcr, refvals, 5, "EV_EFI_ACTION", actionData2,
		string(actionData2))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure EV_EFI_ACTION: %w", err)
	}

	// Create final reference value
	pcrSummary := c.pcrSummary(5, pcr)

	return pcrSummary, refvals, nil
}

func PrecomputePcr6(c *Config) (*ar.Component, []*ar.Component, error) {

	var err error
	pcr := make([]byte, c.HashAlg.Size())
	refvals := make([]*ar.Component, 0)

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

		pcr, refvals, err = c.hashExtend(pcr, refvals, 6, "EV_COMPACT_HASH",
			[]byte(uuidString), "")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure system UUID: %w", err)
		}
	}

	// EV_COMPACT_HASH: machine architecture, measured by OpenHCL
	if c.MachineArchitecture != "" {

		archString := fmt.Sprintf("{\"MachineArchitecture\": %q}", c.MachineArchitecture)

		log.Debugf("Hashing machine architecture: %q", archString)

		pcr, refvals, err = c.hashExtend(pcr, refvals, 6, "EV_COMPACT_HASH",
			[]byte(archString), archString)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure machine architecture: %w", err)
		}
	}

	// EV_SEPARATOR
	pcr, refvals, err = c.hashExtend(pcr, refvals, 6, "EV_SEPARATOR",
		[]byte{0x0, 0x0, 0x0, 0x0}, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure EV_SEPARATOR: %w", err)
	}

	// Create final reference value
	pcrSummary := c.pcrSummary(6, pcr)

	return pcrSummary, refvals, nil
}

func PrecomputePcr7(c *Config) (*ar.Component, []*ar.Component, error) {

	var err error
	pcr := make([]byte, c.HashAlg.Size())
	refvals := make([]*ar.Component, 0)

	pcr, refvals, err = tcg.MeasureSecureBootVariables(c.HashAlg, tcg.TPM, pcr, refvals, 7, c.SecureBoot, c.Pk, c.Kek, c.Db, c.Dbx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure secure boot variables: %w", err)
	}

	// EV_SEPARATOR
	pcr, refvals, err = c.hashExtend(pcr, refvals, 7, "EV_SEPARATOR",
		[]byte{0x0, 0x0, 0x0, 0x0}, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure EV_SEPARATOR: %w", err)
	}

	if c.SbatLevel != "" {
		pcr, refvals, err = tcg.MeasureSbatLevel(c.HashAlg, tcg.TPM, pcr, refvals, 7, c.SbatLevel)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure SbatLevel: %w", err)
		}
	}

	// Create final reference value
	pcrSummary := c.pcrSummary(7, pcr)

	return pcrSummary, refvals, nil
}

func PrecomputePcr8(c *Config) (*ar.Component, []*ar.Component, error) {

	pcr := make([]byte, c.HashAlg.Size())
	refvals := make([]*ar.Component, 0)

	if c.GrubCmds != "" {

		file, err := os.Open(c.GrubCmds)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open grub cmds file: %w", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Bytes()

			var rv *ar.Component
			rv, pcr, err = tcg.CreateExtendRefval(c.HashAlg, tcg.TPM, 8, pcr, line,
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
	pcrSummary := c.pcrSummary(8, pcr)

	return pcrSummary, refvals, nil
}

func PrecomputePcr9(c *Config) (*ar.Component, []*ar.Component, error) {

	var err error
	pcr := make([]byte, c.HashAlg.Size())
	refvals := make([]*ar.Component, 0)

	if len(c.Path) > 0 {
		pcr, refvals, err = tcg.MeasureFiles(c.HashAlg, tcg.TPM, pcr, refvals, 9, c.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure files: %w", err)
		}
	}

	if c.Cmdline != "" {
		pcr, refvals, err = tcg.MeasureCmdline(c.HashAlg, tcg.TPM, pcr, refvals, 9,
			c.Cmdline, "EV_EVENT_TAG", c.AddZeros, c.StripNewline, c.InitrdOption)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure cmdline: %w", err)
		}
	}

	if c.Initrd != "" {
		pcr, refvals, err = tcg.MeasureFile(c.HashAlg, tcg.TPM, "EV_EVENT_TAG", pcr, refvals, 9, c.Initrd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure initrd: %w", err)
		}
	}

	// Create final reference value
	pcrSummary := c.pcrSummary(9, pcr)

	return pcrSummary, refvals, nil
}

func PrecomputePcr10(c *Config) (*ar.Component, []*ar.Component, error) {

	refvals, err := PerformImaPrecomputation(ar.TRUST_ANCHOR_TPM, c.HashAlg, c.ImaHashAlg, 10,
		c.BootAggregate, c.ImaPaths, c.ImaStrip, c.ImaPrepend, c.ImaTemplate, c.ImaExecOnly,
		c.ImaSeeds)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to precompute IMA refvals: %w", err)
	}

	// For PCR10, calculating the final PCR value does not make sense, as the order of
	// measurements cannot be predicted
	return nil, refvals, nil
}

func PrecomputePcr11(c *Config) (*ar.Component, []*ar.Component, error) {

	var err error
	pcr := make([]byte, c.HashAlg.Size())
	refvals := make([]*ar.Component, 0)

	// systemd-stub measures the name and the contents of every section of the
	// Unified Kernel Image it was linked into
	if c.Uki != "" {
		pcr, refvals, err = tcg.MeasureUki(c.HashAlg, tcg.TPM, pcr, refvals, 11, c.Uki)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure UKI: %w", err)
		}
	}

	if len(c.Path) > 0 {
		pcr, refvals, err = tcg.MeasureFiles(c.HashAlg, tcg.TPM, pcr, refvals, 11, c.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure files: %w", err)
		}
	}

	if c.Cmdline != "" {
		pcr, refvals, err = tcg.MeasureCmdlineNarrow(c.HashAlg, tcg.TPM, pcr, refvals, 11,
			c.Cmdline, "EV_IPL", c.AddZeros, c.StripNewline)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure cmdline: %w", err)
		}
	}

	if c.Initrd != "" {
		pcr, refvals, err = tcg.MeasureFile(c.HashAlg, tcg.TPM, "EV_EVENT_TAG", pcr, refvals, 11, c.Initrd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure initrd: %w", err)
		}
	}

	// Create final reference value
	pcrSummary := c.pcrSummary(11, pcr)

	return pcrSummary, refvals, nil
}

func PrecomputePcr12(c *Config) (*ar.Component, []*ar.Component, error) {

	var err error
	pcr := make([]byte, c.HashAlg.Size())
	refvals := make([]*ar.Component, 0)

	if c.Cmdline != "" {
		pcr, refvals, err = tcg.MeasureCmdline(c.HashAlg, tcg.TPM, pcr, refvals, 12,
			c.Cmdline, "EV_IPL", c.AddZeros, c.StripNewline, tcg.InitrdOptionNone)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure cmdline: %w", err)
		}
	}

	// Create final reference value
	pcrSummary := c.pcrSummary(12, pcr)

	return pcrSummary, refvals, nil
}

func PrecomputePcr14(c *Config) (*ar.Component, []*ar.Component, error) {

	var err error
	pcr := make([]byte, c.HashAlg.Size())
	refvals := make([]*ar.Component, 0)

	// EV_IPL: EFI MOK-Lists
	pcr, refvals, err = tcg.MeasureMoklists(c.HashAlg, tcg.TPM, pcr, refvals, 14, c.MokLists)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure MOK lists: %w", err)
	}

	// Create final reference value
	pcrSummary := c.pcrSummary(14, pcr)

	return pcrSummary, refvals, nil
}
