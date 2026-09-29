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
	"fmt"
	"os"
	"path/filepath"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/tcg"
)

// measureGpt records the EV_EFI_GPT_EVENT of the UEFI partition table into the given PCR. The raw
// disk data can be provided, the GPT partition table is located within it if present.
func (c *Config) measureGpt(pcr []byte, refvals []*ar.Component, index int,
) ([]byte, []*ar.Component, error) {

	if c.Gpt == "" {
		return pcr, refvals, nil
	}

	hash, description, err := tcg.MeasureGptFromFile(c.HashAlg.New(), c.Gpt, c.DumpGpt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure GPT: %w", err)
	}

	pcr, refvals, err = c.extendDigest(pcr, refvals, index, "EV_EFI_GPT_EVENT", hash, description)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure GPT: %w", err)
	}

	return pcr, refvals, nil
}

// measureBootApplications records an EV_EFI_BOOT_SERVICES_APPLICATION into the given PCR for every
// bootloader and for a directly booted kernel.
func (c *Config) measureBootApplications(pcr []byte, refvals []*ar.Component, index int,
) ([]byte, []*ar.Component, error) {

	for _, f := range c.Bootloaders {

		data, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read file: %w", err)
		}

		hash, err := tcg.MeasurePeCoff(c.HashAlg, data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure PE image: %w", err)
		}

		pcr, refvals, err = c.extendDigest(pcr, refvals, index,
			"EV_EFI_BOOT_SERVICES_APPLICATION", hash, filepath.Base(f))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure bootloader %v: %w", f, err)
		}
	}

	if c.Kernel == "" {
		return pcr, refvals, nil
	}

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

	pcr, refvals, err = c.extendDigest(pcr, refvals, index, "EV_EFI_BOOT_SERVICES_APPLICATION",
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

	return pcr, refvals, nil
}

func detectDriverFileType(file string) (DriverFileType, error) {

	f, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	buf := make([]byte, 2)
	if _, err := f.Read(buf); err != nil {
		log.Fatal(err)
	}

	switch {
	case buf[0] == 0x4D && buf[1] == 0x5A:
		log.Debug("Detected file type: PE/COFF")
		return PECOFF, nil
	case buf[0] == 0x55 && buf[1] == 0xAA:
		log.Debug("Detected file type: Option ROM")
		return OptionROM, nil
	default:
		return Unknown, fmt.Errorf("unknown driver file type %02x %02x", buf[0], buf[1])
	}

}
