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

func PrecomputeRtmr1(c *Config) (*ar.ReferenceValue, []*ar.ReferenceValue, error) {

	log.Debugf("Precomputing RTMR1...")

	pcr := make([]byte, 48)
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
		pcr = internal.ExtendSha384(hash[:], pcr)

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
	pcr = internal.ExtendSha384(h1[:], pcr)

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
		pcr = internal.ExtendSha384(hashSep[:], pcr)
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
	pcr = internal.ExtendSha384(h2[:], pcr)

	// EV_EFI_ACTION
	h3 := sha512.Sum384([]byte(EFI_EXIT_BOOT_SERVICES_SUCCEEDED))
	refvals = append(refvals, &ar.ReferenceValue{
		Type:        "TDX Reference Value",
		SubType:     "EV_EFI_ACTION",
		Index:       INDEX_RTMR1,
		Sha384:      h3[:],
		Description: fmt.Sprintf("RTMR1: %v", EFI_EXIT_BOOT_SERVICES_SUCCEEDED),
	})
	pcr = internal.ExtendSha384(h3[:], pcr)

	// Create PCR4 final reference value
	pcrSummary := &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     "PCR Summary",
		Description: "PCR4",
		Index:       4,
		Sha384:      pcr,
	}

	return pcrSummary, refvals, nil

}
