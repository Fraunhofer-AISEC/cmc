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
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	EFI_HOB_GENERIC_HEADER_SIZE      = 56 // sizeof(EFI_HOB_HANDOFF_INFO_TABLE)
	EFI_HOB_RESOURCE_DESCRIPTOR_SIZE = 48 // sizeof(EFI_HOB_RESOURCE_DESCRIPTOR)

	RESOURCE_DESCRIPTOR_LEN = 9

	EFI_HOB_TYPE_HANDOFF             = 0x01
	EFI_HOB_TYPE_RESOURCE_DESCRIPTOR = 0x03
	EFI_HOB_HANDOFF_TABLE_VERSION    = 0x09

	// 0x21 - 0xFF... are reserved
	BOOT_WITH_FULL_CONFIGURATION = 0x00

	EFI_RESOURCE_SYSTEM_MEMORY     = 0x00
	EFI_RESOURCE_MEMORY_UNACCEPTED = 0x07

	EFI_RESOURCE_ATTRIBUTE_PRESENT     = 0x01
	EFI_RESOURCE_ATTRIBUTE_INITIALIZED = 0x02
	EFI_RESOURCE_ATTRIBUTE_TESTED      = 0x04
)

// Format and size of the data inside the HOB (all HOBs must contain this generic header)
type HobHeader struct {
	HobType   uint16 // HOB structure type
	HobLength uint16 // length in bytes
	Reserved  uint32 // must be zero
}

// General state information (this HOB must be the first in the HOB list)
type HobHandoffInfoTable struct {
	Header              HobHeader // generic header; HobType = EFI_HOB_TYPE_HANDOFF
	Version             uint32    // PHIT version (4 bytes for 8-byte align with BootMode)
	BootMode            uint32    // system boot mode
	EfiMemoryTop        uint64    // highest allocated addr (4KB aligned)
	EfiMemoryBottom     uint64    // lowest allocated addr
	EfiFreeMemoryTop    uint64    // highest free addr
	EfiFreeMemoryBottom uint64    // lowest free addr
	EfiEndOfHobList     uint64    // end of HOB list
}

// Resource properties of all nonrelocatable resource ranges on host bus during HOB produce phase
type HobResourceDescriptor struct {
	Header            HobHeader // generic header; HobType = EFI_HOB_TYPE_RESOURCE_DESCRIPTOR
	Owner             [16]byte  // owner GUID (type is placeholder)
	ResourceType      uint32    // EFI_RESOURCE_TYPE
	ResourceAttribute uint32    // EFI_RESOURCE_ATTRIBUTE_TYPE
	PhysicalStart     uint64    // physical start address
	ResourceLength    uint64    // size in bytes
}

func CreateTbHob() ([]byte, error) {
	// Create Handoff Info Table
	tbl := HobHandoffInfoTable{
		Header: HobHeader{
			HobType:   EFI_HOB_TYPE_HANDOFF,
			HobLength: uint16(binary.Size(HobHandoffInfoTable{})),
			Reserved:  0,
		},
		Version:         EFI_HOB_HANDOFF_TABLE_VERSION,
		BootMode:        BOOT_WITH_FULL_CONFIGURATION,
		EfiEndOfHobList: 0x8091f0,
	}

	buffer := bytes.Buffer{}
	binary.Write(&buffer, binary.LittleEndian, tbl)

	// Sizes: OvmfPkg/OvmfPkgX64.fdf
	// Build/OvmfX64/RELEASE_GCC5/X64/OvmfPkg/ResetVector/ResetVector/DEBUG/Autogen.h
	// Build/OvmfX64/DEBUG_GCC5/X64/OvmfPkg/Sec/SecMain/DEBUG/AutoGen.h
	// Build/OvmfX64/RELEASE_GCC5/X64/OvmfPkg/PlatformPei/PlatformPei/DEBUG/PlatformPei.debug
	physicalStart := []uint64{
		0x0,         // Size: 0x800000       ?? Reserved BIOS Legacy
		0x800000,    // Size: 0x6000         _PCD_VALUE_PcdOvmfSecPageTablesBase
		0x806000,    // Size: 0x3000         _PCD_VALUE_PcdOvmfLockBoxStorageBase
		0x809000,    // Size: 0x2000         _PCD_VALUE_PcdOvmfSecGhcbBase
		0x80b000,    // Size: 0x2000         _PCD_VALUE_PcdOvmfWorkAreaBase
		0x80d000,    // Size: 0x4000         _PCD_VALUE_PcdOvmfSnpSecretsBase
		0x811000,    // Size: 0xF000         _PCD_VALUE_PcdOvmfSecPeiTempRamBase
		0x820000,    // Size: 0x7F7E0000     _PCD_VALUE_PcdOvmfPeiMemFvBase
		0x100000000, // Size: 0x80000000     ?? PCI MMIO
	}
	resourceLength := []uint64{
		0x800000,   // Base: 0x0            ??
		0x6000,     // Base: 0x800000       _PCD_VALUE_PcdOvmfSecPageTablesBase         _PCD_VALUE_PcdOvmfSecPageTablesSize
		0x3000,     // Base: 0x806000       _PCD_VALUE_PcdOvmfLockBoxStorageBase        _PCD_VALUE_PcdOvmfLockBoxStorageSize (0x1000) + _PCD_VALUE_PcdGuidedExtractHandlerTableSize (0x1000) + _PCD_VALUE_PcdOvmfSecGhcbPageTableSize (0x1000)
		0x2000,     // Base: 0x809000       _PCD_VALUE_PcdOvmfSecGhcbBase               _PCD_VALUE_PcdOvmfSecGhcbSize
		0x2000,     // Base: 0x80b000       _PCD_VALUE_PcdOvmfWorkAreaBase              _PCD_VALUE_PcdOvmfWorkAreaSize (0x1000) + _PCD_VALUE_PcdOvmfCpuidSize (0x1000)
		0x4000,     // Base: 0x80d000       _PCD_VALUE_PcdOvmfSnpSecretsBase            _PCD_VALUE_PcdOvmfSnpSecretsSize (0x1000) + _PCD_VALUE_PcdOvmfCpuidSize (0x1000) + _PCD_VALUE_PcdOvmfSecSvsmCaaSize (0x1000) + _PCD_VALUE_PcdOvmfSecApicPageTableSize (0x1000)
		0xF000,     // Base: 0x811000       _PCD_VALUE_PcdOvmfSecPeiTempRamBase         _PCD_VALUE_PcdOvmfSecPeiTempRamSize
		0x7F7E0000, // Base: 0x820000       _PCD_VALUE_PcdOvmfPeiMemFvBase              ?? _PCD_VALUE_PcdOvmfPeiMemFvSize (0xE0000) + _PCD_VALUE_PcdOvmfDxeMemFvSize (0xE80000)
		0x80000000, // Base: 0x100000000    ??
	}
	resourceType := []uint32{
		EFI_RESOURCE_MEMORY_UNACCEPTED, EFI_RESOURCE_SYSTEM_MEMORY,
		EFI_RESOURCE_MEMORY_UNACCEPTED, EFI_RESOURCE_SYSTEM_MEMORY,
		EFI_RESOURCE_SYSTEM_MEMORY, EFI_RESOURCE_MEMORY_UNACCEPTED,
		EFI_RESOURCE_SYSTEM_MEMORY, EFI_RESOURCE_MEMORY_UNACCEPTED,
		EFI_RESOURCE_MEMORY_UNACCEPTED,
	}

	// Append Resource Descriptors
	for i := 0; i < RESOURCE_DESCRIPTOR_LEN; i++ {
		rd := HobResourceDescriptor{
			Header: HobHeader{
				HobType:   EFI_HOB_TYPE_RESOURCE_DESCRIPTOR,
				HobLength: uint16(binary.Size(HobResourceDescriptor{})),
				Reserved:  0,
			},
			Owner:        [16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			ResourceType: resourceType[i],
			ResourceAttribute: EFI_RESOURCE_ATTRIBUTE_PRESENT |
				EFI_RESOURCE_ATTRIBUTE_INITIALIZED |
				EFI_RESOURCE_ATTRIBUTE_TESTED,
			PhysicalStart:  physicalStart[i],
			ResourceLength: resourceLength[i],
		}

		binary.Write(&buffer, binary.LittleEndian, rd)
	}

	bytes, byteLength := buffer.Bytes(), EFI_HOB_GENERIC_HEADER_SIZE+EFI_HOB_RESOURCE_DESCRIPTOR_SIZE*RESOURCE_DESCRIPTOR_LEN
	if len(bytes) != byteLength {
		return []byte{}, fmt.Errorf("TB Hob size does not match expected size (expect: %d; is: %d)", byteLength, len(bytes))
	}
	return bytes, nil
}
