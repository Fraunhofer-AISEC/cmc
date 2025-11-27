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

	// HobType of EFI_HOB_GENERIC_HEADER.
	EFI_HOB_TYPE_HANDOFF             = 0x01
	EFI_HOB_TYPE_RESOURCE_DESCRIPTOR = 0x03
	EFI_HOB_HANDOFF_TABLE_VERSION    = 0x09

	//
	// 0x21 - 0xf..f are reserved.
	//
	BOOT_WITH_FULL_CONFIGURATION = 0x00

	//
	// Value of ResourceType in EFI_HOB_RESOURCE_DESCRIPTOR.
	//
	EFI_RESOURCE_SYSTEM_MEMORY     = 0x00
	EFI_RESOURCE_MEMORY_UNACCEPTED = 0x07

	EFI_RESOURCE_ATTRIBUTE_PRESENT     = 0x01
	EFI_RESOURCE_ATTRIBUTE_INITIALIZED = 0x02
	EFI_RESOURCE_ATTRIBUTE_TESTED      = 0x04
)

// Describes the format and size of the data inside the HOB.
// All HOBs must contain this generic HOB header.
type HobHeader struct {
	//
	// Identifies the HOB data structure type.
	//
	HobType uint16
	//
	// The length in bytes of the HOB.
	//
	HobLength uint16
	//
	// This field must always be set to zero.
	//
	Reserved uint32
}

// Contains general state information used by the HOB producer phase.
// This HOB must be the first one in the HOB list.
type HobHandoffInfoTable struct {
	//
	// The HOB generic header. Header.HobType = EFI_HOB_TYPE_HANDOFF.
	//
	Header HobHeader
	//
	// The version number pertaining to the PHIT HOB definition.
	// This value is four bytes in length to provide an 8-byte aligned entry
	// when it is combined with the 4-byte BootMode.
	//
	Version uint32
	//
	// The system boot mode as determined during the HOB producer phase.
	//
	BootMode uint32
	//
	// The highest address location of memory that is allocated for use by the HOB producer
	// phase. This address must be 4-KB aligned to meet page restrictions of UEFI.
	//
	EfiMemoryTop uint64
	//
	// The lowest address location of memory that is allocated for use by the HOB producer phase.
	//
	EfiMemoryBottom uint64
	//
	// The highest address location of free memory that is currently available
	// for use by the HOB producer phase.
	//
	EfiFreeMemoryTop uint64
	//
	// The lowest address location of free memory that is available for use by the HOB producer phase.
	//
	EfiFreeMemoryBottom uint64
	//
	// The end of the HOB list.
	//
	EfiEndOfHobList uint64
}

// Describes the resource properties of all fixed,
// nonrelocatable resource ranges found on the processor
// host bus during the HOB producer phase.
type HobResourceDescriptor struct {
	//
	// The HOB generic header. Header.HobType = EFI_HOB_TYPE_RESOURCE_DESCRIPTOR.
	//
	Header HobHeader
	//
	// A GUID representing the owner of the resource. This GUID is used by HOB
	// consumer phase components to correlate device ownership of a resource.
	//
	Owner [16]byte // GUID placeholder
	//
	// The resource type enumeration as defined by EFI_RESOURCE_TYPE.
	//
	ResourceType uint32
	//
	// Resource attributes as defined by EFI_RESOURCE_ATTRIBUTE_TYPE.
	//
	ResourceAttribute uint32
	//
	// The physical start address of the resource region.
	//
	PhysicalStart uint64
	//
	// The number of bytes of the resource region.
	//
	ResourceLength uint64
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
