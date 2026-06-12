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
	"os"
	"sort"

	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/tcg"
)

const (
	EFI_HOB_GENERIC_HEADER_SIZE      = 56 // sizeof(EFI_HOB_HANDOFF_INFO_TABLE)
	EFI_HOB_RESOURCE_DESCRIPTOR_SIZE = 48 // sizeof(EFI_HOB_RESOURCE_DESCRIPTOR)
	EFI_HOB_END_OF_HOB_LIST_SIZE     = 8  // sizeof(EFI_HOB_GENERIC_HEADER)

	EFI_HOB_TYPE_HANDOFF             = 0x01
	EFI_HOB_TYPE_RESOURCE_DESCRIPTOR = 0x03
	EFI_HOB_TYPE_END_OF_HOB_LIST     = 0xFFFF
	EFI_HOB_HANDOFF_TABLE_VERSION    = 0x09

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

// ramEntry mirrors qemu's TdxRamEntry: a contiguous RAM range that is either
// pre-accepted by the VMM (added=true) or left to the guest to accept (unaccepted, added=false)
type ramEntry struct {
	address uint64
	length  uint64
	added   bool
}

// CreateTdHobHob reproduces the TD HOB that qemu (qemu-tdx hw/i386/tdvf-hob.c) hands
// to the guest firmware. The HOB layout is determined by the TDVF metadata sections of type
// TD_HOB and TEMP_MEM in the OVMF image and the guest e820 RAM map, which for a TDX q35 VM is two
// ranges derived from RAM size.
//
// This precomputes what OVMF MeasureHobList hashes: the handoff info table followed by the
// resource descriptors, but without EFI_END_OF_HOB_LIST.
func CreateTdHob(c *Config) ([]byte, error) {
	if c.Ovmf == "" {
		return nil, fmt.Errorf("ovmf must be specified to compute TD HOB")
	}

	ovmfData, err := os.ReadFile(c.Ovmf)
	if err != nil {
		return nil, fmt.Errorf("failed to read ovmf: %w", err)
	}

	sections, err := parseTdvfSections(ovmfData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TDVF metadata: %w", err)
	}

	tdHobBase, ok := findTdHobBase(sections)
	if !ok {
		return nil, fmt.Errorf("TDVF metadata does not contain a TD_HOB section")
	}

	entries, err := buildRamEntries(c.RamSize, sections)
	if err != nil {
		return nil, fmt.Errorf("failed to build RAM entries: %w", err)
	}

	hobBytes := EFI_HOB_GENERIC_HEADER_SIZE + EFI_HOB_RESOURCE_DESCRIPTOR_SIZE*len(entries)

	tbl := HobHandoffInfoTable{
		Header: HobHeader{
			HobType:   EFI_HOB_TYPE_HANDOFF,
			HobLength: uint16(binary.Size(HobHandoffInfoTable{})),
		},
		Version:  EFI_HOB_HANDOFF_TABLE_VERSION,
		BootMode: BOOT_WITH_FULL_CONFIGURATION,
		// EfiEndOfHobList points one past the END_OF_HOB_LIST marker.
		// The marker itself is not hashed.
		EfiEndOfHobList: tdHobBase + uint64(hobBytes) + EFI_HOB_END_OF_HOB_LIST_SIZE,
	}

	buffer := bytes.Buffer{}
	if err := binary.Write(&buffer, binary.LittleEndian, tbl); err != nil {
		return nil, fmt.Errorf("failed to write handoff table: %w", err)
	}

	for _, e := range entries {
		resType := uint32(EFI_RESOURCE_MEMORY_UNACCEPTED)
		if e.added {
			resType = EFI_RESOURCE_SYSTEM_MEMORY
		}
		rd := HobResourceDescriptor{
			Header: HobHeader{
				HobType:   EFI_HOB_TYPE_RESOURCE_DESCRIPTOR,
				HobLength: uint16(binary.Size(HobResourceDescriptor{})),
			},
			ResourceType: resType,
			ResourceAttribute: EFI_RESOURCE_ATTRIBUTE_PRESENT |
				EFI_RESOURCE_ATTRIBUTE_INITIALIZED |
				EFI_RESOURCE_ATTRIBUTE_TESTED,
			PhysicalStart:  e.address,
			ResourceLength: e.length,
		}
		if err := binary.Write(&buffer, binary.LittleEndian, rd); err != nil {
			return nil, fmt.Errorf("failed to write resource descriptor: %w", err)
		}
	}

	if buffer.Len() != hobBytes {
		return nil, fmt.Errorf("TB HOB size does not match expected size (expect: %d; is: %d)", hobBytes, buffer.Len())
	}
	return buffer.Bytes(), nil
}

func findTdHobBase(sections []TdxMetadataSection) (uint64, bool) {
	for _, s := range sections {
		if s.Type == TdxMetadataSectionTypeTdHob {
			return s.MemoryAddress, true
		}
	}
	return 0, false
}

// buildRamEntries reproduces qemu's tdx_init_ram_entries + tdx_accept_ram_range loop
func buildRamEntries(ramSize uint64, sections []TdxMetadataSection) ([]ramEntry, error) {
	entries := initialE820(ramSize)

	for _, s := range sections {
		if s.Type != TdxMetadataSectionTypeTdHob && s.Type != TdxMetadataSectionTypeTempMem {
			continue
		}
		var err error
		entries, err = acceptRamRange(entries, s.MemoryAddress, s.MemoryDataSize)
		if err != nil {
			return nil, fmt.Errorf("failed to accept section %#x+%#x: %w",
				s.MemoryAddress, s.MemoryDataSize, err)
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].address < entries[j].address
	})
	return entries, nil
}

// initialE820 mirrors qemu's pc_q35 RAM split: lowmem = 2 GiB whenever ram_size
// >= 2.75 GiB, else lowmem = ram_size and there is no above-4G range
func initialE820(ramSize uint64) []ramEntry {
	below, above := tcg.QemuQ35RamSplit(ramSize)

	entries := []ramEntry{{address: 0, length: below}}
	if above > 0 {
		entries = append(entries, ramEntry{
			address: tcg.QemuAbove4gMemStart,
			length:  above,
		})
	}
	return entries
}

// acceptRamRange mirrors tdx_accept_ram_range()
func acceptRamRange(entries []ramEntry, address, length uint64) ([]ramEntry, error) {
	for i := range entries {
		e := &entries[i]
		if address+length <= e.address || e.address+e.length <= address {
			continue
		}
		if e.address > address || e.address+e.length < address+length {
			return nil, fmt.Errorf("section %#x+%#x not fully contained in RAM entry %#x+%#x",
				address, length, e.address, e.length)
		}
		if e.added {
			return nil, fmt.Errorf("section %#x+%#x overlaps an already-accepted range", address, length)
		}

		origAddress := e.address
		origLength := e.length

		e.address = address
		e.length = length
		e.added = true

		if headLen := address - origAddress; headLen > 0 {
			entries = append(entries, ramEntry{address: origAddress, length: headLen})
		}
		if tailStart := address + length; tailStart < origAddress+origLength {
			entries = append(entries, ramEntry{
				address: tailStart,
				length:  origAddress + origLength - tailStart,
			})
		}
		return entries, nil
	}
	return nil, fmt.Errorf("section %#x+%#x does not fall within any RAM range", address, length)
}
