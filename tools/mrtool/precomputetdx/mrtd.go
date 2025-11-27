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
	"crypto/sha512"
	"encoding/binary"
	"fmt"
)

type TdxMetadataDescriptor struct {
	Signature            uint32
	Length               uint32
	Version              uint32
	NumberOfSectionEntry uint32
}

type TdxMetadataSection struct {
	DataOffset     uint32
	RawDataSize    uint32
	MemoryAddress  uint64
	MemoryDataSize uint64
	Type           uint32
	Attributes     uint32
}

const (
	PageSize                   = 0x1000
	TdxMetadataSectionTypeTdvf = 1
	TdxMetadataSignature       = 0x46564454
	TdxMetadataVersion         = 1
	TdvfDescriptorOffset       = 0x20
	OvmfTableFooterGuidOffset  = 0x30
)

func getOvmfMetadataOffset(ovmf []byte) (uint64, error) {
	// 16 bytes for GUID
	if OvmfTableFooterGuidOffset > len(ovmf) || OvmfTableFooterGuidOffset < 16 {
		return 0, fmt.Errorf("invalid ovmf offset")
	}

	tableFooterOffset := len(ovmf) - OvmfTableFooterGuidOffset
	footerGuid := ovmf[tableFooterOffset : tableFooterOffset+16]

	// OVMF_TABLE_FOOTER_GUID
	if !bytes.Equal(footerGuid, []byte{0xde, 0x82, 0xb5, 0x96, 0xb2, 0x1f, 0xf7, 0x45, 0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d}) {
		return uint64(binary.LittleEndian.Uint32(ovmf[len(ovmf)-TdvfDescriptorOffset-16:])), nil
	}

	// Footer GUID matches
	ovmfTableOffset := tableFooterOffset - binary.Size(uint16(0)) - 16
	ovmfTableLength := int(binary.LittleEndian.Uint16(ovmf[ovmfTableOffset:])) - binary.Size(uint16(0))

	for count := 0; count < ovmfTableLength; {
		tableGuid := ovmf[ovmfTableOffset : ovmfTableOffset+16]
		length := int(binary.LittleEndian.Uint16(ovmf[ovmfTableOffset-binary.Size(uint16(0)):]))

		// OVMF_TABLE_TDX_METADATA_GUID
		if !bytes.Equal(tableGuid, []byte{0x35, 0x65, 0x7a, 0xe4, 0x4a, 0x98, 0x98, 0x47, 0x86, 0x5e, 0x46, 0x85, 0xa7, 0xbf, 0x8e, 0xc2}) {
			ovmfTableOffset -= length
			count += length
		}

		return uint64(len(ovmf) - int(binary.LittleEndian.Uint32(ovmf[ovmfTableOffset-binary.Size(uint16(0))-binary.Size(uint32(0)):])) - 16), nil
	}
	return 0, nil
}
func isValidDescriptor(descriptor *TdxMetadataDescriptor) error {
	if descriptor.Signature != TdxMetadataSignature {
		return fmt.Errorf("invalid signature: %x (expected %x)", descriptor.Signature, TdxMetadataSignature)
	}
	if descriptor.Version != TdxMetadataVersion {
		return fmt.Errorf("invalid version: %x (expected %x)", descriptor.Version, TdxMetadataVersion)
	}
	if descriptor.NumberOfSectionEntry == 0 {
		return fmt.Errorf("number of section entries is zero")
	}
	return nil
}

func MeasureCfv(ovmf []byte) ([]byte, error) {
	metadataOffset, err := getOvmfMetadataOffset(ovmf)
	if err != nil {
		fmt.Println("")
		return nil, fmt.Errorf("failed to get metadata offset: %w", err)
	}

	// 16 byte offset for GUID
	metadataOffset += 16

	var descriptor TdxMetadataDescriptor
	if metadataOffset+uint64(binary.Size(descriptor)) > uint64(len(ovmf)) {
		return nil, fmt.Errorf("descriptor malformed in ovmf")
	}
	reader := bytes.NewReader(ovmf[metadataOffset:])
	binary.Read(reader, binary.LittleEndian, &descriptor)
	if err = isValidDescriptor(&descriptor); err != nil {
		return nil, fmt.Errorf("descriptor is not valid: %w", err)
	}

	if binary.Size(descriptor)+int(descriptor.NumberOfSectionEntry)*binary.Size(TdxMetadataSection{}) != int(descriptor.Length) || metadataOffset+uint64(descriptor.Length) > uint64(len(ovmf)) {
		return nil, fmt.Errorf("metadata sections malformed in ovmf")
	}

	// only validates sections up to the type tdvf, rest is not validated, as per the c implementation
	var digest [sha512.Size384]byte
	for i := 0; i < int(descriptor.NumberOfSectionEntry); i++ {
		var section TdxMetadataSection
		binary.Read(reader, binary.LittleEndian, &section)

		if section.MemoryAddress%PageSize != 0 {
			return nil, fmt.Errorf("memory address must be 4K aligned!")
		}
		if section.MemoryDataSize%PageSize != 0 {
			return nil, fmt.Errorf("memory data size must be 4K aligned!")
		}
		if uint64(section.DataOffset)+uint64(section.RawDataSize) > uint64(len(ovmf)) {
			return nil, fmt.Errorf("data section calculation exceeds image size")
		}
		if section.Type != TdxMetadataSectionTypeTdvf {
			continue
		}

		digest = sha512.Sum384(ovmf[section.DataOffset : section.DataOffset+section.RawDataSize])
		break
	}

	return digest[:], nil
}
