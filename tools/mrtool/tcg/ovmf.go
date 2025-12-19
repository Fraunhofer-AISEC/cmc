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

package tcg

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/ulikunitz/xz/lzma"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

type EfiFvgAttributes2 uint32

type EfiFvBlockMapEntry struct {
	NumBlocks uint32 // Number of sequential blocks of the same size
	Length    uint32 // Size of the blocks
}

// EFI_FIRMWARE_VOLUME_HEADER without the run-length encoded block map, []EfiFvBlockMapEntry,
// which ends with a {0,0} block and must be dynamically parsed
type EfiFirmwareVolumeHeader struct {
	ZeroVector      [16]byte          // Reserved for processor reset vector
	FileSystemGuid  EfiGuid           // GUID of the firmware file system
	FvLength        uint64            // Length of the complete firmware volume
	Signature       uint32            // Set to EFI_FVH_SIGNATURE
	Attributes      EfiFvgAttributes2 // Capabilities and power-on defaults
	HeaderLength    uint16            // Length of the firmware volume header
	Checksum        uint16            // 16-bit checksum of the header
	ExtHeaderOffset uint16            // Offset of extended header, 0 if none
	Reserved        [1]byte           // Must be zero
	Revision        uint8             // Version, set to 2
}

type EfiCommonSectionHeader struct {
	Size [3]byte
	Type uint8
}

type EfiGuidDefinedSection struct {
	CommonHeader          EfiCommonSectionHeader
	SectionDefinitionGuid EfiGuid
	DataOffset            uint16
	Attributes            uint16
}

type EfiFfsFileHeader struct {
	Name           EfiGuid
	IntegrityCheck uint16
	Type           uint8
	Attributes     uint8
	Size           [3]byte
	State          uint8
}

const (
	EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE = 0x0B
	EFI_SECTION_COMPRESSION               = 0x01
	EFI_SECTION_GUID_DEFINED              = 0x02
	EFI_SECTION_FIRMWARE_VOLUME_IMAGE     = 0x17
	EFI_SECTION_RAW                       = 0x19
)

var (
	EFI_FVH_SIGNATURE = []byte("_FVH")
)

func MeasureOvmf(alg crypto.Hash, ta TrustAnchor, digest []byte,
	refvals []*ar.ReferenceValue, index int, ovmfPath string,
) ([]byte, []*ar.ReferenceValue, error) {

	ovmf, err := os.ReadFile(ovmfPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read ovmf file: %w", err)
	}

	log.Debugf("VarStore start: %x", 0)

	// OVMF Layout: Variable Store | FVMAIN_COMPACT | SECFV
	var VarStoreHdr EfiFirmwareVolumeHeader
	err = binary.Read(bytes.NewReader(ovmf), binary.LittleEndian, &VarStoreHdr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse variable store header: %w", err)
	}
	log.Debugf("VarStore length: %x", VarStoreHdr.FvLength)

	fvMainStart := VarStoreHdr.FvLength

	if fvMainStart > uint64(len(ovmf)) {
		return nil, nil, fmt.Errorf("parsed FVMAIN start (%d) exceeds OVMF (%d)",
			fvMainStart, len(ovmf))
	}
	log.Debugf("FVMAIN start: %x", fvMainStart)

	fvmain, err := extractFvMain(ovmf[fvMainStart:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract FVMAIN: %w", err)
	}
	log.Debugf("Read fvmain size 0x%x", len(fvmain))

	// Measure PEIFV
	peiOffset, err := FindFfsSectionInSectionsOffset(fvmain, EFI_SECTION_FIRMWARE_VOLUME_IMAGE)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find PEIFV: %w", err)
	}

	// EFI_FIRMWARE_VOLUME_HEADER follows EFI_COMMON_SECTION_HEADER (size 4)
	peiOffset += 4
	log.Debugf("Found PEIFV offset 0x%x", peiOffset)

	var PeiHdr EfiFirmwareVolumeHeader
	err = binary.Read(bytes.NewReader(fvmain[peiOffset:]), binary.LittleEndian,
		&PeiHdr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse PEI header: %w", err)
	}
	log.Debugf("PEIFV length: 0x%x", PeiHdr.FvLength)

	var rv *ar.ReferenceValue
	rv, digest, err = CreateExtendRefval(alg, ta, index, digest, fvmain[peiOffset:peiOffset+PeiHdr.FvLength],
		"EV_EFI_PLATFORM_FIRMWARE_BLOB", "OVMF UEFI PEI Firmware Volume")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create refval: %w", err)
	}
	refvals = append(refvals, rv)

	// Measure DXEFV
	dxeOffset, err := FindFfsSectionInSectionsOffset(fvmain[uint64(peiOffset)+PeiHdr.FvLength:], EFI_SECTION_FIRMWARE_VOLUME_IMAGE)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find DXE: %w", err)
	}

	// DXEFV EFI_FIRMWARE_VOLUME_HEADER follows PEIFV and own EFI_COMMON_SECTION_HEADER (size 4)
	dxeOffset += peiOffset + PeiHdr.FvLength + 4
	log.Debugf("Found DXE offset 0x%x", dxeOffset)

	var DxeHdr EfiFirmwareVolumeHeader
	err = binary.Read(bytes.NewReader(fvmain[dxeOffset:]), binary.LittleEndian,
		&DxeHdr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse DXE header: %w", err)
	}
	log.Debugf("DXE length: 0x%x", DxeHdr.FvLength)

	var rv2 *ar.ReferenceValue
	rv2, digest, err = CreateExtendRefval(alg, ta, index, digest,
		fvmain[dxeOffset:uint64(dxeOffset)+DxeHdr.FvLength],
		"EV_EFI_PLATFORM_FIRMWARE_BLOB", "OVMF UEFI DXE Firmware Volume")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create refval: %w", err)
	}
	refvals = append(refvals, rv2)

	return digest, refvals, nil
}

func extractFvMain(buf []byte) ([]byte, error) {

	FvMainHdr := new(EfiFirmwareVolumeHeader)
	err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, FvMainHdr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse FVMAIN header: %w", err)
	}
	log.Debugf("FVMAIN length: %x", FvMainHdr.FvLength)

	offset, err := findFfsFileAndSectionOffset(buf, FvMainHdr, EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE, EFI_SECTION_GUID_DEFINED)
	if err != nil {
		return nil, fmt.Errorf("GUID defined section not found: %w", err)
	}

	var section EfiGuidDefinedSection
	err = binary.Read(bytes.NewReader(buf[offset:]), binary.LittleEndian, &section)
	if err != nil {
		return nil, fmt.Errorf("failed to parse section header: %w", err)
	}

	size := uint32(section.CommonHeader.Size[0]) |
		uint32(section.CommonHeader.Size[1])<<8 |
		uint32(section.CommonHeader.Size[2])<<16

	log.Debugf("Section DataOffset: %d (0x%x)", section.DataOffset, section.DataOffset)
	log.Debugf("Section Type: 0x%x", section.CommonHeader.Type)
	log.Debugf("Section Size: %d (0x%x)", size, size)

	if !GuidsEqual(&section.SectionDefinitionGuid, &LzmaDecompressGuid) {
		return nil, fmt.Errorf("GUID (%v) does not match LZMA decompress GUID (%v)",
			section.SectionDefinitionGuid.String(), LzmaDecompressGuid.String())
	}

	dataOffset := uint32(offset) + uint32(section.DataOffset)

	// Extract LZMA-compressed FVMAIN
	r, err := lzma.NewReader(bytes.NewReader(buf[dataOffset : dataOffset+size]))
	if err != nil {
		return nil, fmt.Errorf("failed to decompress FVMAIN: %w", err)
	}

	fvmain, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read FVMAIN: %w", err)
	}

	return fvmain, nil
}

func findFfsFileAndSectionOffset(buf []byte, fv *EfiFirmwareVolumeHeader, fileType, sectionType uint8) (uint64, error) {
	currAddress := uint64(0)
	endOfFv := fv.FvLength

	log.Debugf("Current address 0x%x", currAddress)
	log.Debugf("EndOfFirmwareVolume: 0x%x", endOfFv)

	sig := make([]byte, 4)
	binary.LittleEndian.PutUint32(sig, fv.Signature)
	if !bytes.Equal(sig, EFI_FVH_SIGNATURE) {
		return 0, fmt.Errorf("unexpected signature %x (expected %x)", sig, EFI_FVH_SIGNATURE)
	}
	log.Debugf("Found FVH header signature")

	log.Debugf("Looping through the FFS files...")

	endOfFile := currAddress + uint64(fv.HeaderLength)
	for {
		currAddress := endOfFile
		log.Debugf("\tCurrent address 0x%x", currAddress)

		// Align to 8-byte boundary
		if rem := currAddress % 8; rem != 0 {
			currAddress += 8 - rem
		}
		if currAddress >= endOfFv {
			return 0, fmt.Errorf("address (0x%x) exceeds end of FV (0x%x)", currAddress, endOfFv)
		}
		log.Debugf("\tCurrent address aligned 0x%x", currAddress)

		var file EfiFfsFileHeader
		r := bytes.NewReader(buf[currAddress:])
		err := binary.Read(r, binary.LittleEndian, &file)
		if err != nil {
			return 0, fmt.Errorf("failed to read EFI FFS file header: %w", err)
		}

		// Compute file size
		fileSize := uint64(file.Size[0]) | uint64(file.Size[1])<<8 | uint64(file.Size[2])<<16
		if fileSize < 24 {
			return 0, fmt.Errorf("invalid FFS file size")
		}
		log.Debugf("\tSize: 0x%x", fileSize)

		endOfFile = currAddress + fileSize

		// Check file type
		if file.Type != fileType {
			continue
		}
		log.Debugf("Found file type 0x%x", fileType)

		// Search sections in the file
		remaining := uint64(len(buf) - r.Len())
		sections := buf[remaining:]
		offset, err := FindFfsSectionInSectionsOffset(sections, sectionType)
		if err == nil {
			log.Debugf("FOUND FFS Section at offset 0x%x", remaining+offset)
			return remaining + offset, nil
		} else {
			return 0, fmt.Errorf("failed to find FFD section: %w", err)
		}

	}
}

func FindFfsSectionInSectionsOffset(sections []byte, sectionType uint8) (uint64, error) {
	offset := uint64(0)
	end := uint64(len(sections))

	log.Debugf("Looping through FFS file sections within FFS file")
	for {
		if offset >= end {
			break
		}

		// Align to 4-byte boundary
		if rem := offset % 4; rem != 0 {
			offset += 4 - rem
		}
		if offset >= end {
			return 0, fmt.Errorf("volume corrupted")
		}

		if offset+4 > end {
			return 0, fmt.Errorf("volume corrupted")
		}

		// Read the section header from the slice
		var section EfiCommonSectionHeader
		reader := bytes.NewReader(sections[offset : offset+4])
		if err := binary.Read(reader, binary.LittleEndian, &section); err != nil {
			return 0, fmt.Errorf("failed to read section header: %w", err)
		}

		// Compute section size
		size := uint64(EfiSectionHeaderSize(&section))
		if size < 4 {
			return 0, fmt.Errorf("volume corrupted")
		}
		log.Debugf("\tSize: 0x%x", size)

		endOfSection := offset + size
		if endOfSection > end {
			return 0, fmt.Errorf("volume corrupted")
		}
		log.Debugf("\tEndOfSection: 0x%x", endOfSection)

		if section.Type == sectionType {
			log.Debugf("Found section type 0x%x", sectionType)
			return offset, nil
		}

		offset = endOfSection
		log.Debugf("New offset: 0x%x", offset)
	}

	return 0, fmt.Errorf("section not found")
}

func EfiSectionHeaderSize(s *EfiCommonSectionHeader) int {
	return int(s.Size[0]) | int(s.Size[1])<<8 | int(s.Size[2])<<16
}
