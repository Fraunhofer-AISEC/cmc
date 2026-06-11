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
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/ovmf"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/tcg"
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
	PageSize                              = 0x1000
	TdxMetadataSectionTypeBfv             = 0
	TdxMetadataSectionTypeTdvf            = 1
	TdxMetadataSectionTypeTdHob           = 2
	TdxMetadataSectionTypeTempMem         = 3
	TdxMetadataSectionTypeTdInfo          = 7
	TdxMetadataSignature                  = 0x46564454
	TdxMetadataVersion                    = 1
	TdxMetadataAttributesExtendMemPageAdd = 0x02
	TdxMetadataAttributesExtendMr         = 0x01
	TdvfDescriptorOffset                  = 0x20
	MrtdExtensionBufferSize               = 0x80
	MemPageAddGpaOffset                   = 0x10
	TdhMrExtendGranularity                = 0x100
)

var tdxMetadataGuid = []byte{
	0x35, 0x65, 0x7a, 0xe4, 0x4a, 0x98, 0x98, 0x47,
	0x86, 0x5e, 0x46, 0x85, 0xa7, 0xbf, 0x8e, 0xc2,
}

// PrecomputeMrtd calculates the TDX Build-Time Measurement Register (MRTD).
// The MRTD contains the digest of the OVMF as hashed by the Intel TDX module.
func PrecomputeMrtd(c *Config) (*ar.Component, []*ar.Component, error) {
	log.Debugf("Precomputing MRTD...")

	var mrtd []byte
	refvals := make([]*ar.Component, 0)

	if c.Ovmf != "" {
		data, err := os.ReadFile(c.Ovmf)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read ovmf: %w", err)
		}

		hash, err := MeasureOvmf(data, c.QemuVersion)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure ovmf: %w", err)
		}

		comp := &ar.Component{
			Type: ar.CycloneDxType(ar.TRUST_ANCHOR_TDX, tcg.INDEX_MRTD),
			Name: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
			Hashes: []ar.ReferenceHash{
				{
					Alg:     "SHA-384",
					Content: hash[:],
				},
			},
			Description: "MRTD: TDX Module Measurement: Initial TD contents (OVMF)",
		}
		comp.SetTrustAnchor(ar.TRUST_ANCHOR_TDX)
		comp.SetIndex(tcg.INDEX_MRTD)
		refvals = append(refvals, comp)
		mrtd = hash[:]
	} else if c.Mrtd != "" {
		hash, err := hex.DecodeString(c.Mrtd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode hash: %w", err)
		}
		if len(hash) != sha512.Size384 {
			return nil, nil, fmt.Errorf("malformed sha384 hash length: (is: %v, expected: %v)", len(hash), sha512.Size384)
		}

		comp := &ar.Component{
			Type: ar.CycloneDxType(ar.TRUST_ANCHOR_TDX, tcg.INDEX_MRTD),
			Name: "OVMF",
			Hashes: []ar.ReferenceHash{
				{
					Alg:     "SHA-384",
					Content: hash[:],
				},
			},
			Description: "MRTD: TDX Module Measurement: Initial TD contents (firmware)",
		}
		comp.SetTrustAnchor(ar.TRUST_ANCHOR_TDX)
		comp.SetIndex(tcg.INDEX_MRTD)
		refvals = append(refvals, comp)
		mrtd = hash[:]
	} else {
		return nil, nil, fmt.Errorf("ovmf or mrtd must be specified for MRTD")
	}

	// Create MRTD final reference value
	mrtdSummary := &ar.Component{
		Type:        ar.CycloneDxType(ar.TRUST_ANCHOR_TDX, tcg.INDEX_MRTD),
		Name:        "MRTD Summary",
		Description: "MRTD",
		Hashes: []ar.ReferenceHash{
			{
				Alg:     "SHA-384",
				Content: mrtd,
			},
		},
	}
	mrtdSummary.SetTrustAnchor(ar.TRUST_ANCHOR_TDX)
	mrtdSummary.SetIndex(tcg.INDEX_MRTD)

	return mrtdSummary, refvals, nil
}

func getOvmfMetadataOffset(ovmfData []byte) (uint64, error) {
	data, err := ovmf.FindGuidTableEntry(ovmfData, tdxMetadataGuid)
	if errors.Is(err, ovmf.ErrFooterGuidNotFound) {
		// TODO check if this is still needed
		return uint64(binary.LittleEndian.Uint32(ovmfData[len(ovmfData)-TdvfDescriptorOffset-16:])), nil
	}
	if err != nil {
		return 0, err
	}
	offset := binary.LittleEndian.Uint32(data)
	return uint64(len(ovmfData)) - uint64(offset) - 16, nil
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

func tdMemPageAdd(gpa uint64) []byte {
	buffer := [MrtdExtensionBufferSize]byte{}

	copy(buffer[:], "MEM.PAGE.ADD")

	// Copy the GPA in little-endian format
	binary.LittleEndian.PutUint64(buffer[MemPageAddGpaOffset:], gpa)

	return buffer[:]
}
func tdMrExtend(gpa uint64, data []byte) []byte {
	buffer := [MrtdExtensionBufferSize * 3]byte{}

	copy(buffer[0:], "MR.EXTEND")
	binary.LittleEndian.PutUint64(buffer[MemPageAddGpaOffset:], gpa)

	copy(buffer[MrtdExtensionBufferSize:], data)

	return buffer[:]
}

func MeasureOvmf(ovmf []byte, qemuVersion string) ([]byte, error) {
	metadataOffset, err := getOvmfMetadataOffset(ovmf)
	if err != nil {
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

	if binary.Size(descriptor)+int(descriptor.NumberOfSectionEntry)*binary.Size(TdxMetadataSection{}) != int(descriptor.Length) ||
		metadataOffset+uint64(descriptor.Length) > uint64(len(ovmf)) {
		return nil, fmt.Errorf("metadata sections malformed in ovmf")
	}

	digest := sha512.New384()

	for i := 0; i < int(descriptor.NumberOfSectionEntry); i++ {
		var section TdxMetadataSection
		binary.Read(reader, binary.LittleEndian, &section)

		if section.MemoryAddress%PageSize != 0 {
			return nil, fmt.Errorf("memory address must be 4K aligned")
		}
		if section.MemoryDataSize%PageSize != 0 {
			return nil, fmt.Errorf("memory data size must be 4K aligned")
		}
		if section.Type != TdxMetadataSectionTypeTdInfo && (section.MemoryAddress != 0 ||
			section.MemoryDataSize != 0) && section.MemoryDataSize < uint64(section.RawDataSize) {
			return nil, fmt.Errorf("memory data size must be greater or equal to raw data size")
		}
		if uint64(section.DataOffset)+uint64(section.RawDataSize) > uint64(len(ovmf)) {
			return nil, fmt.Errorf("data section calculation exceeds image size")
		}

		pageCount := section.MemoryDataSize / PageSize

		qemuMajor, err := getQemuVersionMajor(qemuVersion)
		if err != nil {
			return nil, fmt.Errorf("failed to get qemu version major: %w", err)
		}

		if qemuMajor < 9 {
			if (section.Attributes & TdxMetadataAttributesExtendMemPageAdd) == 0 {
				for i := 0; i < int(pageCount); i++ {
					buffer := tdMemPageAdd(section.MemoryAddress + uint64(i*PageSize))
					digest.Write(buffer)
				}
			}
			if (section.Attributes & TdxMetadataAttributesExtendMr) != 0 {
				for i := 0; i < int(pageCount); i++ {
					granularity := TdhMrExtendGranularity
					iteration := PageSize / TdhMrExtendGranularity

					for chunk := 0; chunk < iteration; chunk++ {
						dataOffset := int(section.DataOffset) + i*PageSize + chunk*granularity
						if dataOffset >= len(ovmf) || dataOffset+2*MrtdExtensionBufferSize > len(ovmf) {
							return nil, fmt.Errorf("failed to perform MR.EXTEND on section extending ovmf image size")
						}
						buffer := tdMrExtend(section.MemoryAddress+uint64(i*PageSize)+uint64(chunk*granularity), ovmf[dataOffset:])
						digest.Write(buffer)
					}
				}
			}
		} else { // QEMU v9 or higher
			for i := 0; i < int(pageCount); i++ {
				if (section.Attributes & TdxMetadataAttributesExtendMemPageAdd) == 0 {
					buffer := tdMemPageAdd(section.MemoryAddress + uint64(i*PageSize))
					digest.Write(buffer)
				}

				if (section.Attributes & TdxMetadataAttributesExtendMr) != 0 {
					granularity := TdhMrExtendGranularity
					iteration := PageSize / TdhMrExtendGranularity

					for chunk := 0; chunk < iteration; chunk++ {
						dataOffset := int(section.DataOffset) + i*PageSize + chunk*granularity
						if dataOffset >= len(ovmf) || dataOffset+2*MrtdExtensionBufferSize > len(ovmf) {
							return nil, fmt.Errorf("failed to perform MR.EXTEND on section extending ovmf image size")
						}
						buffer := tdMrExtend(section.MemoryAddress+uint64(i*PageSize)+uint64(chunk*granularity), ovmf[dataOffset:])
						digest.Write(buffer)
					}
				}
			}
		}
	}

	return digest.Sum(nil), nil
}

func measureCfv(ovmf []byte) ([]byte, error) {
	metadataOffset, err := getOvmfMetadataOffset(ovmf)
	if err != nil {
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

	if binary.Size(descriptor)+int(descriptor.NumberOfSectionEntry)*binary.Size(TdxMetadataSection{}) != int(descriptor.Length) ||
		metadataOffset+uint64(descriptor.Length) > uint64(len(ovmf)) {
		return nil, fmt.Errorf("metadata sections malformed in ovmf")
	}

	// only validates sections up to the type tdvf
	var digest [sha512.Size384]byte
	for i := 0; i < int(descriptor.NumberOfSectionEntry); i++ {
		var section TdxMetadataSection
		binary.Read(reader, binary.LittleEndian, &section)

		if section.MemoryAddress%PageSize != 0 {
			return nil, fmt.Errorf("memory address must be 4K aligned")
		}
		if section.MemoryDataSize%PageSize != 0 {
			return nil, fmt.Errorf("memory data size must be 4K aligned")
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

// parseTdvfSections locates and decodes the TDVF metadata embedded in an OVMF
// image, returning all section entries.
func parseTdvfSections(ovmfData []byte) ([]TdxMetadataSection, error) {
	metadataOffset, err := getOvmfMetadataOffset(ovmfData)
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata offset: %w", err)
	}

	// 16 byte offset for GUID
	metadataOffset += 16

	var descriptor TdxMetadataDescriptor
	if metadataOffset+uint64(binary.Size(descriptor)) > uint64(len(ovmfData)) {
		return nil, fmt.Errorf("descriptor malformed in ovmf")
	}
	reader := bytes.NewReader(ovmfData[metadataOffset:])
	if err := binary.Read(reader, binary.LittleEndian, &descriptor); err != nil {
		return nil, fmt.Errorf("failed to read descriptor: %w", err)
	}
	if err := isValidDescriptor(&descriptor); err != nil {
		return nil, fmt.Errorf("descriptor is not valid: %w", err)
	}

	if binary.Size(descriptor)+int(descriptor.NumberOfSectionEntry)*binary.Size(TdxMetadataSection{}) != int(descriptor.Length) ||
		metadataOffset+uint64(descriptor.Length) > uint64(len(ovmfData)) {
		return nil, fmt.Errorf("metadata sections malformed in ovmf")
	}

	sections := make([]TdxMetadataSection, descriptor.NumberOfSectionEntry)
	for i := range sections {
		if err := binary.Read(reader, binary.LittleEndian, &sections[i]); err != nil {
			return nil, fmt.Errorf("failed to read section %d: %w", i, err)
		}
	}
	return sections, nil
}

func getQemuVersionMajor(version string) (int, error) {
	split := strings.Split(version, ".")
	if len(split) == 0 {
		return 0, fmt.Errorf("malformatted string %v", version)
	}
	major, err := strconv.Atoi(split[0])
	if err != nil {
		return 0, fmt.Errorf("failed to convert: %w", err)
	}
	return major, nil
}
