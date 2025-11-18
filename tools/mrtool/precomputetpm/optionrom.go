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
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	MAX_ADDRESS = 0xFFFFFFFFFFFFFFFF
	BIT8        = 0x00000100
	BITBUFSIZE  = 32
	MAXMATCH    = 256
	THRESHOLD   = 3
	CODE_BIT    = 16
	BAD_TABLE   = uint16(0xffff)
	NC          = (0xff + MAXMATCH + 2 - THRESHOLD)
	CBIT        = 9
	MAXPBIT     = 5
	TBIT        = 5
	MAXNP       = ((1 << MAXPBIT) - 1)
	NT          = (CODE_BIT + 3)
)

const (
	// NPT = NT if NT > MAXNP else NPT = MAXNP
	NPT = MAXNP
)

const (
	PCI_CODE_TYPE_EFI_IMAGE                 = 0x03
	EFI_PCI_EXPANSION_ROM_HEADER_COMPRESSED = 0x0001
	INDICATOR_LAST                          = uint8(0x80)
)

type ScratchData struct {
	SrcBase      []uint8
	DstBase      []uint8
	OutBuf       uint32
	InBuf        uint32
	BitCount     uint16
	BitBuf       uint32
	SubBitBuf    uint32
	BlockSize    uint16
	CompSize     uint32
	OrigSize     uint32
	BadTableFlag uint16
	Left         [2*NC - 1]uint16
	Right        [2*NC - 1]uint16
	CLen         [NC]uint8
	PTLen        [NPT]uint8
	CTable       [4096]uint16
	PTTable      [256]uint16
	PBit         uint8
}

type PciExpansionRomHdr struct {
	Signature  uint16 // 0xAA55
	Reserved   [0x16]uint8
	PcirOffset uint16
}

type EfiPciExpansionRomHdr struct {
	Signature            uint16 // 0xAA55
	InitializationSize   uint16
	EfiSignature         uint32 // 0x0EF1
	EfiSubsystem         uint16
	EfiMachineType       uint16
	CompressionType      uint16
	Reserved             [8]uint8
	EfiImageHeaderOffset uint16
	PcirOffset           uint16
}

type PciDataStructure struct {
	Signature    uint32 // "PCIR"
	VendorId     uint16
	DeviceId     uint16
	Reserved0    uint16
	Length       uint16
	Revision     uint8
	ClassCode    [3]uint8
	ImageLength  uint16
	CodeRevision uint16
	CodeType     uint8
	Indicator    uint8
	Reserved1    uint16
}

type Pci30DataStruct struct {
	Signature                     uint32 // "PCIR"
	VendorId                      uint16
	DeviceId                      uint16
	DeviceListOffset              uint16
	Length                        uint16
	Revision                      uint8
	ClassCode                     [3]uint8
	ImageLength                   uint16
	CodeRevision                  uint16
	CodeType                      uint8
	Indicator                     uint8
	MaxRuntimeImageLength         uint16
	ConfigUtilityCodeHeaderOffset uint16
	DMTFCLPEntryPointOffset       uint16
}

func ExtractPeImage(driver string) ([]byte, error) {

	data, err := os.ReadFile(driver)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var romStart uint32 = 0

	// Search for compressed ROMs
	if romStart, err = GetEfiCompressedROM(driver, 0); err != nil {
		if romStart, err = GetEfiCompressedROM(driver, 1); err != nil {
			log.Debug("File is not a compressed ROM file, trying to decompress directly")
		}
	}

	// Extract ROM if start offset was found
	if romStart > 0 {
		if int(romStart) > len(data) {
			return nil, fmt.Errorf("ROM start (%v) beyond input data size (%v)", romStart, len(data))
		}
		romBuf := make([]byte, len(data)-int(romStart))
		copy(romBuf, data[romStart:])
		data = romBuf
	}

	// Get decompression info
	outSize, err := UefiDecompressGetInfo(data)
	if err != nil {
		return nil, fmt.Errorf("failed to get EFI decompression info")
	}

	log.Debugf("Input size: %v, Output size: %v", len(data), outSize)

	outBuf := make([]byte, outSize)

	if err := UefiDecompress(data, outBuf); err != nil {
		return nil, fmt.Errorf("failed to decompress: %w", err)
	}

	return outBuf[:outSize], nil
}

func GetEfiCompressedROM(in string, pci23 uint8) (uint32, error) {

	f, err := os.Open(in)
	if err != nil {
		return 0, fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	imageCount := 0
	for {

		pos, err := f.Seek(0, io.SeekCurrent)
		if err != nil {
			return 0, fmt.Errorf("failed to get file position: %w", err)
		}
		imageStart := uint32(pos)
		imageCount++

		var pciRomHdr PciExpansionRomHdr
		if err := binary.Read(f, binary.LittleEndian, &pciRomHdr); err != nil {
			return 0, fmt.Errorf("failed to read PCI ROM header: %w", err)
		}

		if _, err := f.Seek(int64(imageStart)+int64(pciRomHdr.PcirOffset), io.SeekStart); err != nil {
			return 0, fmt.Errorf("failed to seek to PCI data structure: %w", err)
		}

		pciDs23 := PciDataStructure{}
		pciDs30 := Pci30DataStruct{}

		if pci23 == 1 {
			if err := binary.Read(f, binary.LittleEndian, &pciDs23); err != nil {
				return 0, fmt.Errorf("failed to read PCI data structure: %w", err)
			}
		} else {
			if err := binary.Read(f, binary.LittleEndian, &pciDs30); err != nil {
				return 0, fmt.Errorf("failed to read PCI data structure: %w", err)
			}
		}

		codeIsEFI := false
		if pci23 == 1 {
			codeIsEFI = (pciDs23.CodeType == PCI_CODE_TYPE_EFI_IMAGE)
		} else {
			codeIsEFI = (pciDs30.CodeType == PCI_CODE_TYPE_EFI_IMAGE)
		}

		if codeIsEFI {
			if _, err := f.Seek(int64(imageStart), io.SeekStart); err != nil {
				return 0, fmt.Errorf("failed to re-seek to ROM header structure: %w", err)
			}

			var efiRomHdr EfiPciExpansionRomHdr
			if err := binary.Read(f, binary.LittleEndian, &efiRomHdr); err != nil {
				return 0, fmt.Errorf("failed to read EFI PCI ROM header from file: %w", err)
			}

			if efiRomHdr.CompressionType == EFI_PCI_EXPANSION_ROM_HEADER_COMPRESSED {
				efiStart := imageStart + uint32(efiRomHdr.EfiImageHeaderOffset)
				log.Debugf("Found compressed EFI ROM at %x", efiStart)
				return efiStart, nil
			}

			return 0, fmt.Errorf("found non-compressed EFI ROM at %x",
				imageStart+uint32(efiRomHdr.EfiImageHeaderOffset))
		}

		lastInd := INDICATOR_LAST
		if (pci23 == 1 && pciDs23.Indicator == lastInd) || (pci23 == 0 && pciDs30.Indicator == lastInd) {
			break
		}

		if pci23 == 1 {
			nextOffset := imageStart + (uint32(pciDs23.ImageLength) * 512)
			if _, err := f.Seek(int64(nextOffset), io.SeekStart); err != nil {
				return 0, fmt.Errorf("failed to seek to next image: %w", err)
			}
		} else {
			nextOffset := imageStart + (uint32(pciDs30.ImageLength) * 512)
			if _, err := f.Seek(int64(nextOffset), io.SeekStart); err != nil {
				return 0, fmt.Errorf("failed to seek to next image: %w", err)
			}
		}
	}

	return 0, fmt.Errorf("failed to find compressed EFI ROM")
}

func UefiDecompress(src []byte, dst []byte) error {

	log.Debugf("Performing UEFI Decompress")

	if src == nil || dst == nil {
		return fmt.Errorf("invalid parameter: nil slice")
	}
	if len(src) < 8 {
		return fmt.Errorf("source too short")
	}

	compSize := binary.LittleEndian.Uint32(src[0:4])
	origSize := binary.LittleEndian.Uint32(src[4:8])

	if origSize == 0 {
		return nil
	}

	sd := ScratchData{
		PBit:     4,
		SrcBase:  src[8:],
		DstBase:  dst,
		CompSize: compSize,
		OrigSize: origSize,
	}

	FillBuf(&sd, BITBUFSIZE)

	Decode(&sd)

	if sd.BadTableFlag != 0 {
		return fmt.Errorf("decompression failed: bad table")
	}

	return nil
}

func UefiDecompressGetInfo(source []byte) (uint32, error) {

	if source == nil {
		return 0, fmt.Errorf("source is nil")
	}
	if len(source) < 8 {
		return 0, fmt.Errorf("invalid parameter: sourceSize < 8")
	}

	compressedSize := binary.LittleEndian.Uint32(source[0:4])

	if len(source) < int(compressedSize+8) {
		return 0, fmt.Errorf("invalid parameter: sourceSize < compressedSize + 8")
	}

	destSize := binary.LittleEndian.Uint32(source[4:8])

	return destSize, nil
}

func Decode(sd *ScratchData) {

	for {
		charC := DecodeC(sd)
		if sd.BadTableFlag != 0 {
			break
		}

		if charC < 256 {
			if sd.OutBuf >= sd.OrigSize {
				break
			}
			sd.DstBase[sd.OutBuf] = uint8(charC)
			sd.OutBuf++
		} else {
			charC = charC - (BIT8 - THRESHOLD)
			bytesRemain := int16(charC)
			dataIdx := int(sd.OutBuf) - int(DecodeP(sd)) - 1

			bytesRemain--
			for bytesRemain >= 0 {
				sd.DstBase[sd.OutBuf] = sd.DstBase[uint32(dataIdx)]
				sd.OutBuf++
				dataIdx++
				if sd.OutBuf >= sd.OrigSize {
					break
				}
				bytesRemain--
			}
		}
	}
}

func DecodeC(sd *ScratchData) uint16 {

	if sd.BlockSize == 0 {
		sd.BlockSize = uint16(GetBits(sd, 16))

		sd.BadTableFlag = ReadPTLen(sd, NT, TBIT, 3)
		if sd.BadTableFlag != 0 {
			return 0
		}

		ReadCLen(sd)

		sd.BadTableFlag = ReadPTLen(sd, MAXNP, uint16(sd.PBit), uint16(0xFFFF))
		if sd.BadTableFlag != 0 {
			return 0
		}
	}

	sd.BlockSize--

	index := sd.CTable[int(sd.BitBuf>>(BITBUFSIZE-12))]

	if int(index) >= int(NC) {
		mask := uint32(1) << (BITBUFSIZE - 1 - 12)

		for int(index) >= int(NC) {
			if (sd.BitBuf & mask) != 0 {
				index = sd.Right[index]
			} else {
				index = sd.Left[index]
			}
			mask >>= 1
		}
	}

	FillBuf(sd, uint16(sd.CLen[index]))

	return index
}

func ReadCLen(sd *ScratchData) {
	var charC uint16
	number := GetBits(sd, CBIT)

	if number == 0 {
		charC = uint16(GetBits(sd, CBIT))

		for i := range sd.CLen {
			sd.CLen[i] = 0
		}
		for i := range sd.CTable {
			sd.CTable[i] = charC
		}
		return
	}

	index := 0
	for index < int(number) && index < int(NC) {
		charC = sd.PTTable[sd.BitBuf>>(BITBUFSIZE-8)]
		if charC >= NT {
			mask := uint32(1) << (BITBUFSIZE - 1 - 8)
			for charC >= NT {
				if (sd.BitBuf & mask) != 0 {
					charC = sd.Right[charC]
				} else {
					charC = sd.Left[charC]
				}
				mask >>= 1
			}
		}

		FillBuf(sd, uint16(sd.PTLen[charC]))

		if charC <= 2 {
			switch charC {
			case 0:
				charC = 1
			case 1:
				charC = uint16(GetBits(sd, 4) + 3)
			case 2:
				charC = uint16(GetBits(sd, CBIT) + 20)
			}

			for ; charC > 0 && index < int(NC); charC-- {
				sd.CLen[index] = 0
				index++
			}
		} else {
			sd.CLen[index] = uint8(charC - 2)
			index++
		}
	}

	for i := index; i < int(NC); i++ {
		sd.CLen[i] = 0
	}

	MakeTable(sd, uint16(NC), sd.CLen[:], 12, sd.CTable[:])
}

func ReadPTLen(sd *ScratchData, nn uint16, nbit uint16, special uint16) uint16 {
	var charC uint16

	number := uint16(GetBits(sd, nbit))

	if number == 0 {
		charC = uint16(GetBits(sd, nbit))

		for i := range sd.PTTable {
			sd.PTTable[i] = charC
		}
		limit := int(nn)
		if limit > len(sd.PTLen) {
			limit = len(sd.PTLen)
		}
		for i := 0; i < limit; i++ {
			sd.PTLen[i] = 0
		}
		return 0
	}

	index := uint16(0)

	for index < number && index < NPT {
		charC = uint16(sd.BitBuf >> (BITBUFSIZE - 3))

		if charC == 7 {
			Mask := uint32(1) << (BITBUFSIZE - 1 - 3)
			for (Mask & sd.BitBuf) != 0 {
				Mask >>= 1
				charC++
			}
		}

		if charC < 7 {
			FillBuf(sd, 3)
		} else {
			FillBuf(sd, charC-3)
		}

		sd.PTLen[index] = uint8(charC)
		index++

		if index == special {
			twoBits := GetBits(sd, 2)
			for twoBits > 0 && index < NPT {
				sd.PTLen[index] = 0
				index++
				twoBits--
			}
		}
	}

	for index < nn && index < NPT {
		sd.PTLen[index] = 0
		index++
	}

	return MakeTable(sd, nn, sd.PTLen[:], 8, sd.PTTable[:])
}

func DecodeP(sd *ScratchData) uint32 {
	val := sd.PTTable[sd.BitBuf>>(BITBUFSIZE-8)]

	if val >= MAXNP {
		mask := uint32(1) << (BITBUFSIZE - 1 - 8)
		for val >= MAXNP {
			if (sd.BitBuf & mask) != 0 {
				val = sd.Right[int(val)]
			} else {
				val = sd.Left[int(val)]
			}
			mask >>= 1
		}
	}

	FillBuf(sd, uint16(sd.PTLen[val]))

	pos := uint32(val)
	if val > 1 {
		pos = (uint32(1) << (int(val) - 1)) + uint32(GetBits(sd, val-1))
	}

	return pos
}

func MakeTable(sd *ScratchData, numOfChar uint16, bitLen []uint8, tableBits uint16, table []uint16) uint16 {
	var count [17]uint16
	var weight [17]uint16
	var start [18]uint16

	if tableBits > 16 {
		return BAD_TABLE
	}

	for i := 0; i <= 16; i++ {
		count[i] = 0
	}

	for i := 0; i < int(numOfChar); i++ {
		if int(i) >= len(bitLen) {
			log.Warnf("Index (%v) exceeds length of BitLen (%v)", i, len(bitLen))
			return BAD_TABLE
		}
		if int(bitLen[i]) >= len(count) {
			log.Warnf("BitLen at Index %v (%v) exceeds length of Count (%v)", i, bitLen[i], len(count))
			return BAD_TABLE
		}
		count[bitLen[i]]++
	}

	start[0] = 0
	start[1] = 0

	for i := 1; i <= 16; i++ {
		start[i+1] = start[i] + (count[i] << (16 - i))
	}

	if start[17] != 0 {
		return BAD_TABLE
	}

	juBits := uint16(16) - tableBits

	weight[0] = 0
	for i := uint16(1); i <= tableBits; i++ {
		start[i] >>= juBits
		weight[i] = uint16(1) << (tableBits - i)
	}
	for i := tableBits + 1; i <= 16; i++ {
		weight[i] = uint16(1) << (16 - i)
	}

	index := uint16(start[tableBits+1] >> juBits)
	index2 := uint16(0)

	if index != 0 {
		index2 = uint16(1) << tableBits
		if index < index2 {
			for i := int(index); i < int(index2); i++ {
				if i < len(table) {
					table[i] = 0
				}
			}
		}
	}

	avail := numOfChar
	mask := uint16(1) << (15 - tableBits)

	for char := uint16(0); char < numOfChar; char++ {
		length := uint16(bitLen[char])
		if length == 0 || length >= 17 {
			continue
		}

		nextCode := start[length] + weight[length]

		if length <= tableBits {
			for i := start[length]; i < nextCode; i++ {
				if i < uint16(len(table)) {
					table[i] = char
				}
			}
		} else {
			index2 = start[length]
			p := &table[int(index2>>juBits)]
			index := length - tableBits

			for index != 0 {
				if *p == 0 && avail < (2*NC-1) {
					sd.Right[avail] = 0
					sd.Left[avail] = 0
					*p = avail
					avail++
				}

				if *p < (2*NC - 1) {
					if (index2 & mask) != 0 {
						p = &sd.Right[int(*p)]
					} else {
						p = &sd.Left[int(*p)]
					}
				}

				index2 <<= 1
				index--
			}

			*p = char
		}

		start[length] = nextCode
	}

	return 0
}

func GetBits(sd *ScratchData, numOfBits uint16) uint32 {
	shift := uint(BITBUFSIZE) - uint(numOfBits)
	outBits := sd.BitBuf >> shift
	FillBuf(sd, numOfBits)
	return uint32(outBits)
}

func FillBuf(sd *ScratchData, numOfBits uint16) {

	sd.BitBuf <<= numOfBits

	for numOfBits > sd.BitCount {

		numOfBits = numOfBits - sd.BitCount
		sd.BitBuf |= sd.SubBitBuf << numOfBits

		if sd.CompSize > 0 {
			sd.CompSize--
			sd.SubBitBuf = uint32(sd.SrcBase[sd.InBuf])
			sd.InBuf++
			sd.BitCount = 8
		} else {
			sd.SubBitBuf = 0
			sd.BitCount = 8
		}
	}

	sd.BitCount = sd.BitCount - numOfBits

	sd.BitBuf |= sd.SubBitBuf >> sd.BitCount
}
