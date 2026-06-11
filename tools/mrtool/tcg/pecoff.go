// Copyright (c) 2026 Fraunhofer AISEC
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
	"debug/pe"
	"encoding/binary"
	"fmt"
	"slices"
)

const (
	dosSignature = 0x5A4D // "MZ"
	dosLfanewOff = 0x3C   // offset of e_lfanew in EFI_IMAGE_DOS_HEADER

	coffSigSize       = 4  // "PE\0\0"
	fileHeaderSize    = 20 // sizeof(EFI_IMAGE_FILE_HEADER)
	optHdrChecksumOff = 64 // offset of CheckSum within OptionalHeader (PE32 == PE32+)

	// Offsets of the DataDirectory array within OptionalHeader.
	dataDirOffPE32  = 96
	dataDirOffPE32p = 112

	securityDirIdx  = 4 // EFI_IMAGE_DIRECTORY_ENTRY_SECURITY
	dataDirEntrySz  = 8 // sizeof(EFI_IMAGE_DATA_DIRECTORY) = {VirtualAddress, Size}
	checksumFieldSz = 4
)

// MeasurePeCoff returns the Authenticode hash of a PE/COFF image
func MeasurePeCoff(alg crypto.Hash, buf []byte) ([]byte, error) {
	if !alg.Available() {
		return nil, fmt.Errorf("hash algorithm %v not available", alg)
	}

	f, err := pe.NewFile(bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("parse PE/COFF: %w", err)
	}
	defer f.Close()

	peHdrOff, err := peHeaderOffset(buf)
	if err != nil {
		return nil, err
	}

	var sizeOfHeaders uint32
	var numberOfRvaAndSizes uint32
	var certSize uint32
	var dataDirOff int
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		sizeOfHeaders = oh.SizeOfHeaders
		numberOfRvaAndSizes = oh.NumberOfRvaAndSizes
		if numberOfRvaAndSizes > securityDirIdx {
			certSize = oh.DataDirectory[securityDirIdx].Size
		}
		dataDirOff = dataDirOffPE32
	case *pe.OptionalHeader64:
		sizeOfHeaders = oh.SizeOfHeaders
		numberOfRvaAndSizes = oh.NumberOfRvaAndSizes
		if numberOfRvaAndSizes > securityDirIdx {
			certSize = oh.DataDirectory[securityDirIdx].Size
		}
		dataDirOff = dataDirOffPE32p
	default:
		return nil, fmt.Errorf("PE/COFF image has no optional header")
	}

	if uint64(sizeOfHeaders) > uint64(len(buf)) {
		return nil, fmt.Errorf("SizeOfHeaders (%d) exceeds image size (%d)", sizeOfHeaders, len(buf))
	}

	ohStart := peHdrOff + coffSigSize + fileHeaderSize
	checksumStart := ohStart + optHdrChecksumOff
	afterChecksum := checksumStart + checksumFieldSz
	securityDirStart := ohStart + dataDirOff + securityDirIdx*dataDirEntrySz
	afterSecurityDir := securityDirStart + dataDirEntrySz

	h := alg.New()

	// PE/COFF Spec 8.0 Appendix A, steps 3-9:
	// Hash from beginning to but excluding checksum, then either hash up to SizeOfHeaders
	// (no security dir) or up to the Security data directory
	h.Write(buf[:checksumStart])
	if numberOfRvaAndSizes <= securityDirIdx {
		if afterChecksum < int(sizeOfHeaders) {
			h.Write(buf[afterChecksum:sizeOfHeaders])
		}
	} else {
		if afterChecksum < securityDirStart {
			h.Write(buf[afterChecksum:securityDirStart])
		}
		if afterSecurityDir < int(sizeOfHeaders) {
			h.Write(buf[afterSecurityDir:sizeOfHeaders])
		}
	}

	// Steps 11-15: walk sections in PointerToRawData order, hash
	// section raw data, accumulate total bytes
	sections := slices.Clone(f.Sections)
	slices.SortFunc(sections, func(a, b *pe.Section) int {
		return int(a.Offset) - int(b.Offset)
	})

	sumOfBytesHashed := uint64(sizeOfHeaders)
	for _, s := range sections {
		if s.Size == 0 {
			continue
		}
		end := uint64(s.Offset) + uint64(s.Size)
		if end > uint64(len(buf)) {
			return nil, fmt.Errorf("section %q extends past image: end=%d, size=%d", s.Name, end, len(buf))
		}
		h.Write(buf[s.Offset:end])
		sumOfBytesHashed += uint64(s.Size)
	}

	// Step 16: hash trailing bytes beyond the section data, exclude the
	// attribute certificate table
	bufLen := uint64(len(buf))
	if bufLen > sumOfBytesHashed {
		trailingEnd := bufLen - uint64(certSize)
		if trailingEnd < sumOfBytesHashed {
			return nil, fmt.Errorf("cert table (%d) larger than trailing image data (%d)",
				certSize, bufLen-sumOfBytesHashed)
		}
		if trailingEnd > sumOfBytesHashed {
			h.Write(buf[sumOfBytesHashed:trailingEnd])
		}
	}

	return h.Sum(nil), nil
}

// peHeaderOffset returns the file offset of the COFF signature.
// If a DOS header is present, this is e_lfanew; otherwise it is 0.
func peHeaderOffset(buf []byte) (int, error) {
	if len(buf) < dosLfanewOff+4 {
		return 0, fmt.Errorf("image too small (%d bytes)", len(buf))
	}
	if binary.LittleEndian.Uint16(buf[:2]) != dosSignature {
		return 0, nil
	}
	off := int(binary.LittleEndian.Uint32(buf[dosLfanewOff:]))
	if off < 0 || off+coffSigSize+fileHeaderSize > len(buf) {
		return 0, fmt.Errorf("invalid PE header offset %d", off)
	}
	return off, nil
}
