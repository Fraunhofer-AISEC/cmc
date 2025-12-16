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
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"unicode/utf16"
)

// EfiLBA represents a Logical Block Address.
type EfiLBA uint64

// EfiTableHeader represents the common header for all EFI tables.
type EfiTableHeader struct {
	Signature  uint64 // 64-bit table type signature
	Revision   uint32 // EFI spec revision (major:upper16, minor:lower16)
	HeaderSize uint32 // Size of the table including this header
	CRC32      uint32 // 32-bit CRC of the table
	Reserved   uint32
}

// EfiGuid represents a GUID/UUID.
type EfiGuid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]uint8
}

// GptPartitionTableHeader represents the GPT Partition Table Header.
type GptPartitionTableHeader struct {
	Header                   EfiTableHeader // Table header (EFI_PTAB_HEADER_ID)
	MyLBA                    EfiLBA         // LBA of this header
	AlternateLBA             EfiLBA         // LBA of alternate GPT header
	FirstUsableLBA           EfiLBA         // First usable block for partitions
	LastUsableLBA            EfiLBA         // Last usable block for partitions
	DiskGUID                 EfiGuid        // Unique disk identifier
	PartitionEntryLBA        EfiLBA         // Starting LBA of partition entries
	NumberOfPartitionEntries uint32         // Number of partition entries
	SizeOfPartitionEntry     uint32         // Size of each partition entry (128 * 2^n)
	PartitionEntryArrayCRC32 uint32         // CRC32 of partition entry array
}

// EfiPartitionEntry represents a single GPT partition entry.
type EfiPartitionEntry struct {
	PartitionTypeGUID   EfiGuid    // GUID defining the type/purpose of the partition
	UniquePartitionGUID EfiGuid    // Unique GUID for this partition
	StartingLBA         EfiLBA     // Starting LBA of the partition
	EndingLBA           EfiLBA     // Ending LBA of the partition
	Attributes          uint64     // Partition attribute bits (UEFI defined)
	PartitionName       [36]uint16 // UTF-16 partition name
}

const (
	PrimaryPartHeaderLBA  = 1
	EfiPtabHeaderID       = 0x5452415020494645 // 'EFI PART'
	GptHeaderRevisionV1   = 0x00010000
	LogicalBlockSize      = 512 // default GPT logical block size
	HeaderSize            = 92
	MinPartitionEntrySize = 128
)

// MeasureGptTable reads the GPT table from a raw disk file and returns its SHA-256 hash.
// Only valid partitions (non-zero) are included.
func MeasureGptFromFile(h hash.Hash, path, dump string) ([]byte, string, error) {
	var buf bytes.Buffer

	f, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("open disk image: %w", err)
	}
	defer f.Close()

	// Find primary GPT header
	headerOffset, err := findGptHeaderOffset(f)
	if err != nil {
		return nil, "", fmt.Errorf("failed to find GPT header: %w", err)
	}

	var header GptPartitionTableHeader
	if err := readStructAt(f, headerOffset, &header); err != nil {
		return nil, "", fmt.Errorf("read GPT header: %w", err)
	}

	PrintGptHeader(&header)

	// Validate header
	if err := checkEFIPartitionTableHeader(header); err != nil {
		return nil, "", err
	}

	// Serialize header
	if err := binary.Write(&buf, binary.LittleEndian, &header); err != nil {
		return nil, "", fmt.Errorf("write GPT header: %w", err)
	}

	// Count number of partitions
	entryArrayOffset := headerOffset + 1*LogicalBlockSize
	entrySize := header.SizeOfPartitionEntry
	entryCount := header.NumberOfPartitionEntries
	numberOfPartitions := uint64(0)
	for i := uint32(0); i < entryCount; i++ {
		var entry EfiPartitionEntry
		offset := entryArrayOffset + int64(i*entrySize)
		if err := readStructAt(f, offset, &entry); err != nil {
			return nil, "", fmt.Errorf("read partition entry %v: %w", i, err)
		}
		// Only measure non-zero PartitionTypeGUID
		if isZeroGuid(entry.PartitionTypeGUID) {
			continue
		}
		numberOfPartitions++
	}

	// Serialize number of partitions
	if err := binary.Write(&buf, binary.LittleEndian, &numberOfPartitions); err != nil {
		return nil, "", fmt.Errorf("write number of partitions: %w", err)
	}

	// Serialize partition entry array
	for i := uint32(0); i < entryCount; i++ {
		var entry EfiPartitionEntry

		offset := entryArrayOffset + int64(i*entrySize)
		if err := readStructAt(f, offset, &entry); err != nil {
			return nil, "", fmt.Errorf("read partition entry %v: %w", i, err)
		}

		// Only measure non-zero PartitionTypeGUID
		if isZeroGuid(entry.PartitionTypeGUID) {
			continue
		}

		log.Debugf("Read non-zero partition entry %v", i)
		PrintGptPartitionEntry(&entry)

		// Serialize entry
		if err := binary.Write(&buf, binary.LittleEndian, &entry); err != nil {
			return nil, "", fmt.Errorf("write partition entry %d: %w", i, err)
		}
	}

	if dump != "" {
		err := os.WriteFile(dump, buf.Bytes(), 0644)
		if err != nil {
			return nil, "", fmt.Errorf("failed to write file: %w", err)
		}
	}

	if _, err := h.Write(buf.Bytes()); err != nil {
		return nil, "", fmt.Errorf("hash GPT header: %w", err)
	}

	return h.Sum(nil), WriteGptHeader(&header), nil
}

func findGptHeaderOffset(f *os.File) (int64, error) {
	// Try canonical location first (LBA 1)
	canonical := int64(PrimaryPartHeaderLBA * LogicalBlockSize)

	var header GptPartitionTableHeader
	if err := readStructAt(f, canonical, &header); err == nil {
		if header.Header.Signature == EfiPtabHeaderID {
			return canonical, nil
		}
	}

	// Fallback: check if GPT header can be found anywhere in the file
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	size := info.Size()

	buf := make([]byte, binary.Size(GptPartitionTableHeader{}))
	for off := int64(0); off+int64(len(buf)) <= size; off++ { // scan byte-by-byte
		if _, err := f.ReadAt(buf, off); err != nil {
			continue
		}

		var header GptPartitionTableHeader
		r := bytes.NewReader(buf)
		if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
			continue
		}

		if header.Header.Signature == EfiPtabHeaderID {
			if off != canonical {
				log.Warnf("GPT header found at non-standard offset %d (expected %d)", off, canonical)
			}
			return off, nil
		}
	}

	return 0, fmt.Errorf("EFI GPT header not found (signature 0x%X)", EfiPtabHeaderID)
}

func WriteGptHeader(hdr *GptPartitionTableHeader) string {
	guidStr := writeGuid(&hdr.DiskGUID) // Get GUID as string

	return fmt.Sprintf(
		"UEFI Partition Table: "+
			"Signature: 0x%x, "+
			"Revision: 0x%x, "+
			"HeaderSize: %d, "+
			"HeaderCRC32: 0x%x, "+
			"MyLBA: 0x%x, "+
			"AlternateLBA: 0x%x, "+
			"FirstUsableLBA: 0x%x, "+
			"LastUsableLBA: 0x%x, "+
			"DiskGUID: %s, "+
			"PartitionEntryLBA: 0x%x, "+
			"NumberOfPartitionEntries: %d, "+
			"SizeOfPartitionEntry: %d, "+
			"PartitionEntryArrayCRC32: 0x%x",
		hdr.Header.Signature,
		hdr.Header.Revision,
		hdr.Header.HeaderSize,
		hdr.Header.CRC32,
		hdr.MyLBA,
		hdr.AlternateLBA,
		hdr.FirstUsableLBA,
		hdr.LastUsableLBA,
		guidStr,
		hdr.PartitionEntryLBA,
		hdr.NumberOfPartitionEntries,
		hdr.SizeOfPartitionEntry,
		hdr.PartitionEntryArrayCRC32,
	)
}

// WriteGuid returns a GUID as a formatted string.
func writeGuid(guid *EfiGuid) string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1],
		guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7])
}

func PrintGptHeader(hdr *GptPartitionTableHeader) {
	log.Debugf("Signature               : 0x%x", hdr.Header.Signature)
	log.Debugf("Revision                : 0x%x", hdr.Header.Revision)
	log.Debugf("HeaderSize              : %d", hdr.Header.HeaderSize)
	log.Debugf("HeaderCRC32             : 0x%x", hdr.Header.CRC32)
	log.Debugf("MyLBA                   : %d", hdr.MyLBA)
	log.Debugf("AlternateLBA            : 0x%x", hdr.AlternateLBA)
	log.Debugf("FirstUsableLBA          : 0x%x", hdr.FirstUsableLBA)
	log.Debugf("LastUsableLBA           : 0x%x", hdr.LastUsableLBA)
	printGuid(&hdr.DiskGUID, "Disk GUID               :")
	log.Debugf("PartitionEntryLBA       : 0x%x", hdr.PartitionEntryLBA)
	log.Debugf("NumberOfPartitionEntries: %d", hdr.NumberOfPartitionEntries)
	log.Debugf("SizeOfPartitionEntry    : %d", hdr.SizeOfPartitionEntry)
	log.Debugf("PartitionEntryArrayCRC32: 0x%x", hdr.PartitionEntryArrayCRC32)
}

func PrintGptPartitionEntry(entry *EfiPartitionEntry) {

	printGuid(&entry.PartitionTypeGUID, "Partition Type GUID:")
	printGuid(&entry.UniquePartitionGUID, "Unique Partition GUID:")
	log.Debugf("Starting LBA: %d", entry.StartingLBA)
	log.Debugf("Ending LBA:   %d", entry.EndingLBA)
	log.Debugf("Attributes:   0x%x", entry.Attributes)
	var name []uint16
	for _, c := range entry.PartitionName {
		if c == 0 {
			break
		}
		name = append(name, c)
	}
	log.Debugf("Partition Name: %s", string(utf16.Decode(name)))
}

// PrintGuid prints a GUID in standard format.
func printGuid(guid *EfiGuid, name string) {
	log.Debugf("%s %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		name,
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1],
		guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7])
}

// checkEFIPartitionTableHeader validates a GPT partition table header.
// Returns an error describing the first failing check, including the relevant values.
func checkEFIPartitionTableHeader(header GptPartitionTableHeader) error {
	// Signature check
	if header.Header.Signature != EfiPtabHeaderID {
		return fmt.Errorf("invalid partition table header signature: got 0x%X, want 0x%X",
			header.Header.Signature, EfiPtabHeaderID)
	}

	// Revision check
	if header.Header.Revision != GptHeaderRevisionV1 {
		return fmt.Errorf("invalid partition table header revision: got 0x%X, want 0x%X",
			header.Header.Revision, GptHeaderRevisionV1)
	}

	// HeaderSize check
	if header.Header.HeaderSize < HeaderSize || header.Header.HeaderSize > LogicalBlockSize {
		return fmt.Errorf("invalid header size: got %d, must be between %d and %d",
			header.Header.HeaderSize, HeaderSize, LogicalBlockSize)
	}

	// PartitionEntryLBA vs FirstUsableLBA
	if header.FirstUsableLBA <= header.PartitionEntryLBA {
		return fmt.Errorf("PartitionEntryLBA %d must be less than FirstUsableLBA %d",
			header.PartitionEntryLBA, header.FirstUsableLBA)
	}

	// PartitionEntryLBA overflow check
	if header.PartitionEntryLBA > math.MaxUint64/LogicalBlockSize {
		return fmt.Errorf("PartitionEntryLBA too large for allocation: %d", header.PartitionEntryLBA)
	}

	// Number of partition entries > 0
	if header.NumberOfPartitionEntries == 0 {
		return fmt.Errorf("number of partition entries cannot be zero")
	}

	// SizeOfPartitionEntry check (128 x 2^n)
	size := header.SizeOfPartitionEntry
	if size < MinPartitionEntrySize || (size&(size-1)) != 0 {
		return fmt.Errorf("invalid SizeOfPartitionEntry: %d, must be 128 x 2^n", size)
	}

	// Total allocation overflow check
	if uint64(header.NumberOfPartitionEntries) > math.MaxUint64/uint64(size) {
		return fmt.Errorf("number of partition entries too large: %d with SizeOfPartitionEntry %d would overflow",
			header.NumberOfPartitionEntries, size)
	}

	return nil
}

func readStructAt[T any](r io.ReaderAt, offset int64, out *T) error {
	sr := io.NewSectionReader(r, offset, int64(binary.Size(out)))
	return binary.Read(sr, binary.LittleEndian, out)
}

func isZeroGuid(g EfiGuid) bool {
	return g.Data1 == 0 &&
		g.Data2 == 0 &&
		g.Data3 == 0 &&
		g.Data4 == [8]uint8{}
}
