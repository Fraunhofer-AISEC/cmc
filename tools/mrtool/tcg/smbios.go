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
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	smbiosTypeBios               = 0
	smbiosTypeSystem             = 1
	smbiosTypeChassis            = 3
	smbiosTypeProcessor          = 4
	smbiosTypeMemoryArray        = 16
	smbiosTypeMemoryDevice       = 17
	smbiosTypeMemoryArrayMapping = 19
	smbiosTypeBootInfo           = 32
	smbiosTypeEnd                = 127

	smbiosHandleBios          = 0x0000
	smbiosHandleSystem        = 0x0100
	smbiosHandleChassis       = 0x0300
	smbiosHandleProcessorBase = 0x0400
	smbiosHandleMemoryArray   = 0x1000
	smbiosHandleMemDeviceBase = 0x1100
	smbiosHandleMemMapBase    = 0x1300
	smbiosHandleBootInfo      = 0x2000
	smbiosHandleEnd           = 0xfeff
)

// SmbiosSpec describes a qemu-equivalent SMBIOS table
type SmbiosSpec struct {
	// VM topology.
	Sockets    int    // -smp sockets; one Type 4 emitted per socket
	RamSize    uint64 // -m, in bytes; required
	RamBelow4G uint64 // 0 => derive via QemuQ35RamSplit at encode time

	// Type 0 (BIOS Information)
	BiosVendor               string
	BiosVersion              string
	BiosDate                 string
	BiosStartingAddressSeg   uint16
	BiosCharacteristics      uint64
	BiosCharacteristicsExt   [2]byte
	BiosMajorRelease         uint8
	BiosMinorRelease         uint8
	EmbeddedCtlFirmwareMajor uint8
	EmbeddedCtlFirmwareMinor uint8

	// Type 1 (System Information). UUID and WakeUpType are dropped by the
	// EDK2 SmbiosMeasurementDxe filter, so they are not exposed here.
	Manufacturer   string
	ProductName    string
	MachineVersion string

	// Type 3 (Chassis)
	ChassisType           uint8
	ChassisBootupState    uint8
	ChassisPowerState     uint8
	ChassisThermalState   uint8
	ChassisSecurityStatus uint8
	ChassisOemDefined     uint32
	ChassisHeight         uint8
	ChassisNumPowerCords  uint8

	// Type 4 (Processor). One emitted per socket. Voltage, CurrentSpeed and
	// CoreCount-family fields are dropped by the filter, so they are not
	// exposed here.
	ProcessorId              uint64
	ProcessorFamily          uint8
	ProcessorFamily2         uint16
	ProcessorMaxSpeedMHz     uint16
	ProcessorUpgrade         uint8
	ProcessorStatus          uint8
	ProcessorCharacteristics uint16

	// Type 16 (Memory Array)
	MemoryArrayLocation        uint8
	MemoryArrayUse             uint8
	MemoryArrayErrorCorrection uint8

	// Type 17 (Memory Device)
	MemoryDeviceFormFactor uint8
	MemoryDeviceType       uint8
	MemoryDeviceTypeDetail uint16

	// Type 32 (Boot Information)
	BootStatus uint8
}

// SmbiosDefaults returns an SmbiosSpec populated with the qemu standard q35 defaults
func SmbiosDefaults() SmbiosSpec {
	return SmbiosSpec{
		Sockets: 1,

		BiosVendor:               "EDK II",
		BiosVersion:              "unknown",
		BiosDate:                 "02/02/2022",
		BiosStartingAddressSeg:   0xe800,
		BiosCharacteristics:      0x08,
		BiosCharacteristicsExt:   [2]byte{0x00, 0x1c},
		EmbeddedCtlFirmwareMajor: 0xff,
		EmbeddedCtlFirmwareMinor: 0xff,

		Manufacturer:   "QEMU",
		ProductName:    "Standard PC (Q35 + ICH9, 2009)",
		MachineVersion: "pc-q35-10.1",

		ChassisType:           0x01,
		ChassisBootupState:    0x03,
		ChassisPowerState:     0x03,
		ChassisThermalState:   0x03,
		ChassisSecurityStatus: 0x03,

		ProcessorFamily:          0xfe,
		ProcessorFamily2:         0x0001,
		ProcessorMaxSpeedMHz:     2000,
		ProcessorUpgrade:         0x01,
		ProcessorStatus:          0x41,
		ProcessorCharacteristics: 0x0002,
		ProcessorId:              0x178bfbff00800f12, // -cpu EPYC-v4 Family=17h, Model=1, Stepping=2

		MemoryArrayLocation:        0x01,
		MemoryArrayUse:             0x03,
		MemoryArrayErrorCorrection: 0x06,

		MemoryDeviceFormFactor: 0x09,
		MemoryDeviceType:       0x07,
		MemoryDeviceTypeDetail: 0x0002,
	}
}

func (s *SmbiosSpec) validate() error {
	if s.RamSize == 0 {
		return fmt.Errorf("ram size is required")
	}
	if s.Sockets < 1 {
		return fmt.Errorf("sockets must be >= 1")
	}
	if s.RamBelow4G == 0 {
		below, _ := QemuQ35RamSplit(s.RamSize)
		s.RamBelow4G = below
	}
	if s.RamBelow4G > s.RamSize {
		return fmt.Errorf("ram below 4G (%#x) exceeds RamSize (%#x)", s.RamBelow4G, s.RamSize)
	}
	return nil
}

func BuildSmbiosTable(spec SmbiosSpec) ([]byte, error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}

	var out bytes.Buffer

	// Order matches qemu: 1, 3, 4×N, 16, 17×D, 19×R, 32, 0, 127.
	if err := appendStruct(&out, smbiosTypeSystem, smbiosHandleSystem,
		encodeType1(spec),
		[]string{spec.Manufacturer, spec.ProductName, spec.MachineVersion}); err != nil {
		return nil, err
	}
	if err := appendStruct(&out, smbiosTypeChassis, smbiosHandleChassis,
		encodeType3(spec),
		[]string{spec.Manufacturer, spec.MachineVersion}); err != nil {
		return nil, err
	}
	for i := 0; i < spec.Sockets; i++ {
		if err := appendStruct(&out, smbiosTypeProcessor, smbiosHandleProcessorBase+uint16(i),
			encodeType4(spec, i),
			[]string{fmt.Sprintf("CPU %d", i), spec.Manufacturer, spec.MachineVersion}); err != nil {
			return nil, err
		}
	}
	if err := appendStruct(&out, smbiosTypeMemoryArray, smbiosHandleMemoryArray,
		encodeType16(spec, 1),
		nil); err != nil {
		return nil, err
	}
	// Single memory device covering all RAM (single -object memory-backend-ram)
	if err := appendStruct(&out, smbiosTypeMemoryDevice, smbiosHandleMemDeviceBase,
		encodeType17(spec, 0, spec.RamSize),
		[]string{"DIMM 0", spec.Manufacturer}); err != nil {
		return nil, err
	}

	regions := mappedAddressRegions(spec.RamSize, spec.RamBelow4G)
	for i, r := range regions {
		if err := appendStruct(&out, smbiosTypeMemoryArrayMapping, smbiosHandleMemMapBase+uint16(i),
			encodeType19(r.startKB, r.endKB),
			nil); err != nil {
			return nil, err
		}
	}

	if err := appendStruct(&out, smbiosTypeBootInfo, smbiosHandleBootInfo,
		encodeType32(spec),
		nil); err != nil {
		return nil, err
	}
	// Type 0 emitted near the end, matching qemu
	if err := appendStruct(&out, smbiosTypeBios, smbiosHandleBios,
		encodeType0(spec),
		[]string{spec.BiosVendor, spec.BiosVersion, spec.BiosDate}); err != nil {
		return nil, err
	}
	if err := appendStruct(&out, smbiosTypeEnd, smbiosHandleEnd,
		nil, nil); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

// appendStruct writes one SMBIOS structure: 4-byte header (type, length,
// handle) + formatted area + string set.
func appendStruct(out *bytes.Buffer, sType uint8, handle uint16, body []byte, strs []string) error {
	hdrLen := 4 + len(body)
	if hdrLen > 0xff {
		return fmt.Errorf("structure type %d formatted area too large (%d bytes)", sType, hdrLen)
	}

	if err := out.WriteByte(sType); err != nil {
		return err
	}
	if err := out.WriteByte(uint8(hdrLen)); err != nil {
		return err
	}
	if err := binary.Write(out, binary.LittleEndian, handle); err != nil {
		return err
	}
	if _, err := out.Write(body); err != nil {
		return err
	}
	return encodeStringSet(out, strs)
}

// encodeStringSet packs the string set after the formatted area: each string
// is NUL-terminated, followed by an additional NUL terminating the set
func encodeStringSet(out *bytes.Buffer, strs []string) error {
	written := false
	for _, s := range strs {
		if s == "" {
			continue
		}
		if _, err := out.WriteString(s); err != nil {
			return err
		}
		if err := out.WriteByte(0); err != nil {
			return err
		}
		written = true
	}
	if !written {
		if err := out.WriteByte(0); err != nil {
			return err
		}
	}
	return out.WriteByte(0)
}

func encodeType0(s SmbiosSpec) []byte {
	// SMBIOS 3.1 Type 0 length = 0x1A (26): 4 header + 22 formatted area.
	body := make([]byte, 22)
	body[0] = 1 // Vendor string idx
	body[1] = 2 // BIOSVersion string idx
	binary.LittleEndian.PutUint16(body[2:], s.BiosStartingAddressSeg)
	body[4] = 3 // BIOSReleaseDate string idx
	body[5] = 0 // BIOSROMSize (use ExtendedBIOSROMSize when 0)
	binary.LittleEndian.PutUint64(body[6:], s.BiosCharacteristics)
	body[14] = s.BiosCharacteristicsExt[0]
	body[15] = s.BiosCharacteristicsExt[1]
	body[16] = s.BiosMajorRelease
	body[17] = s.BiosMinorRelease
	body[18] = s.EmbeddedCtlFirmwareMajor
	body[19] = s.EmbeddedCtlFirmwareMinor
	binary.LittleEndian.PutUint16(body[20:], 0) // ExtendedBIOSROMSize
	return body
}

func encodeType1(s SmbiosSpec) []byte {
	// Length = 0x1B (27): 4 header + 23 formatted area.
	body := make([]byte, 23)
	body[0] = 1 // Manufacturer string idx
	body[1] = 2 // ProductName string idx
	body[2] = 3 // Version string idx
	body[3] = 0 // SerialNumber (none)
	// body[4..19] UUID and body[20] WakeUpType left zero; both are filtered.
	body[21] = 0 // SKUNumber (none)
	body[22] = 0 // Family (none)
	return body
}

func encodeType3(s SmbiosSpec) []byte {
	// Length = 0x16 (22): 4 header + 18 formatted area.
	body := make([]byte, 18)
	body[0] = 1 // Manufacturer string idx
	body[1] = s.ChassisType
	body[2] = 2 // Version string idx
	body[3] = 0 // SerialNumber (none)
	body[4] = 0 // AssetTag (none)
	body[5] = s.ChassisBootupState
	body[6] = s.ChassisPowerState
	body[7] = s.ChassisThermalState
	body[8] = s.ChassisSecurityStatus
	binary.LittleEndian.PutUint32(body[9:], s.ChassisOemDefined)
	body[13] = s.ChassisHeight
	body[14] = s.ChassisNumPowerCords
	body[15] = 0 // ContainedElementCount
	body[16] = 0 // ContainedElementRecordLength
	body[17] = 0 // SKUNumber (none)
	return body
}

func encodeType4(s SmbiosSpec, _ int) []byte {
	// Length = 0x2A (42): 4 header + 38 formatted area.
	body := make([]byte, 38)
	body[0] = 1    // SocketDesignation string idx ("CPU N")
	body[1] = 0x03 // ProcessorType = Central Processor
	body[2] = s.ProcessorFamily
	body[3] = 2 // ProcessorManufacturer string idx
	binary.LittleEndian.PutUint64(body[4:], s.ProcessorId)
	body[12] = 3 // ProcessorVersion string idx
	// body[13] Voltage left zero (filtered)
	binary.LittleEndian.PutUint16(body[14:], 0) // ExternalClock
	binary.LittleEndian.PutUint16(body[16:], s.ProcessorMaxSpeedMHz)
	// body[18..19] CurrentSpeed left zero (filtered)
	body[20] = s.ProcessorStatus
	body[21] = s.ProcessorUpgrade
	binary.LittleEndian.PutUint16(body[22:], 0xffff) // L1CacheHandle
	binary.LittleEndian.PutUint16(body[24:], 0xffff) // L2CacheHandle
	binary.LittleEndian.PutUint16(body[26:], 0xffff) // L3CacheHandle
	body[28] = 0                                     // SerialNumber (none)
	body[29] = 0                                     // AssetTag (none)
	body[30] = 0                                     // PartNumber (none)
	body[31] = 0                                     // CoreCount
	body[32] = 0                                     // CoreEnabled
	body[33] = 0                                     // ThreadCount
	binary.LittleEndian.PutUint16(body[34:], s.ProcessorCharacteristics)
	binary.LittleEndian.PutUint16(body[36:], s.ProcessorFamily2)
	return body
}

func encodeType16(s SmbiosSpec, numDevices uint16) []byte {
	// Length = 0x17 (23): 4 header + 19 formatted area.
	body := make([]byte, 19)
	body[0] = s.MemoryArrayLocation
	body[1] = s.MemoryArrayUse
	body[2] = s.MemoryArrayErrorCorrection

	maxKB := s.RamSize / 1024
	const u32max uint64 = 1 << 31 // 2 TiB in KB
	if maxKB >= u32max {
		binary.LittleEndian.PutUint32(body[3:], 0x80000000)
		binary.LittleEndian.PutUint64(body[11:], s.RamSize)
	} else {
		binary.LittleEndian.PutUint32(body[3:], uint32(maxKB))
		// ExtendedMaxCapacity bytes at body[11..18] left zero.
	}
	binary.LittleEndian.PutUint16(body[7:], 0xfffe) // MemoryErrorInformationHandle (no data)
	binary.LittleEndian.PutUint16(body[9:], numDevices)
	return body
}

func encodeType17(s SmbiosSpec, _ int, deviceSize uint64) []byte {
	// SMBIOS 2.8 layout: length = 0x28 (40), 4 header + 36 formatted area.
	body := make([]byte, 36)
	binary.LittleEndian.PutUint16(body[0:], smbiosHandleMemoryArray)
	binary.LittleEndian.PutUint16(body[2:], 0xfffe) // MemoryErrorInformationHandle (no data)
	binary.LittleEndian.PutUint16(body[4:], 0xffff) // TotalWidth unknown
	binary.LittleEndian.PutUint16(body[6:], 0xffff) // DataWidth unknown

	sizeMB := deviceSize / (1 << 20)
	if sizeMB >= 0x7fff {
		// Size > 32 GiB: use ExtendedSize.
		binary.LittleEndian.PutUint16(body[8:], 0x7fff)
		if sizeMB > 0xffffffff {
			// >4 PiB doesn't fit in ExtendedSize either; clamp.
			binary.LittleEndian.PutUint32(body[24:], 0xffffffff)
		} else {
			binary.LittleEndian.PutUint32(body[24:], uint32(sizeMB))
		}
	} else {
		binary.LittleEndian.PutUint16(body[8:], uint16(sizeMB))
	}

	body[10] = s.MemoryDeviceFormFactor
	body[11] = 0 // DeviceSet
	body[12] = 1 // DeviceLocator string idx ("DIMM N")
	body[13] = 0 // BankLocator (none)
	body[14] = s.MemoryDeviceType
	binary.LittleEndian.PutUint16(body[15:], s.MemoryDeviceTypeDetail)
	binary.LittleEndian.PutUint16(body[17:], 0) // Speed unknown
	body[19] = 2                                // Manufacturer string idx
	body[20] = 0                                // SerialNumber (none)
	body[21] = 0                                // AssetTag (none)
	body[22] = 0                                // PartNumber (none)
	body[23] = 0                                // Attributes
	// body[24..27] ExtendedSize set above when needed.
	binary.LittleEndian.PutUint16(body[28:], 0) // ConfiguredMemorySpeed
	binary.LittleEndian.PutUint16(body[30:], 0) // MinimumVoltage
	binary.LittleEndian.PutUint16(body[32:], 0) // MaximumVoltage
	binary.LittleEndian.PutUint16(body[34:], 0) // ConfiguredVoltage
	return body
}

func encodeType19(startKB, endKB uint32) []byte {
	// SMBIOS 2.7+ layout: length = 0x1F (31), 4 header + 27 formatted area.
	body := make([]byte, 27)
	binary.LittleEndian.PutUint32(body[0:], startKB)
	binary.LittleEndian.PutUint32(body[4:], endKB)
	binary.LittleEndian.PutUint16(body[8:], smbiosHandleMemoryArray)
	body[10] = 0x01 // PartitionWidth: 1 device
	// body[11..18] ExtendedStartingAddress = 0 (use 32-bit fields)
	// body[19..26] ExtendedEndingAddress = 0
	return body
}

func encodeType32(s SmbiosSpec) []byte {
	// Length = 0x0B (11), 4 header + 7 formatted area.
	body := make([]byte, 7)
	// body[0..5] Reserved
	body[6] = s.BootStatus
	return body
}

// SmbiosStructure is one decoded SMBIOS structure: 4-byte header (type, length,
// handle) + formatted area + string set. It mirrors the layout that
// appendStruct emits so a parse → encode round-trip is byte-identical.
type SmbiosStructure struct {
	Type    uint8
	Length  uint8 // length of the formatted area + 4-byte header
	Handle  uint16
	Body    []byte // formatted area bytes (Length-4 bytes long)
	Strings []string
}

// ParseSmbiosStructures decodes an smbios-tables blob
func ParseSmbiosStructures(blob []byte) ([]SmbiosStructure, error) {
	var out []SmbiosStructure
	off := 0
	sawEnd := false
	for off < len(blob) {
		if off+4 > len(blob) {
			return nil, fmt.Errorf("structure header truncated at offset %#x", off)
		}
		s := SmbiosStructure{
			Type:   blob[off],
			Length: blob[off+1],
			Handle: binary.LittleEndian.Uint16(blob[off+2:]),
		}
		if int(s.Length) < 4 {
			return nil, fmt.Errorf("structure at offset %#x has length %d < 4", off, s.Length)
		}
		bodyEnd := off + int(s.Length)
		if bodyEnd > len(blob) {
			return nil, fmt.Errorf("structure type %d at offset %#x: body extends past blob (%d > %d)",
				s.Type, off, bodyEnd, len(blob))
		}
		s.Body = append([]byte(nil), blob[off+4:bodyEnd]...)

		// String set layout: each string is NUL-terminated and the set itself
		// is terminated by a single extra NUL. When no strings are present the
		// set is just \0\0.
		ss := bodyEnd
		if ss >= len(blob) {
			return nil, fmt.Errorf("structure type %d at offset %#x: missing string set",
				s.Type, off)
		}
		if blob[ss] == 0 {
			if ss+1 >= len(blob) || blob[ss+1] != 0 {
				return nil, fmt.Errorf("structure type %d at offset %#x: empty string set must be \\0\\0",
					s.Type, off)
			}
			ss += 2
		} else {
			for {
				start := ss
				for ss < len(blob) && blob[ss] != 0 {
					ss++
				}
				if ss >= len(blob) {
					return nil, fmt.Errorf("structure type %d at offset %#x: unterminated string",
						s.Type, off)
				}
				s.Strings = append(s.Strings, string(blob[start:ss]))
				ss++ // consume the per-string NUL
				if ss >= len(blob) {
					return nil, fmt.Errorf("structure type %d at offset %#x: missing set terminator",
						s.Type, off)
				}
				if blob[ss] == 0 {
					ss++ // consume the set terminator NUL
					break
				}
			}
		}

		out = append(out, s)
		off = ss

		if s.Type == smbiosTypeEnd {
			sawEnd = true
			break
		}
	}
	if !sawEnd {
		return nil, fmt.Errorf("end-of-table marker (Type 127) not found")
	}
	if off != len(blob) {
		return nil, fmt.Errorf("%d trailing bytes after end-of-table", len(blob)-off)
	}
	return out, nil
}

// Return human-readable string representation of the SMBIOS table
func (s SmbiosStructure) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Type %d (%s)  handle=%#04x  length=%d  body=%d\n",
		s.Type, smbiosTypeName(s.Type), s.Handle, s.Length, len(s.Body))
	switch s.Type {
	case smbiosTypeBios:
		writeFields(&b, s.Body, s.Strings, []smbiosField{
			{"Vendor", 0, 1, "str"},
			{"BIOSVersion", 1, 1, "str"},
			{"BIOSStartingAddressSegment", 2, 2, "hex"},
			{"BIOSReleaseDate", 4, 1, "str"},
			{"BIOSROMSize", 5, 1, "hex"},
			{"BIOSCharacteristics", 6, 8, "hex"},
			{"BIOSCharacteristicsExt", 14, 2, "hex"},
			{"SystemBIOSMajorRelease", 16, 1, "dec"},
			{"SystemBIOSMinorRelease", 17, 1, "dec"},
			{"EmbeddedCtlFirmwareMajor", 18, 1, "hex"},
			{"EmbeddedCtlFirmwareMinor", 19, 1, "hex"},
			{"ExtendedBIOSROMSize", 20, 2, "hex"},
		})
	case smbiosTypeSystem:
		writeFields(&b, s.Body, s.Strings, []smbiosField{
			{"Manufacturer", 0, 1, "str"},
			{"ProductName", 1, 1, "str"},
			{"Version", 2, 1, "str"},
			{"SerialNumber", 3, 1, "str"},
			{"UUID", 4, 16, "hex"},
			{"WakeUpType", 20, 1, "hex"},
			{"SKUNumber", 21, 1, "str"},
			{"Family", 22, 1, "str"},
		})
	case smbiosTypeChassis:
		writeFields(&b, s.Body, s.Strings, []smbiosField{
			{"Manufacturer", 0, 1, "str"},
			{"ChassisType", 1, 1, "hex"},
			{"Version", 2, 1, "str"},
			{"SerialNumber", 3, 1, "str"},
			{"AssetTag", 4, 1, "str"},
			{"BootupState", 5, 1, "hex"},
			{"PowerSupplyState", 6, 1, "hex"},
			{"ThermalState", 7, 1, "hex"},
			{"SecurityStatus", 8, 1, "hex"},
			{"OemDefined", 9, 4, "hex"},
			{"Height", 13, 1, "dec"},
			{"NumberOfPowerCords", 14, 1, "dec"},
			{"SKUNumber", 17, 1, "str"},
		})
	case smbiosTypeProcessor:
		writeFields(&b, s.Body, s.Strings, []smbiosField{
			{"SocketDesignation", 0, 1, "str"},
			{"ProcessorType", 1, 1, "hex"},
			{"ProcessorFamily", 2, 1, "hex"},
			{"Manufacturer", 3, 1, "str"},
			{"ProcessorID", 4, 8, "hex"},
			{"Version", 12, 1, "str"},
			{"Voltage", 13, 1, "hex"},
			{"ExternalClock", 14, 2, "hex"},
			{"MaxSpeed", 16, 2, "dec"},
			{"CurrentSpeed", 18, 2, "dec"},
			{"Status", 20, 1, "hex"},
			{"ProcessorUpgrade", 21, 1, "hex"},
			{"L1CacheHandle", 22, 2, "hex"},
			{"L2CacheHandle", 24, 2, "hex"},
			{"L3CacheHandle", 26, 2, "hex"},
			{"CoreCount", 31, 1, "dec"},
			{"CoreEnabled", 32, 1, "dec"},
			{"ThreadCount", 33, 1, "dec"},
			{"ProcessorCharacteristics", 34, 2, "hex"},
			{"ProcessorFamily2", 36, 2, "hex"},
		})
	case smbiosTypeMemoryArray:
		writeFields(&b, s.Body, s.Strings, []smbiosField{
			{"Location", 0, 1, "hex"},
			{"Use", 1, 1, "hex"},
			{"ErrorCorrection", 2, 1, "hex"},
			{"MaxCapacityKB", 3, 4, "hex"},
			{"MemoryErrorInfoHandle", 7, 2, "hex"},
			{"NumberOfMemoryDevices", 9, 2, "dec"},
			{"ExtendedMaxCapacity", 11, 8, "hex"},
		})
	case smbiosTypeMemoryDevice:
		writeFields(&b, s.Body, s.Strings, []smbiosField{
			{"PhysicalMemoryArrayHandle", 0, 2, "hex"},
			{"MemoryErrorInfoHandle", 2, 2, "hex"},
			{"TotalWidth", 4, 2, "hex"},
			{"DataWidth", 6, 2, "hex"},
			{"Size", 8, 2, "hex"},
			{"FormFactor", 10, 1, "hex"},
			{"DeviceSet", 11, 1, "hex"},
			{"DeviceLocator", 12, 1, "str"},
			{"BankLocator", 13, 1, "str"},
			{"MemoryType", 14, 1, "hex"},
			{"TypeDetail", 15, 2, "hex"},
			{"Speed", 17, 2, "dec"},
			{"Manufacturer", 19, 1, "str"},
			{"ExtendedSize", 24, 4, "hex"},
		})
	case smbiosTypeMemoryArrayMapping:
		writeFields(&b, s.Body, s.Strings, []smbiosField{
			{"StartingAddressKB", 0, 4, "hex"},
			{"EndingAddressKB", 4, 4, "hex"},
			{"MemoryArrayHandle", 8, 2, "hex"},
			{"PartitionWidth", 10, 1, "dec"},
			{"ExtendedStartingAddress", 11, 8, "hex"},
			{"ExtendedEndingAddress", 19, 8, "hex"},
		})
	case smbiosTypeBootInfo:
		writeFields(&b, s.Body, s.Strings, []smbiosField{
			{"BootStatus", 6, 1, "hex"},
		})
	case smbiosTypeEnd:
		// header-only, nothing else to print
	default:
		fmt.Fprintf(&b, "  body: % x\n", s.Body)
	}
	return b.String()
}

func smbiosTypeName(t uint8) string {
	switch t {
	case smbiosTypeBios:
		return "BIOS Information"
	case smbiosTypeSystem:
		return "System Information"
	case smbiosTypeChassis:
		return "System Enclosure"
	case smbiosTypeProcessor:
		return "Processor"
	case smbiosTypeMemoryArray:
		return "Physical Memory Array"
	case smbiosTypeMemoryDevice:
		return "Memory Device"
	case smbiosTypeMemoryArrayMapping:
		return "Memory Array Mapped Address"
	case smbiosTypeBootInfo:
		return "System Boot Information"
	case smbiosTypeEnd:
		return "End-of-Table"
	default:
		return "?"
	}
}

type smbiosField struct {
	name   string
	offset int
	size   int
	render string // "hex" | "dec" | "str"
}

func writeFields(b *strings.Builder, body []byte, strs []string, fields []smbiosField) {
	for _, f := range fields {
		if f.offset+f.size > len(body) {
			break
		}
		chunk := body[f.offset : f.offset+f.size]
		switch f.render {
		case "str":
			idx := int(chunk[0])
			switch {
			case idx == 0:
				fmt.Fprintf(b, "  %s = (none)\n", f.name)
			case idx <= len(strs):
				fmt.Fprintf(b, "  %s = %q\n", f.name, strs[idx-1])
			default:
				fmt.Fprintf(b, "  %s = (invalid string index %d)\n", f.name, idx)
			}
		case "dec":
			var v uint64
			switch len(chunk) {
			case 1:
				v = uint64(chunk[0])
			case 2:
				v = uint64(binary.LittleEndian.Uint16(chunk))
			case 4:
				v = uint64(binary.LittleEndian.Uint32(chunk))
			case 8:
				v = binary.LittleEndian.Uint64(chunk)
			}
			fmt.Fprintf(b, "  %s = %d\n", f.name, v)
		default: // hex; "% x" gives space-separated bytes
			fmt.Fprintf(b, "  %s = % x\n", f.name, chunk)
		}
	}
}

type mappedRegion struct {
	startKB, endKB uint32
}

func mappedAddressRegions(ramSize, ramBelow4G uint64) []mappedRegion {
	regions := make([]mappedRegion, 0, 2)
	regions = append(regions, mappedRegion{
		startKB: 0,
		endKB:   uint32(ramBelow4G/1024 - 1),
	})
	if above := ramSize - ramBelow4G; above > 0 {
		startKB := uint32(QemuAbove4gMemStart / 1024)
		regions = append(regions, mappedRegion{
			startKB: startKB,
			endKB:   startKB + uint32(above/1024) - 1,
		})
	}
	return regions
}

// FilterSmbiosForMeasurement applies the EDK2 MdeModulePkg/Universal/
// SmbiosMeasurementDxe filter blacklist to the SMBIOS table that
// OVMF measures as EV_EFI_HANDOFF_TABLES. Per-type fields are
// zeroed (numeric) or overwritten with spaces (string-indexed), and certain
// whole types are zeroed entirely. The input must be an SMBIOS
// structure table (e.g. /sys/firmware/dmi/tables/DMI). The returned bytes are
// what TpmMeasureAndLogData hashes.
func FilterSmbiosForMeasurement(blob []byte) ([]byte, error) {
	structs, err := ParseSmbiosStructures(blob)
	if err != nil {
		return nil, fmt.Errorf("parse smbios: %w", err)
	}
	for i := range structs {
		filterStructure(&structs[i])
	}

	var out bytes.Buffer
	for _, s := range structs {
		if err := appendStruct(&out, s.Type, s.Handle, s.Body, s.Strings); err != nil {
			return nil, fmt.Errorf("re-emit type %d: %w", s.Type, err)
		}
	}
	return out.Bytes(), nil
}

// filterStructure mutates s in place to match EDK2 FilterSmbiosEntry output.
func filterStructure(s *SmbiosStructure) {
	// OEM types: zero entire body, leave string set untouched.
	if s.Type >= 128 {
		for i := range s.Body {
			s.Body[i] = 0
		}
		return
	}
	switch s.Type {
	case 1: // System Information
		zeroString(s, 3)         // SerialNumber → spaces
		zeroBytes(s.Body, 4, 16) // UUID
		zeroBytes(s.Body, 20, 1) // WakeUpType
	case 2: // Baseboard
		zeroString(s, 3) // SerialNumber
		zeroString(s, 8) // LocationInChassis
	case 3: // System Enclosure
		zeroString(s, 3) // SerialNumber
		zeroString(s, 4) // AssetTag
	case 4: // Processor
		zeroString(s, 28)        // SerialNumber
		zeroString(s, 29)        // AssetTag
		zeroString(s, 30)        // PartNumber
		zeroBytes(s.Body, 13, 1) // Voltage
		zeroBytes(s.Body, 18, 2) // CurrentSpeed
		zeroBytes(s.Body, 31, 1) // CoreCount
		zeroBytes(s.Body, 32, 1) // EnabledCoreCount
		zeroBytes(s.Body, 33, 1) // ThreadCount
		zeroBytes(s.Body, 38, 2) // CoreCount2 (SMBIOS 3.0+, length >= 42)
		zeroBytes(s.Body, 40, 2) // EnabledCoreCount2
		zeroBytes(s.Body, 42, 2) // ThreadCount2
	case 11, 15, 18, 31, 33: // OEM Strings, EventLog, 32-bit MemErr, BootIntegrityServices, 64-bit MemErr
		for i := range s.Body {
			s.Body[i] = 0
		}
	case 17: // Memory Device
		zeroString(s, 20) // SerialNumber
		zeroString(s, 21) // AssetTag
		zeroString(s, 22) // PartNumber
	case 22: // Portable Battery
		zeroString(s, 7)         // SerialNumber
		zeroBytes(s.Body, 13, 2) // SBDSSerialNumber
		zeroBytes(s.Body, 15, 2) // SBDSManufactureDate
	case 23: // System Reset
		zeroBytes(s.Body, 7, 2) // ResetCount
	case 27: // Cooling Device
		zeroBytes(s.Body, 11, 2) // NominalSpeed
	case 39: // System Power Supply
		zeroString(s, 10) // SerialNumber
		zeroString(s, 11) // AssetTagNumber
		zeroString(s, 13) // ModelPartNumber
	}
}

// zeroBytes zeros body[off:off+size] when fully in range. Out-of-range offsets
// are silently skipped to match EDK2's "field is present" guard.
func zeroBytes(body []byte, off, size int) {
	if off+size > len(body) {
		return
	}
	for i := off; i < off+size; i++ {
		body[i] = 0
	}
}

// zeroString overwrites the string referenced by body[off] with spaces in the
// structure's string set
func zeroString(s *SmbiosStructure, off int) {
	if off >= len(s.Body) {
		return
	}
	idx := int(s.Body[off])
	if idx == 0 || idx > len(s.Strings) {
		return
	}
	str := []byte(s.Strings[idx-1])
	for i := range str {
		str[i] = ' '
	}
	s.Strings[idx-1] = string(str)
}
