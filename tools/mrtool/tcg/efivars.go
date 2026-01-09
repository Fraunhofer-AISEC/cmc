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
	"os"
	"path/filepath"
	"strconv"
	"unicode/utf16"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

var (
	EfiGlobalVariableGuid                  = [16]byte{0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}
	EfiImageSecurityDatabaseGuid           = [16]byte{0xcb, 0xb2, 0x19, 0xd7, 0x3a, 0x3d, 0x96, 0x45, 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f}
	EfiImageSecurityDatabase1SbatLevelGuid = [16]byte{0x50, 0xab, 0x5d, 0x60, 0x46, 0xe0, 0x00, 0x43, 0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23}
	FvNameGuid                             = [16]byte{0xc9, 0xbd, 0xb8, 0x7c, 0xeb, 0xf8, 0x34, 0x4f, 0xaa, 0xea, 0x3e, 0xe4, 0xaf, 0x65, 0x16, 0xa1}
	FileGuid                               = [16]byte{0x21, 0xaa, 0x2c, 0x46, 0x14, 0x76, 0x03, 0x45, 0x83, 0x6e, 0x8a, 0xb6, 0xf4, 0x66, 0x23, 0x31}
)

const (
	LoadOptionActive      = (1 << 0)
	LoadOptionHidden      = (1 << 3)
	LoadOptionCategoryApp = (1 << 8)

	MediaProtocolType         = 4
	EndOfPathType             = 0x7f
	PiwgFirmwareFileSubType   = 6
	piwgFirmwareVolumeSubType = 7

	// EFI_GUID    VariableName;
	// UINT64      UnicodeNameLength;
	// UINT64      VariableDataLength;
	// CHAR16      UnicodeName[1];
	// INT8        VariableData[1];
	UefiVariableDataMinSize = 16 + 8 + 8
)

type SecBootVariableType struct {
	EventType    string
	VariableName string
	VendorGuid   [16]byte
	Path         string
	Data         []byte
}

func MeasureEfiBootVars(alg crypto.Hash, ta TrustAnchor, digest []byte,
	refvals []*ar.ReferenceValue, index int, bootOrder []string, bootXxxx []string,
) ([]byte, []*ar.ReferenceValue, error) {
	var err error

	// parse the boot order to uint16
	bootOrderParsed := make([]uint16, len(bootOrder))
	for i, s := range bootOrder {
		val, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid boot order value: %w", err)
		}
		bootOrderParsed[i] = uint16(val)
	}

	// if no boor order is given, it must contain a default 0 value
	if len(bootOrderParsed) == 0 {
		bootOrderParsed = append(bootOrderParsed, 0)
	}

	// EV_EFI_VARIABLE_BOOT Boot order
	bootOrderSerialized, _ := binary.Append(nil, binary.LittleEndian, bootOrderParsed)

	var bootOrderRefval *ar.ReferenceValue
	bootOrderRefval, digest, err = CreateExtendRefval(alg, ta, index, digest, bootOrderSerialized,
		"EV_EFI_VARIABLE_BOOT",
		"VariableName - BootOrder, VendorGuid - 8BE4DF61-93CA-11D2-AA0D-00E098032B8C")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create boot order reference value: %w", err)
	}
	refvals = append(refvals, bootOrderRefval)

	// Default EV_EFI_VARIABLE_BOOT Boot0000 variable
	if len(bootXxxx) == 0 {
		efiVariableBoot0000 := calculateEfiLoadOption()

		var boot0000Refval *ar.ReferenceValue
		boot0000Refval, digest, err = CreateExtendRefval(alg, ta, index, digest, efiVariableBoot0000,
			"EV_EFI_VARIABLE_BOOT", "VariableName - Boot0000, VendorGuid - 8BE4DF61-93CA-11D2-AA0D-00E098032B8C")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create boot order reference value: %w", err)
		}
		refvals = append(refvals, boot0000Refval)

	} else {
		for _, path := range bootXxxx {

			data, err := readEfiVariableFromFile(path, EfiGlobalVariableGuid)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read efi variable from file: %w", err)
			}

			var bootRefval *ar.ReferenceValue
			bootRefval, digest, err = CreateExtendRefval(alg, ta, index, digest, data,
				"EV_EFI_VARIABLE_BOOT", filepath.Base(path))
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create reference value for %v: %w", path, err)
			}

			refvals = append(refvals, bootRefval)
		}
	}

	return digest, refvals, nil
}

func MeasureSecureBootVariables(alg crypto.Hash, ta TrustAnchor, digest []byte,
	refvals []*ar.ReferenceValue, index int, secureBoot, pk, kek, db, dbx string,
) ([]byte, []*ar.ReferenceValue, error) {

	vars := []SecBootVariableType{
		{EventType: "EV_EFI_VARIABLE_DRIVER_CONFIG", VariableName: "SecureBoot", VendorGuid: EfiGlobalVariableGuid, Path: secureBoot},
		{EventType: "EV_EFI_VARIABLE_DRIVER_CONFIG", VariableName: "PK", VendorGuid: EfiGlobalVariableGuid, Path: pk},
		{EventType: "EV_EFI_VARIABLE_DRIVER_CONFIG", VariableName: "KEK", VendorGuid: EfiGlobalVariableGuid, Path: kek},
		{EventType: "EV_EFI_VARIABLE_DRIVER_CONFIG", VariableName: "db", VendorGuid: EfiImageSecurityDatabaseGuid, Path: db},
		{EventType: "EV_EFI_VARIABLE_DRIVER_CONFIG", VariableName: "dbx", VendorGuid: EfiImageSecurityDatabaseGuid, Path: dbx},
	}

	for _, val := range vars {
		varData, err := createVariable(val)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure variable: %w", err)
		}

		var rv *ar.ReferenceValue
		rv, digest, err = CreateExtendRefval(alg, ta, index, digest, varData, val.EventType, val.VariableName)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create secure boot reference value for %v: %w",
				val.VariableName, err)
		}

		refvals = append(refvals, rv)
	}

	return digest, refvals, nil
}

func MeasureMoklists(alg crypto.Hash, ta TrustAnchor, digest []byte, refvals []*ar.ReferenceValue,
	index int, moklists []string,
) ([]byte, []*ar.ReferenceValue, error) {

	for _, path := range moklists {

		data, err := readEfiVariableFromFile(path, EfiImageSecurityDatabase1SbatLevelGuid)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read efi variable from file: %w", err)
		}

		var rv *ar.ReferenceValue
		rv, digest, err = CreateExtendRefval(alg, ta, index, digest, data, "EV_IPL", filepath.Base(path))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create reference value for %v: %w", path, err)
		}

		refvals = append(refvals, rv)
	}

	return digest, refvals, nil
}

func MeasureSbatLevel(alg crypto.Hash, ta TrustAnchor, digest []byte,
	refvals []*ar.ReferenceValue, index int, sbatlevelPath string,
) ([]byte, []*ar.ReferenceValue, error) {

	sbat := SecBootVariableType{
		EventType:    "EV_EFI_VARIABLE_AUTHORITY",
		VariableName: "SbatLevel",
		VendorGuid:   EfiImageSecurityDatabase1SbatLevelGuid,
		Path:         sbatlevelPath,
	}

	varData, err := createVariable(sbat)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure variable: %w", err)
	}

	var rv *ar.ReferenceValue
	rv, digest, err = CreateExtendRefval(alg, ta, index, digest, varData, sbat.EventType, sbat.VariableName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create secure boot reference value for %v: %w",
			sbat.VariableName, err)
	}

	refvals = append(refvals, rv)

	return digest, refvals, nil
}

// TCG PC Client Platform Firmware Profile Specification layout of UEFI_VARIABLE_DATA:
//
//	typedef struct tdUEFI_VARIABLE_DATA {
//			UEFI_GUID VariableName;
//			UINT64 UnicodeNameLength;
//			UINT64 VariableDataLength;
//			CHAR16 UnicodeName[];
//			INT8 VariableData[]; // Driver or platform-specific data
//	} UEFI_VARIABLE_DATA;
func createVariable(val SecBootVariableType) ([]byte, error) {
	var err error

	data := val.Data
	if val.Path != "" {
		data, err = os.ReadFile(val.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to read variable file: %w", err)
		}
	}

	// encode name as utf-16
	utf16Units := utf16.Encode([]rune(val.VariableName))

	// write the guid to the data buffer (reconstructing UEFI_VARIABLE_DATA)
	buffer := []byte{}
	buffer = append(buffer, val.VendorGuid[:]...)

	// write the name length and variable data length to the buffer
	buffer, _ = binary.Append(buffer, binary.LittleEndian, uint64(len(utf16Units)))
	buffer, _ = binary.Append(buffer, binary.LittleEndian, uint64(len(data)))

	// write the utf-16 encoded string to the buffer
	for _, unit := range utf16Units {
		buffer, _ = binary.Append(buffer, binary.LittleEndian, unit)
	}

	// write the data to the buffer
	buffer = append(buffer, data...)

	return buffer, nil
}

func createNode(baseType, subType uint8, data []byte) []byte {
	buffer := []byte{baseType, subType}
	buffer = binary.LittleEndian.AppendUint16(buffer, uint16(len(data)+4))
	return append(buffer, data...)
}

func createFilePathList() []byte {
	buffer := []byte{}

	// UEFI Platform Initialization Specification, Version 1.8 Errata A, II-8.2
	// Firmware Volume Media Device Path: PIWG Firmware Volume Device Path node
	buffer = append(buffer, createNode(MediaProtocolType, piwgFirmwareVolumeSubType, FvNameGuid[:])...)

	// UEFI Platform Initialization Specification, Version 1.8 Errata A, II-8.3
	// Firmware File Media Device Path: PIWG Firmware File Device Path node
	buffer = append(buffer, createNode(MediaProtocolType, PiwgFirmwareFileSubType, FileGuid[:])...)

	// UEFI Specification, Release 2.10 Errata A, 10.3.1 Generic Device Path Structures,
	// Table 10.2: Device Path End Structure: End Entire Device Path node
	buffer = append(buffer, createNode(EndOfPathType, 0xff, []byte{})...)
	return buffer
}

func calculateEfiLoadOption() []byte {
	// UEFI Specification, Release 2.10 Errata A, 3.1.3 Load Options: EFI_LOAD_OPTION

	// attributes
	buffer := binary.LittleEndian.AppendUint32([]byte{}, uint32(LoadOptionActive|LoadOptionHidden|LoadOptionCategoryApp))

	// filepath list length
	filePathList := createFilePathList()
	buffer = binary.LittleEndian.AppendUint16(buffer, uint16(len(filePathList)))

	// description + null-byte
	for _, unit := range utf16.Encode([]rune("UiApp")) {
		buffer = binary.LittleEndian.AppendUint16(buffer, unit)
	}
	buffer = binary.LittleEndian.AppendUint16(buffer, 0)

	// file path list
	buffer = append(buffer, filePathList...)

	// optional data (there are none, so nothing to write)
	return buffer
}

func readEfiVariableFromFile(path string, efiGuid [16]byte) ([]byte, error) {

	// Read file with binary efi variable data. Variable data can either be with a
	// full UEFI_VARIABLE_DATA header or with a 4-byte efi variable attributes header
	// as written to /sys/firmware/efi/efivars
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read efi variable file: %w", err)
	}

	// Data in the format as written to /sys/firmware/efi/efivars has a 4-byte
	// efi variable attributes header followed by the variable data
	offset := uint64(4)

	// Check if the file starts with UEFI_VARIABLE_DATA header, which is not extended
	if len(data) > UefiVariableDataMinSize {
		if bytes.Equal(data[:16], efiGuid[:]) {
			nameLength := binary.LittleEndian.Uint64(data[16:])

			// In this case, adjust the offset to the start of the variable data
			// which is the minimum size, plus the length of the name, which is CHAR16
			offset = UefiVariableDataMinSize + (nameLength * 2)
		}
	}

	log.Tracef("Calculate EFI variable offset: %v", offset)

	if offset > uint64(len(data)) {
		return nil, fmt.Errorf("efi variable offset exceeds file: %d > %d", offset, len(data))
	}

	return data[offset:], nil

}
