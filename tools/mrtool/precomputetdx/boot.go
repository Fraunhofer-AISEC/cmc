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
	"os"
	"strconv"
	"unicode/utf16"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/tools/mrtool/tcg"
)

var (
	EfiGlobalVariableGuid        = [16]byte{0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}
	EfiImageSecurityDatabaseGuid = [16]byte{0xcb, 0xb2, 0x19, 0xd7, 0x3a, 0x3d, 0x96, 0x45, 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f}
	FvNameGuid                   = [16]byte{0xc9, 0xbd, 0xb8, 0x7c, 0xeb, 0xf8, 0x34, 0x4f, 0xaa, 0xea, 0x3e, 0xe4, 0xaf, 0x65, 0x16, 0xa1}
	FileGuid                     = [16]byte{0x21, 0xaa, 0x2c, 0x46, 0x14, 0x76, 0x03, 0x45, 0x83, 0x6e, 0x8a, 0xb6, 0xf4, 0x66, 0x23, 0x31}
)

const (
	LoadOptionActive      = (1 << 0)
	LoadOptionHidden      = (1 << 3)
	LoadOptionCategoryApp = (1 << 8)

	MediaProtocolType         = 4
	EndOfPathType             = 0x7f
	PiwgFirmwareFileSubType   = 6
	piwgFirmwareVolumeSubType = 7
)

type SecBootVariableType struct {
	EventType    string
	VariableName string
	VendorGuid   [16]byte
	Path         string
	Data         []byte
}

//
//	UEFI_VARIABLE_DATA:
//	GUID VariableName
//	UINT64 UnicodeNameLength
//	UINT64 VariableDataLength
//	CHAR16[...] UnicodeName
//	INT8[...] VariableData
//

func measureVariable(val SecBootVariableType) ([sha512.Size384]byte, error) {
	var err error

	data := val.Data
	if val.Path != "" {
		data, err = os.ReadFile(val.Path)
		if err != nil {
			return [sha512.Size384]byte{}, fmt.Errorf("failed to read variable file: %w", err)
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

	return sha512.Sum384(buffer), nil
}

func MeasureSecureBootVariables(digest []byte, refvals []*ar.ReferenceValue, index int, secureBoot, pk, kek, db, dbx string) ([]byte, []*ar.ReferenceValue, error) {
	vars := []SecBootVariableType{
		SecBootVariableType{EventType: "EV_EFI_VARIABLE_DRIVER_CONFIG", VariableName: "SecureBoot", VendorGuid: EfiGlobalVariableGuid, Path: secureBoot},
		SecBootVariableType{EventType: "EV_EFI_VARIABLE_DRIVER_CONFIG", VariableName: "PK", VendorGuid: EfiGlobalVariableGuid, Path: pk},
		SecBootVariableType{EventType: "EV_EFI_VARIABLE_DRIVER_CONFIG", VariableName: "KEK", VendorGuid: EfiGlobalVariableGuid, Path: kek},
		SecBootVariableType{EventType: "EV_EFI_VARIABLE_DRIVER_CONFIG", VariableName: "db", VendorGuid: EfiImageSecurityDatabaseGuid, Path: db},
		SecBootVariableType{EventType: "EV_EFI_VARIABLE_DRIVER_CONFIG", VariableName: "dbx", VendorGuid: EfiImageSecurityDatabaseGuid, Path: dbx},
	}

	for _, val := range vars {
		varHash, err := measureVariable(val)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure variable: %w", err)
		}

		digest = internal.ExtendSha384(digest, varHash[:])
		refvals = append(refvals, &ar.ReferenceValue{
			Type:        "TDX Reference Value",
			SubType:     val.EventType,
			Index:       index,
			Sha384:      varHash[:],
			Description: fmt.Sprintf("%v: %v", tcg.IndexToMr(index), val.VariableName),
		})
	}

	return digest, refvals, nil
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

func CalculateEfiBootVars(digest []byte, refvals []*ar.ReferenceValue, index int, bootOrder []string, bootXxxx []string) ([]byte, []*ar.ReferenceValue, error) {
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
	bootOrderHash := sha512.Sum384(bootOrderSerialized)

	digest = internal.ExtendSha384(digest, bootOrderHash[:])
	refvals = append(refvals, &ar.ReferenceValue{
		Type:        "TDX Reference Value",
		SubType:     "EV_EFI_VARIABLE_BOOT",
		Index:       index,
		Sha384:      bootOrderHash[:],
		Description: fmt.Sprintf("%v: VariableName - BootOrder, VendorGuid - 8BE4DF61-93CA-11D2-AA0D-00E098032B8C", tcg.IndexToMr(index)),
	})

	// Default EV_EFI_VARIABLE_BOOT Boot0000 variable
	if len(bootXxxx) == 0 {
		efiVariableBoot0000 := calculateEfiLoadOption()
		dataHash := sha512.Sum384(efiVariableBoot0000)

		digest = internal.ExtendSha384(digest, dataHash[:])
		refvals = append(refvals, &ar.ReferenceValue{
			Type:        "TDX Reference Value",
			SubType:     "EV_EFI_VARIABLE_BOOT",
			Index:       index,
			Sha384:      dataHash[:],
			Description: fmt.Sprintf("%v: VariableName - Boot0000, VendorGuid - 8BE4DF61-93CA-11D2-AA0D-00E098032B8C", tcg.IndexToMr(index)),
		})
	} else {
		for _, path := range bootXxxx {
			// Read file with binary efi variable data. Variable data can either be with a
			// full UEFI_VARIABLE_DATA header or with a 4-byte efi variable attributes header
			// as written to /sys/firmware/efi/efivars
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read bootxxxx file: %w", err)
			}

			// Data in the format as written to /sys/firmware/efi/efivars has a 4-byte
			// efi variable attributes header
			offset := uint64(4)

			// Check if the file starts with UEFI_VARIABLE_DATA header, which is not extended
			if len(data) > 16+8+8 {
				if bytes.Equal(data[0:16], EfiGlobalVariableGuid[:]) {
					nameLength := binary.LittleEndian.Uint64(data[16:])
					offset = 16 + 8 + 8 + nameLength
				}
			}

			if offset > uint64(len(data)) {
				return nil, nil, fmt.Errorf("data offset in bootxxxx outside of file: %d > %d", offset, len(data))
			}
			dataHash := sha512.Sum384(data[offset:])

			digest = internal.ExtendSha384(digest, dataHash[:])
			refvals = append(refvals, &ar.ReferenceValue{
				Type:        "TDX Reference Value",
				SubType:     "EV_EFI_VARIABLE_BOOT",
				Index:       index,
				Sha384:      dataHash[:],
				Description: fmt.Sprintf("%v: VariableName - Boot####, VendorGuid - 8BE4DF61-93CA-11D2-AA0D-00E098032B8C", tcg.IndexToMr(index)),
			})
		}
	}

	return digest, refvals, nil
}
