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

package ovmf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

var ErrFooterGuidNotFound = errors.New("OVMF table footer GUID not found")

const GuidTableFooterOffset = 0x30

var GuidTableFooterGuid = [16]byte{
	0xde, 0x82, 0xb5, 0x96, 0xb2, 0x1f, 0xf7, 0x45,
	0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d,
}

// FindGuidTableEntry walks the OVMF GUID table at the end of the binary and
// returns the data payload of the entry whose GUID matches the given target
func FindGuidTableEntry(ovmf []byte, guid []byte) ([]byte, error) {
	if len(ovmf) < GuidTableFooterOffset {
		return nil, fmt.Errorf("OVMF image too small (%v)", len(ovmf))
	}

	tableFooterOffset := len(ovmf) - GuidTableFooterOffset
	footerGuid := ovmf[tableFooterOffset : tableFooterOffset+16]

	if !bytes.Equal(footerGuid, GuidTableFooterGuid[:]) {
		return nil, ErrFooterGuidNotFound
	}

	ovmfTableOffset := tableFooterOffset - binary.Size(uint16(0)) - 16
	ovmfTableLength := int(binary.LittleEndian.Uint16(ovmf[ovmfTableOffset:])) - binary.Size(uint16(0))

	for count := 0; count < ovmfTableLength; {
		tableGuid := ovmf[ovmfTableOffset : ovmfTableOffset+16]
		length := int(binary.LittleEndian.Uint16(ovmf[ovmfTableOffset-binary.Size(uint16(0)):]))

		if !bytes.Equal(tableGuid, guid) {
			ovmfTableOffset -= length
			count += length
			continue
		}

		dataSize := length - binary.Size(uint16(0)) - 16
		dataStart := ovmfTableOffset - binary.Size(uint16(0)) - dataSize
		return ovmf[dataStart : dataStart+dataSize], nil
	}

	return nil, fmt.Errorf("GUID entry not found in OVMF table")
}
