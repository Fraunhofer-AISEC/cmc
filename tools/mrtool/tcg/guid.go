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
)

// EfiGuid represents a GUID/UUID.
type EfiGuid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]uint8
}

var (
	LzmaDecompressGuid      = EfiGuid{0xEE4E5898, 0x3914, 0x4259, [8]byte{0x9D, 0x6E, 0xDC, 0x7B, 0xD7, 0x94, 0x03, 0xCF}}
	OvmfPlatformInfoHobGuid = EfiGuid{0xdec9b486, 0x1f16, 0x47c7, [8]byte{0x8f, 0x68, 0xdf, 0x1a, 0x41, 0x88, 0x8b, 0xa5}}
	EfiFirmwareFfs2Guid     = EfiGuid{0x8c8ce578, 0x8a3d, 0x4f1c, [8]byte{0x99, 0x35, 0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3}}
)

func (guid EfiGuid) Bytes() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, guid)
	return buf.Bytes()
}

func (guid EfiGuid) String() string {
	return fmt.Sprintf("%v-%v-%v-%v-%v-%v-%v-%v-%v-%v-%v", guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7])
}

func ParseGuid(data []byte) EfiGuid {
	var guid EfiGuid
	binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &guid)
	return guid
}

func GuidsEqual(g1, g2 *EfiGuid) bool {
	return bytes.Equal(g1.Bytes(), g2.Bytes())
}
