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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
)

type KernelSetupHdr struct {
	NotImplemented [0x210]uint8 `json:"notImplemented"`
	TypeOfLoader   uint8        `json:"typeOfLoader"`
	LoadFlags      uint8        `json:"loadFlags"`
	SetupMoveSize  uint16       `json:"setupMoveSize"`
	Code32Start    uint32       `json:"code32Start"`
	RamdiskImage   uint32       `json:"ramdiskImage"`
	RamdiskSize    uint32       `json:"ramdiskSize"`
	BootsectKludge uint32       `json:"bootsectKludge"`
	HeapEndPtr     uint16       `json:"heapEndPtr"`
	ExtLoaderVer   uint8        `json:"extLoaderVer"`
	ExtLoaderType  uint8        `json:"extLoaderType"`
	CmdLinePtr     uint32       `json:"cmdLinePtr"`
	RamdiskMax     uint32       `json:"ramdiskMax"`
}

func LoadKernelSetupHeader(config string) (*KernelSetupHdr, error) {
	data, err := os.ReadFile(config)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}

	hdr := new(KernelSetupHdr)
	err = json.Unmarshal(data, hdr)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}

	return hdr, nil
}

func PrepareKernel(kernel []byte, hdr *KernelSetupHdr) error {

	const hdrSize = 0x230 // end of RamdiskMax (0x22C + 4)

	if len(kernel) < hdrSize {
		return fmt.Errorf("kernel image too small")
	}

	// Offsets based on the C packed struct
	kernel[0x210] = hdr.TypeOfLoader
	kernel[0x211] = hdr.LoadFlags

	binary.LittleEndian.PutUint16(kernel[0x212:], hdr.SetupMoveSize)
	binary.LittleEndian.PutUint32(kernel[0x214:], hdr.Code32Start)
	binary.LittleEndian.PutUint32(kernel[0x218:], hdr.RamdiskImage)
	binary.LittleEndian.PutUint32(kernel[0x21C:], hdr.RamdiskSize)

	binary.LittleEndian.PutUint32(kernel[0x220:], hdr.BootsectKludge)
	binary.LittleEndian.PutUint16(kernel[0x224:], hdr.HeapEndPtr)

	kernel[0x226] = hdr.ExtLoaderVer
	kernel[0x227] = hdr.ExtLoaderType

	binary.LittleEndian.PutUint32(kernel[0x228:], hdr.CmdLinePtr)

	// Do not set
	// binary.LittleEndian.PutUint32(kernel[0x22C:], hdr.RamdiskMax)

	return nil
}
