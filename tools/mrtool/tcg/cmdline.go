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
	"crypto"
	"encoding/binary"
	"fmt"
	"os"
	"unicode/utf16"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// MeasureKernelHandoff measures the artifacts the firmware hands over to the kernel into
// PCR9/RTMR2: the UEFI LoadOptions carrying the command line and, if present, the initrd.
//
// EDK2 records the LoadOptions of a chainloaded kernel twice over the same digest: once as
// EV_IPL and once as an EV_EVENT_TAG tagged 0x8f3b22ed (LOADED_IMAGE::LoadOptions). A kernel
// loaded by the firmware itself only gets the EV_EVENT_TAG, see Conf.Chainloaded. The initrd is
// measured as an EV_EVENT_TAG tagged 0x8f3b22ec (Linux initrd) in both cases, as EDK2 serves it
// to the kernel over LoadFile2 either way. The tags are event data only and do not enter the
// digests.
func (c *Conf) MeasureKernelHandoff(alg crypto.Hash, ta TrustAnchor, digest []byte,
	refvals []*ar.Component, index int,
) ([]byte, []*ar.Component, error) {

	var err error

	if c.Cmdline != "" {
		if c.Chainloaded() {
			digest, refvals, err = MeasureCmdline(alg, ta, digest, refvals, index, c.Cmdline,
				"EV_IPL", c.AddZeros, c.StripNewline, c.InitrdOption)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to measure load options: %w", err)
			}
		}

		digest, refvals, err = MeasureCmdline(alg, ta, digest, refvals, index, c.Cmdline,
			"EV_EVENT_TAG", c.AddZeros, c.StripNewline, c.InitrdOption)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure cmdline: %w", err)
		}
	}

	if c.Initrd != "" {
		digest, refvals, err = MeasureFile(alg, ta, "EV_EVENT_TAG", digest, refvals, index,
			c.Initrd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to measure initrd: %w", err)
		}
	}

	return digest, refvals, nil
}

func MeasureCmdline(alg crypto.Hash, ta TrustAnchor, digest []byte, refvals []*ar.Component,
	index int, cmdline, eventType string, zeros int, stripLf bool, initrdOption InitrdOption,
) ([]byte, []*ar.Component, error) {

	// Read the commandline
	cmdLineData, err := os.ReadFile(cmdline)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read commandline: %w", err)
	}

	// sanitize the data
	if stripLf && cmdLineData[len(cmdLineData)-1] == '\n' {
		cmdLineData = cmdLineData[:len(cmdLineData)-1]
	}

	// interpret the cmdline as utf-8
	cmdLineStr := string(cmdLineData)

	// OvmfPkg/Library/{X86,Generic}QemuLoadImageLib/*QemuLoadImageLib.c: OVMF injects
	// initrd=initrd when an initial ramdisk is provided. Older edk2 appends it as a
	// suffix (" initrd=initrd"), newer edk2 (post-reorder) inserts it as a prefix
	// ("initrd=initrd ").
	switch initrdOption {
	case InitrdOptionPrefix:
		cmdLineStr = "initrd=initrd " + cmdLineStr
	case InitrdOptionSuffix:
		cmdLineStr = cmdLineStr + " initrd=initrd"
	case InitrdOptionNone:
	}

	// Interpret bytes as ascii/utf-8 and encode as utf-16
	utf16Line := utf16.Encode([]rune(cmdLineStr))
	utf16Line = append(utf16Line, make([]uint16, zeros)...)

	// Add the final hash
	buffer, err := binary.Append(nil, binary.LittleEndian, utf16Line)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cmdline buffer: %w", err)
	}

	refval, digest, err := CreateExtendRefval(alg, ta, index, digest, buffer, eventType, cmdLineStr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create reference value: %w", err)
	}

	return digest, append(refvals, refval), nil
}

func MeasureCmdlineNarrow(alg crypto.Hash, ta TrustAnchor, digest []byte,
	refvals []*ar.Component, index int, cmdline, eventType string, zeros int, stripLf bool,
) ([]byte, []*ar.Component, error) {

	// Read the commandline
	cmdLineData, err := os.ReadFile(cmdline)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read commandline: %w", err)
	}

	// Sanitize the data
	if stripLf && cmdLineData[len(cmdLineData)-1] == '\n' {
		cmdLineData = cmdLineData[:len(cmdLineData)-1]
	}
	cmdLineData = append(cmdLineData, make([]byte, zeros)...)

	// Add the final hash
	buffer, err := binary.Append(nil, binary.LittleEndian, cmdLineData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cmdline buffer: %w", err)
	}

	refval, digest, err := CreateExtendRefval(alg, ta, index, digest, buffer, eventType,
		string(cmdLineData))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create reference value: %w", err)
	}

	return digest, append(refvals, refval), nil
}
