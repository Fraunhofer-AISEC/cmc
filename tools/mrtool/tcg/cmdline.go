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

func MeasureCmdline(alg crypto.Hash, ta TrustAnchor, digest []byte, refvals []*ar.ReferenceValue,
	index int, cmdline, eventType string, zeros int, stripLf, appendInitrd bool,
) ([]byte, []*ar.ReferenceValue, error) {

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

	// OvmfPkg/Library/X86QemuLoadImageLib/X86QemuLoadImageLib.c#L570
	// OVMF appends initrd=initrd if initial ramdisk was specified
	if appendInitrd {
		cmdLineStr = fmt.Sprintf("%s initrd=initrd", cmdLineStr)
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

	return digest, []*ar.ReferenceValue{refval}, nil
}

func MeasureCmdlineNarrow(alg crypto.Hash, ta TrustAnchor, digest []byte,
	refvals []*ar.ReferenceValue, index int, cmdline, eventType string, zeros int, stripLf,
	appendInitrd bool,
) ([]byte, []*ar.ReferenceValue, error) {

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

	return digest, []*ar.ReferenceValue{refval}, nil
}
