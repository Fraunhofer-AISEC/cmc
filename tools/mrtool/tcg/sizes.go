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
	"fmt"
	"strconv"
	"strings"
)

// ParseRamSize accepts qemu-style sizes and converts it to uint64
func ParseRamSize(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty value")
	}

	mul := uint64(1)
	last := s[len(s)-1]
	if last == 'i' || last == 'I' {
		if len(s) < 2 {
			return 0, fmt.Errorf("missing unit before 'i'")
		}
		s = s[:len(s)-1]
		last = s[len(s)-1]
	}
	switch last {
	case 'K', 'k':
		mul = 1 << 10
	case 'M', 'm':
		mul = 1 << 20
	case 'G', 'g':
		mul = 1 << 30
	case 'T', 't':
		mul = 1 << 40
	default:
		if last < '0' || last > '9' {
			return 0, fmt.Errorf("unknown unit %q", string(last))
		}
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, err
		}
		return n, nil
	}
	n, err := strconv.ParseUint(s[:len(s)-1], 10, 64)
	if err != nil {
		return 0, err
	}
	return n * mul, nil
}

// QEMU q35 RAM layout constants. See qemu hw/i386/pc_q35.c pc_q35_init().
const (
	QemuQ35LowmemThreshold = 0xb0000000 // 2.75 GiB
	QemuQ35Lowmem          = 0x80000000 // 2 GiB
	QemuAbove4gMemStart    = 0x100000000
)

// QemuQ35RamSplit reproduces the qemu pc_q35 lowmem rule with default
// max-ram-below-4g: lowmem = 2 GiB when ram_size >= 2.75 GiB, else lowmem =
// ram_size (no above-4G chunk). Returns (below, above) chunk sizes in bytes.
func QemuQ35RamSplit(ramSize uint64) (below, above uint64) {
	below = uint64(QemuQ35Lowmem)
	if ramSize < QemuQ35LowmemThreshold {
		below = ramSize
	}
	if ramSize > below {
		above = ramSize - below
	}
	return below, above
}
