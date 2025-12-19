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
	"fmt"
	"io"
)

// UEFI Spec 2.10 Section 38.4.1:
// TPM PCR Index | CC Measurement Register Index | TDX-measurement register
// 0             |   0                           |   MRTD
// 1, 7          |   1                           |   RTMR[0]
// 2~6           |   2                           |   RTMR[1]
// 8~15          |   3                           |   RTMR[2]
const (
	MR_LEN       = 6
	INDEX_MRTD   = 0
	INDEX_RTMR0  = 1
	INDEX_RTMR1  = 2
	INDEX_RTMR2  = 3
	INDEX_RTMR3  = 4
	INDEX_MRSEAM = 5 // Additional reference value, not part of UEFI spec
)

func IndexToMr(ta TrustAnchor, index int) string {

	switch ta {
	case TPM:
		return fmt.Sprintf("PCR%v", index)
	case TDX:
		switch index {
		case INDEX_MRTD:
			return "MRTD"
		case INDEX_RTMR0:
			return "RTMR0"
		case INDEX_RTMR1:
			return "RTMR1"
		case INDEX_RTMR2:
			return "RTMR2"
		case INDEX_RTMR3:
			return "RTMR3"
		case INDEX_MRSEAM:
			return "MRSEAM"
		default:
			return "Unknown"
		}
	default:
		return "Unknown"
	}

}

func ReadStructAt[T any](r io.ReaderAt, offset int64, out *T) error {
	sr := io.NewSectionReader(r, offset, int64(binary.Size(out)))
	return binary.Read(sr, binary.LittleEndian, out)
}

type TrustAnchor uint

const (
	TPM TrustAnchor = 1 + iota
	TDX
)

func (t TrustAnchor) RefvalString() string {
	switch t {
	case TPM:
		return "TPM Reference Value"
	case TDX:
		return "TDX Reference Value"
	default:
		return fmt.Sprintf("Unknown Reference Value (%v)", t)
	}
}
