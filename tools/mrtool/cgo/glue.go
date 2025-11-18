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

package cgo

/*
#cgo CFLAGS: -I${SRCDIR}
#cgo LDFLAGS: -lcrypto
#include "MeasureBootPeCoff.h"
*/
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/sirupsen/logrus"
)

type HashAlg int

const (
	SHA256 HashAlg = iota
	SHA384
	UNKNOWN
)

func MeasurePeImage(alg HashAlg, buf []byte) ([]byte, error) {

	l := logrus.GetLevel()
	if l == logrus.DebugLevel || l == logrus.TraceLevel {
		C.SetDebug()
	}

	var hash []byte

	switch alg {
	case SHA256:
		hash = make([]byte, 32)
		v := C.MeasurePeImageSha256(
			(*C.uint8_t)(unsafe.Pointer(&hash[0])),
			(*C.uint8_t)(unsafe.Pointer(&buf[0])),
			C.uint64_t(len(buf)),
		)
		if v != 0x0 {
			return nil, fmt.Errorf("failed to measure PE image. Error Code: %x", uint64(v))
		}
	case SHA384:
		hash = make([]byte, 48)
		v := C.MeasurePeImageSha384(
			(*C.uint8_t)(unsafe.Pointer(&hash[0])),
			(*C.uint8_t)(unsafe.Pointer(&buf[0])),
			C.uint64_t(len(buf)),
		)
		if v != 0x0 {
			return nil, fmt.Errorf("failed to measure PE image. Error Code: %x", uint64(v))
		}
	default:
		return nil, fmt.Errorf("Unknown hash algorithm %v", alg)
	}

	return hash[:], nil
}
