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

package internal

import (
	"fmt"
)

type AkType byte

const (
	UNKNOWN = iota
	VCEK
	VLEK
)

func (t AkType) String() string {
	switch t {
	case VCEK:
		return "vcek"
	case VLEK:
		return "vlek"
	default:
		return "unknown"
	}
}

func GetAkType(keySelection uint32) (AkType, error) {
	arkey := (keySelection >> 2) & 0x7
	if arkey == 0 {
		log.Debug("VCEK is used to sign attestation report")
		return VCEK, nil
	} else if arkey == 1 {
		log.Debug("VLEK is used to sign attestation report")
		return VLEK, nil
	}
	return UNKNOWN, fmt.Errorf("unknown AK type %v", arkey)
}
