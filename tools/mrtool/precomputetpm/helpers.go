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

package precomputetpm

import (
	"fmt"
	"os"
)

func detectDriverFileType(file string) (DriverFileType, error) {

	f, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	buf := make([]byte, 2)
	if _, err := f.Read(buf); err != nil {
		log.Fatal(err)
	}

	switch {
	case buf[0] == 0x4D && buf[1] == 0x5A:
		log.Debug("Detected file type: PE/COFF")
		return PECOFF, nil
	case buf[0] == 0x55 && buf[1] == 0xAA:
		log.Debug("Detected file type: Option ROM")
		return OptionROM, nil
	default:
		return Unknown, fmt.Errorf("unknown driver file type %02x %02x", buf[0], buf[1])
	}

}
