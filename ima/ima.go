// Copyright (c) 2021 Fraunhofer AISEC
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

package ima

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io/ioutil"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	SHA1_DIGEST_LEN   = 20
	SHA256_DIGEST_LEN = 32
	MAX_TCG_EVENT_LEN = 255
)

type Header struct {
	Pcr     int32
	Digest  [SHA1_DIGEST_LEN]byte
	NameLen uint32
}

type ImaTemplate struct {
	Header  Header
	Name    [MAX_TCG_EVENT_LEN + 1]byte
	Ptr     uint32
	DataLen uint32
	Data    []byte
}

func GetImaRuntimeDigests() ([][SHA256_DIGEST_LEN]byte, error) {
	data, err := ioutil.ReadFile("/sys/kernel/security/ima/binary_runtime_measurements")
	if err != nil {
		log.Error("Failed to load IMA runtime measurements from /sys/kernel/security/ima/binary_runtime_measurements - ", err)
		return nil, err
	}

	digests, err := parseImaRuntimeDigests(data)
	if err != nil {
		log.Error("Failed to parse IMA runtime digests - ", err)
		return nil, err
	}

	return digests, nil
}

func parseImaRuntimeDigests(data []byte) ([][SHA256_DIGEST_LEN]byte, error) {

	buf := bytes.NewBuffer(data)
	digests := make([][SHA256_DIGEST_LEN]byte, 0)

	for buf.Len() > 0 {
		header := Header{}
		err := binary.Read(buf, binary.LittleEndian, &header)
		if err != nil {
			log.Error("Error Reading binary data: ", err)
			return nil, err
		}

		name := make([]byte, header.NameLen)
		err = binary.Read(buf, binary.LittleEndian, name)

		var template ImaTemplate
		template.Header = header
		copy(template.Name[:], name)

		log.Trace("PCR: ", header.Pcr)
		log.Trace("Name: ", string(template.Name[:]))

		var len uint32
		if strings.Compare(string(template.Name[:]), "ima") == 0 {
			template.DataLen = SHA1_DIGEST_LEN + MAX_TCG_EVENT_LEN + 1
			len = SHA1_DIGEST_LEN
		} else {
			err = binary.Read(buf, binary.LittleEndian, &template.DataLen)
			if err != nil {
				log.Error("Error Reading binary data: ", err)
				return nil, err
			}
			len = template.DataLen
		}

		template.Data = make([]byte, len)
		err = binary.Read(buf, binary.LittleEndian, template.Data)
		if err != nil {
			log.Error("Error Reading binary data: ", err)
			return nil, err
		}

		if strings.Compare(string(template.Name[:]), "ima") == 0 {
			var fieldLen uint32
			binary.Read(buf, binary.LittleEndian, &fieldLen)

			addData := make([]byte, fieldLen)
			binary.Read(buf, binary.LittleEndian, addData)
			template.Data = append(template.Data, addData...)
		}

		// Even in case of SHA256 PCRs, the template hash from IMA is a
		// SHA1 hash and cannot be used. Instead, the SHA256 hash of the
		// template must be calculated manually
		digest := sha256.Sum256(template.Data)
		log.Trace("Sha256: ", hex.EncodeToString(digest[:]))

		digests = append(digests, digest)
	}

	return digests, nil
}
