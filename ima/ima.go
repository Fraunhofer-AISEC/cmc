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
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

var log = logrus.WithField("service", "ima")

// Constants for digests and TCG Events
const (
	SHA1_DIGEST_LEN   = 20
	SHA256_DIGEST_LEN = 32
	MAX_TCG_EVENT_LEN = 255
)

type header struct {
	Pcr     int32
	Digest  [SHA1_DIGEST_LEN]byte
	NameLen uint32
}

type imaTemplate struct {
	header  header
	Name    [MAX_TCG_EVENT_LEN + 1]byte
	Ptr     uint32
	DataLen uint32
	Data    []byte
}

// GetImaRuntimeDigests returns all hashes extended by the IMA into the TPM
// IMA PCR as read from the sysfs
func GetImaRuntimeDigests() ([]ar.MeasureEvent, error) {
	file := "/sys/kernel/security/ima/binary_runtime_measurements"
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	digests, err := parseImaRuntimeDigests(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IMA runtime digests: %w", err)
	}

	return digests, nil
}

func parseImaRuntimeDigests(data []byte) ([]ar.MeasureEvent, error) {

	buf := bytes.NewBuffer(data)
	events := make([]ar.MeasureEvent, 0)

	for buf.Len() > 0 {
		header := header{}
		err := binary.Read(buf, binary.LittleEndian, &header)
		if err != nil {
			return nil, fmt.Errorf("error reading binary data: %w", err)
		}

		name := make([]byte, header.NameLen)
		err = binary.Read(buf, binary.LittleEndian, name)
		if err != nil {
			return nil, fmt.Errorf("error reading binary data: %w", err)
		}

		var template imaTemplate
		template.header = header
		copy(template.Name[:], name)

		var length uint32
		if strings.Compare(string(template.Name[:]), "ima") == 0 {
			template.DataLen = SHA1_DIGEST_LEN + MAX_TCG_EVENT_LEN + 1
			length = SHA1_DIGEST_LEN
		} else {
			err = binary.Read(buf, binary.LittleEndian, &template.DataLen)
			if err != nil {
				return nil, fmt.Errorf("error reading binary data: %w", err)
			}
			length = template.DataLen
		}

		template.Data = make([]byte, length)
		err = binary.Read(buf, binary.LittleEndian, template.Data)
		if err != nil {
			return nil, fmt.Errorf("error reading binary data: %w", err)
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

		// Parse the template data to retrieve additional information
		_, eventName, err := parseTemplateData(&template)
		if err != nil {
			log.Tracef("Failed to parse additional template data: %v", err)
		}

		event := ar.MeasureEvent{
			Sha256:    digest[:],
			EventName: eventName,
		}

		log.Tracef("Parsed IMA PCR%v %v event %v", header.Pcr,
			string(template.Name[:template.header.NameLen]), eventName)

		events = append(events, event)
	}

	return events, nil
}

func parseTemplateData(tmpl *imaTemplate) ([]byte, string, error) {

	if !bytes.Equal(tmpl.Name[:tmpl.header.NameLen], []byte("ima-ng")) &&
		!bytes.Equal(tmpl.Name[:tmpl.header.NameLen], []byte("ima-sig")) {
		return nil, "", fmt.Errorf("template %v parsing additional information not supported", tmpl.Name[:tmpl.header.NameLen])
	}

	var tmplDigestLen uint32
	buf := bytes.NewBuffer(tmpl.Data)
	err := binary.Read(buf, binary.LittleEndian, &tmplDigestLen)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read digest length from template: %w", err)
	}

	tmplDigest := make([]byte, tmplDigestLen)
	err = binary.Read(buf, binary.LittleEndian, tmplDigest)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read digest from template: %w", err)
	}

	var tmplPathLen uint32
	err = binary.Read(buf, binary.LittleEndian, &tmplPathLen)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read digest length from template: %w", err)
	}

	tmplPath := make([]byte, tmplPathLen)
	err = binary.Read(buf, binary.LittleEndian, tmplPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read path from template: %w", err)
	}
	// Strip the path from the parsed \0 byte
	tmplPath = tmplPath[:len(tmplPath)-1]

	return tmplDigest, string(tmplPath), nil
}
