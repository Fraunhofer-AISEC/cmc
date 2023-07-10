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

package tpmdriver

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// Constants for digests and TCG Events
const (
	SHA1_DIGEST_LEN   = 20
	SHA256_DIGEST_LEN = 32
	MAX_TCG_EVENT_LEN = 1024
)

// Constants
var (
	EV_NO_ACTION = uint32(3)
)

// TPM2B_EVENT is a TPM event as specified by the TPM specificatoin
type TPM2B_EVENT struct {
	Size uint16
	Buf  []byte
}

// TCG_EVENT is a TCG Event as specified by the TPM specification
type TCG_EVENT struct {
	PcrIndex      uint32
	EventType     uint32
	Digest        [20]byte
	EventDataSize uint32
}

// GetBiosMeasurements retrieves the measurements recorded into
// the TPM PCRs by BIOS, UEFI and IPL. The file with the binary
// measurements (usually /sys/kernel/security/tpm0/binary_bios_measurements)
// must be specified
func GetBiosMeasurements(file string) ([]ar.ReferenceValue, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to load IMA runtime measurements from %v: %w", file, err)
	}

	digests, err := parseBiosMeasurements(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IMA runtime digests: %w", err)
	}

	return digests, nil
}

func parseBiosMeasurements(data []byte) ([]ar.ReferenceValue, error) {

	extends := make([]ar.ReferenceValue, 0)
	buf := bytes.NewBuffer(data)

	// Read initial TCG Event to detect event log format
	event := TCG_EVENT{}
	err := binary.Read(buf, binary.LittleEndian, &event)
	if err != nil {
		return nil, fmt.Errorf("failed to read initial binary data: %w", err)
	}

	log.Tracef("Event type: %v", event.EventType)

	// This means that the event log format version 2 is used
	if event.EventType != EV_NO_ACTION {
		return nil, errors.New("event log format version 1 not supported")
	}

	log.Trace("Detected event log format version 2")

	// TODO read the rest of the event log and fill events into 'extends' variable

	return extends, nil
}
