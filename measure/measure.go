// Copyright (c) 2024 Fraunhofer AISEC
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

package measure

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "measure")

type MeasureEntry struct {
	Pcr            int        `json:"pcr,omitempty" cbor:"0,keyasint,omitempty"`
	TemplateSha256 ar.HexByte `json:"templateSha256,omitempty" cbor:"1,keyasint,omitempty"`
	Name           string     `json:"name,omitempty" cbor:"2,keyasint,omitempty"`
	ConfigSha256   ar.HexByte `json:"configSha256,omitempty" cbor:"3,keyasint,omitempty"`
	RootfsSha256   ar.HexByte `json:"rootfsSha256,omitempty" cbor:"4,keyasint,omitempty"`
}

type MeasureConfig struct {
	Serializer ar.Serializer
	Pcr        int
	LogFile    string
	Driver     string
}

func Measure(name string, configSha256, rootfsSha256 []byte, mc *MeasureConfig) error {

	if mc == nil {
		return errors.New("internal error: measure config is nil")
	}

	// Hash config entry
	// TODO discuss if name is required
	// tbh := []byte(name)
	// tbh = append(tbh, configSha256...)
	tbh := []byte(configSha256)
	tbh = append(tbh, rootfsSha256...)

	hasher := sha256.New()
	hasher.Write(tbh)
	hash := hasher.Sum(nil)

	// Generate config entry
	entry := MeasureEntry{
		TemplateSha256: hash,
		Name:           name,
		ConfigSha256:   configSha256,
		RootfsSha256:   rootfsSha256,
	}

	if strings.EqualFold(mc.Driver, "tpm") {
		entry.Pcr = mc.Pcr
	}

	log.Tracef("Recording measurement %v: %v", name, hex.EncodeToString(entry.TemplateSha256))

	// Read the existing measurement list if it already exists
	var measureList []MeasureEntry
	if _, err := os.Stat(mc.LogFile); err == nil {
		data, err := os.ReadFile(mc.LogFile)
		if err != nil {
			return fmt.Errorf("failed to read measurement list: %w", err)
		}

		err = mc.Serializer.Unmarshal(data, &measureList)
		if err != nil {
			return fmt.Errorf("failed to unmarshal measurement list: %w", err)
		}
	}

	// Search the existing measurement list..
	found := false
	for _, e := range measureList {
		if bytes.Equal(e.TemplateSha256, entry.TemplateSha256) {
			found = true
			break
		}
	}

	// ..if the container was already measured, exit
	if found {
		log.Tracef("Measurement %v already exists, nothing to do", name)
		return nil
	}

	// ..otherwise append it to the measurement list and record the measurement
	measureList = append(measureList, entry)
	log.Tracef("Recorded measurement %v into measurement list", name)

	data, err := mc.Serializer.Marshal(measureList)
	if err != nil {
		return fmt.Errorf("failed to marshal measurement list: %w", err)
	}

	err = os.WriteFile(mc.LogFile, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write measurement list: %w", err)
	}

	// Write the entry to the specified driver, if any
	if strings.EqualFold(mc.Driver, "tpm") {
		addr, err := getTpmAddr()
		if err != nil {
			return fmt.Errorf("failed to get TPM path: %v", err)
		}

		rwc, err := tpm2.OpenTPM(addr)
		if err != nil {
			return fmt.Errorf("failed to open TPM%v: %w", addr, err)
		}
		defer rwc.Close()

		err = tpm2.PCRExtend(rwc, tpmutil.Handle(mc.Pcr), tpm2.AlgSHA256, entry.TemplateSha256, "")
		if err != nil {
			return fmt.Errorf("failed to extend PCR%v: %w", mc.Pcr, err)
		}

		log.Tracef("Recorded measurement %v into PCR%v", name, mc.Pcr)
	} else if strings.EqualFold(mc.Driver, "sw") {
		log.Tracef("Nothing to do for SW driver")
	} else {
		return fmt.Errorf("unknown driver '%v'", mc.Driver)
	}

	return nil
}

func getTpmAddr() (string, error) {
	// TODO more robust
	if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		return "/dev/tpmrm0", nil
	} else if _, err := os.Stat("/dev/tpm0"); err == nil {
		return "/dev/tpm0", nil
	} else {
		return "", errors.New("failed to find TPM device in /dev")
	}
}
