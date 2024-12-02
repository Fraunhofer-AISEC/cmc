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

	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "measure")

type MeasureConfig struct {
	Serializer ar.Serializer
	Pcr        int
	LogFile    string
	ExtLog     bool
	Driver     string
}

func Measure(req *api.MeasureRequest, mc *MeasureConfig) error {

	if mc == nil {
		return errors.New("internal error: measure config is nil")
	}

	// Hash config entry
	tbh := []byte(req.ConfigSha256)
	tbh = append(tbh, req.RootfsSha256...)

	hasher := sha256.New()
	hasher.Write(tbh)
	templateHash := hasher.Sum(nil)

	// Generate config entry
	entry := ar.MeasureEvent{
		Sha256:    templateHash,
		EventName: req.Name,
		CtrData: &ar.CtrData{
			ConfigSha256: req.ConfigSha256,
			RootfsSha256: req.RootfsSha256,
			OciSpec:      req.OciSpec,
		},
	}

	log.Tracef("Recording measurement %v: %v", req.Name, hex.EncodeToString(entry.Sha256))

	// Read the existing measurement list if it already exists
	var measureList []ar.MeasureEvent
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
		if bytes.Equal(e.Sha256, entry.Sha256) {
			found = true
			break
		}
	}

	// ..if the container was already measured, exit
	if found {
		log.Tracef("Measurement %v already exists, nothing to do", req.Name)
		return nil
	}

	// ..otherwise append it to the measurement list and record the measurement
	measureList = append(measureList, entry)
	log.Tracef("Recorded measurement %v into measurement list", req.Name)

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

		err = tpm2.PCRExtend(rwc, tpmutil.Handle(mc.Pcr), tpm2.AlgSHA256, entry.Sha256, "")
		if err != nil {
			return fmt.Errorf("failed to extend PCR%v: %w", mc.Pcr, err)
		}

		log.Tracef("Recorded measurement %v into PCR%v", req.Name, mc.Pcr)
	} else if strings.EqualFold(mc.Driver, "sw") {
		log.Tracef("Nothing to do for SW driver")
	} else {
		return fmt.Errorf("unknown driver '%v'", mc.Driver)
	}

	return nil
}

func getTpmAddr() (string, error) {
	if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		return "/dev/tpmrm0", nil
	} else if _, err := os.Stat("/dev/tpm0"); err == nil {
		return "/dev/tpm0", nil
	} else {
		return "", errors.New("failed to find TPM device in /dev")
	}
}
