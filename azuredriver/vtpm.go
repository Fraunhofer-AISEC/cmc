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

package azuredriver

import (
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/tpmdriver"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	nvIndexAkCert          = tpmutil.Handle(0x01C101D0) // NV index to read
	nvIndexTdReport        = tpmutil.Handle(0x01400001) // NV index to read attestation report from
	nvIndexTdUserData      = tpmutil.Handle(0x01400002) // NV index to supply attestation report user data
	akHandle               = tpmutil.Handle(0x81000003)
	tpmResourceManagerPath = "/dev/tpmrm0"
	tpmDevicePath          = "/dev/tpm0"
)

func (azure *Azure) GetVtpmMeasurement(pcrs []int, nonce []byte) (ar.Measurement, error) {

	log.Debug("Collecting Azure vTPM measurements")

	quote, sig, pcrValues, err := GetVtpmQuote(pcrs, nonce)
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to get vTPM quote: %w", err)
	}

	artifacts, err := tpmdriver.GetEventLogs(azure.Serializer,
		azure.MeasurementLog, azure.Ima, azure.ctrLog,
		azure.pcrs, azure.ImaPcr, azure.CtrPcr,
		azure.CtrLog, pcrValues)
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to get event logs: %w", err)
	}

	tpmAk, err := GetVtpmAkCert()
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to get vTPM AK cert: %w", err)
	}

	tm := ar.Measurement{
		Type:      "Azure vTPM Measurement",
		Evidence:  quote,
		Signature: sig,
		Certs:     [][]byte{tpmAk},
		Artifacts: artifacts,
	}

	for _, elem := range tm.Artifacts {
		for _, event := range elem.Events {
			log.Tracef("PCR%v %v: %v", elem.Index, elem.Type, hex.EncodeToString(event.Sha256))
		}
	}
	log.Debug("Quote: ", hex.EncodeToString(tm.Evidence))
	log.Debug("Signature: ", hex.EncodeToString(tm.Signature))

	return tm, nil
}

func GetVtpmQuote(pcrs []int, nonce []byte) ([]byte, []byte, map[int][]byte, error) {

	azureAkHandle := tpmutil.Handle(akHandle)

	log.Debugf("Fetching quote with nonce %v...", hex.EncodeToString(nonce))

	sel := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: pcrs,
	}

	tpm, err := OpenTpm()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to open TPM device %s: %w", tpmDevicePath, err)
	}
	defer tpm.Close()

	quote, sig, err := tpm2.Quote(tpm, azureAkHandle, "", "", nonce, sel, tpm2.AlgNull)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get quote: %w", err)
	}

	rawSig, err := tpmutil.Pack(sig.Alg, sig.RSA.HashAlg, sig.RSA.Signature)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to pack signature: %w", err)
	}

	log.Debugf("Successfully fetched quote")

	pcrValues, err := ReadPcrs(tpm, tpm2.AlgSHA256)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read PCRs: %w", err)
	}

	return quote, rawSig, pcrValues, nil
}

func GetVtpmAkCert() ([]byte, error) {

	log.Debugf("Fetching AK cert from vTPM NVIndex %x...", nvIndexAkCert)

	tpm, err := OpenTpm()
	if err != nil {
		return nil, fmt.Errorf("unable to open TPM device %s: %w", tpmDevicePath, err)
	}
	defer tpm.Close()

	// Read NV index contents
	data, err := tpm2.NVReadEx(tpm, nvIndexAkCert, tpm2.HandleOwner, "", 0)
	if err != nil {
		return nil, fmt.Errorf("NVRead failed: %w", err)
	}

	// Extract only the first ASN.1 object to get only the actual certificate
	var val asn1.RawValue
	rest, err := asn1.Unmarshal(data, &val)
	if err != nil {
		return nil, fmt.Errorf("asn1.Unmarshal: %w", err)
	}
	cert := data[:len(data)-len(rest)]

	log.Debugf("Successfully fetched vTPM AK cert")

	return cert, nil
}

func ReadPcrs(tpm io.ReadWriter, alg tpm2.Algorithm) (map[int][]byte, error) {
	numPcrs := 24
	out := map[int][]byte{}

	log.Debugf("Reading PCRs...")

	for i := 0; i < numPcrs; i++ {
		sel := tpm2.PCRSelection{Hash: alg}
		for pcr := 0; pcr < numPcrs; pcr++ {
			if _, present := out[pcr]; !present {
				sel.PCRs = append(sel.PCRs, pcr)
			}
		}

		ret, err := tpm2.ReadPCRs(tpm, sel)
		if err != nil {
			return nil, fmt.Errorf("failed to read PCRs: %w", err)
		}

		for pcr, digest := range ret {
			out[pcr] = digest
		}
		if len(out) == numPcrs {
			break
		}
	}

	if len(out) != numPcrs {
		return nil, fmt.Errorf("failed to read PCRs. Readf %v, expected %v", len(out), numPcrs)
	}

	log.Debugf("Successfully read PCRs")

	return out, nil
}

func OpenTpm() (*os.File, error) {

	dev, err := GetTpmDevicePath()
	if err != nil {
		return nil, err
	}

	return os.OpenFile(dev, os.O_RDWR, 0)
}

func GetTpmDevicePath() (string, error) {
	if _, err := os.Stat(tpmResourceManagerPath); err == nil {
		return tpmResourceManagerPath, nil
	} else if _, err := os.Stat(tpmDevicePath); err == nil {
		return tpmDevicePath, nil
	} else {
		return "", errors.New("failed to find TPM device in /dev")
	}
}
