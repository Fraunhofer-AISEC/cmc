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
	"os"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers/tpmdriver"
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

func (azure *Azure) GetVtpmEvidence(nonce []byte) (*ar.Evidence, error) {

	log.Debug("Collecting Azure vTPM quote")

	quote, sig, err := GetVtpmQuote(azure.pcrs, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get vTPM quote: %w", err)
	}

	log.Tracef("Quote: %x", quote)
	log.Tracef("Signature: %x", sig)

	evidence := &ar.Evidence{
		Type:      ar.TYPE_EVIDENCE_AZURE_TPM,
		Data:      quote,
		Signature: sig,
	}

	return evidence, nil
}

func (azure *Azure) GetVtpmCollateral() (*ar.Collateral, error) {

	artifacts := make([]ar.Artifact, 0)

	if azure.MeasurementLogs {
		events, err := tpmdriver.GetEventLogs(azure.pcrs, azure.ctrLog, azure.CtrLog)
		if err != nil {
			return nil, fmt.Errorf("failed to get event logs: %w", err)
		}
		artifacts = append(artifacts, events...)
	} else {
		pcrs, err := azure.GetVtpmPcrs()
		if err != nil {
			return nil, fmt.Errorf("failed to get prs: %w", err)
		}
		artifacts = append(artifacts, pcrs...)
	}

	// Just for logging
	for _, elem := range artifacts {
		for _, event := range elem.Events {
			log.Tracef("PCR%v %v: %v", elem.Index, elem.Type, hex.EncodeToString(event.Sha256))
		}
	}

	tpmAk, err := GetVtpmAkCert()
	if err != nil {
		return nil, fmt.Errorf("failed to get vTPM AK cert: %w", err)
	}

	collateral := &ar.Collateral{
		Type:      ar.TYPE_EVIDENCE_AZURE_TPM,
		Certs:     [][]byte{tpmAk},
		Artifacts: artifacts,
	}

	return collateral, nil
}

func GetVtpmQuote(pcrs []int, nonce []byte) ([]byte, []byte, error) {

	azureAkHandle := tpmutil.Handle(akHandle)

	log.Debugf("Fetching quote with nonce %v...", hex.EncodeToString(nonce))

	sel := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: pcrs,
	}

	tpm, err := OpenTpm()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to open TPM device %s: %w", tpmDevicePath, err)
	}
	defer tpm.Close()

	quote, sig, err := tpm2.Quote(tpm, azureAkHandle, "", "", nonce, sel, tpm2.AlgNull)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get quote: %w", err)
	}

	rawSig, err := tpmutil.Pack(sig.Alg, sig.RSA.HashAlg, sig.RSA.Signature)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to pack signature: %w", err)
	}

	log.Debugf("Successfully fetched quote")

	return quote, rawSig, nil
}

func (azure *Azure) GetVtpmPcrs() ([]ar.Artifact, error) {

	log.Debugf("Reading PCRs...")

	artifacts := make([]ar.Artifact, 0, len(azure.pcrs))

	tpm, err := OpenTpm()
	if err != nil {
		return nil, fmt.Errorf("unable to open TPM device %s: %w", tpmDevicePath, err)
	}
	defer tpm.Close()

	// ReadPCRs cannot read at most 8 PCRs at the same time
	for _, index := range azure.pcrs {
		sel := tpm2.PCRSelection{
			Hash: tpm2.AlgSHA256,
			PCRs: []int{index},
		}

		pcrs, err := tpm2.ReadPCRs(tpm, sel)
		if err != nil {
			return nil, fmt.Errorf("failed to read PCR: %w", err)
		}

		for pcr, digest := range pcrs {
			artifacts = append(artifacts, ar.Artifact{
				Type:  ar.TYPE_PCR_SUMMARY,
				Index: pcr,
				Events: []ar.MeasureEvent{
					{
						Sha256: digest,
					},
				},
			})
		}
	}

	log.Debugf("Successfully read PCRs")

	return artifacts, nil
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
