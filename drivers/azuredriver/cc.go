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
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/verifier"

	"github.com/google/go-tdx-guest/pcs"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	imdsEndpoint = "http://169.254.169.254/acc"
	quotePath    = "/tdquote"
)

func GetCcMeasurement(nonce []byte, akchain []*x509.Certificate) (ar.Measurement, error) {

	log.Debugf("Retrieving hardware report (SNP report or TDX quote)...")

	err := UpdateAzureUserData(nonce)
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to update azure user data")
	}

	var reportType verifier.AzureReportType
	var reportRaw []byte
	var rtdataRaw []byte
	success := false
	for i := 0; i < 3; i++ {

		data, err := GetAzureReport()
		if err != nil {
			return ar.Measurement{}, fmt.Errorf("failed to get azure report: %w", err)
		}

		reportRaw, rtdataRaw, err = DecodeAzureReport(data)
		if err != nil {
			return ar.Measurement{}, fmt.Errorf("failed to decode azure report: %w", err)
		}

		rtdata, claims, err := verifier.DecodeAzureRtData(rtdataRaw)
		if err != nil {
			return ar.Measurement{}, fmt.Errorf("failed to decode runtime data: %w", err)
		}
		reportType = verifier.AzureReportType(rtdata.ReportType)

		userData, err := hex.DecodeString(claims.UserData)
		if err != nil {
			return ar.Measurement{}, fmt.Errorf("failed to decode user data: %w", err)
		}
		fullNonce := make([]byte, 64)
		copy(fullNonce, nonce)
		if bytes.Equal(userData, fullNonce) {
			success = true
			break
		}
		// Sometimes, the nonce written to the NVindex is not effective immediately
		log.Warnf("Nonce does not match NVIndex nonce (%x vs. %x). Trying again...",
			userData, fullNonce)
		time.Sleep(3 * time.Second)
	}

	if !success {
		return ar.Measurement{}, fmt.Errorf("failed to create report nonce specified via NVIndex")
	}

	switch reportType {
	case verifier.SnpReport:
		return createSnpMeasurement(reportRaw, rtdataRaw, akchain)
	case verifier.TdxReport:
		// TDREPORT is only 1024 bytes TODO use length field in header if possible,
		// currently, however, the length field in the azure report includes runtime data
		quote, err := GetTdxQuote(reportRaw[:1024])
		if err != nil {
			return ar.Measurement{}, fmt.Errorf("failed to get TDX quote: %w", err)
		}
		return createTdxMeasurement(quote, rtdataRaw, akchain)
	}

	return ar.Measurement{}, fmt.Errorf("unknown report type %v", reportType)
}

func UpdateAzureUserData(nonce []byte) error {

	if len(nonce) > 32 {
		return fmt.Errorf("nonce length %v exceeds maximum length (32 bytes)", len(nonce))
	}
	fullNonce := make([]byte, 64)
	copy(fullNonce, nonce)

	log.Debugf("Updating azure user data via NV index 0x%x: %x", nvIndexTdUserData, nonce)

	rwc, err := OpenTpm()
	if err != nil {
		return fmt.Errorf("unable to open TPM device %s: %w", tpmDevicePath, err)
	}
	defer rwc.Close()

	// Check if NV index already exists
	caps, _, err := tpm2.GetCapability(rwc, tpm2.CapabilityHandles, 20, uint32(tpm2.HandleTypeNVIndex)<<24)
	if err != nil {
		return fmt.Errorf("GetCapability failed: %w", err)
	}

	indexExists := false
	for _, c := range caps {
		if h, ok := c.(tpmutil.Handle); ok && h == nvIndexTdUserData {
			indexExists = true
			break
		}
	}
	log.Debugf("Index 0x%x exists: %v", nvIndexTdUserData, indexExists)

	// Define NV space if it doesn't exist
	if !indexExists {
		attrs := tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead | tpm2.AttrWriteSTClear | tpm2.AttrReadSTClear
		if err := tpm2.NVDefineSpace(
			rwc,
			tpm2.HandleOwner,
			tpmutil.Handle(nvIndexTdUserData),
			"",
			"",
			nil,
			attrs,
			64,
		); err != nil {
			return fmt.Errorf("NVDefineSpace failed: %w", err)
		}
	}

	// Write the nonce to the NV index
	if err := tpm2.NVWrite(rwc, tpm2.HandleOwner, nvIndexTdUserData, "", fullNonce, 0); err != nil {
		return fmt.Errorf("NVWrite failed: %w", err)
	}

	// Read back NV index to ensure update was effective
	retNonce, err := GetAzureUserData()
	if err != nil {
		return fmt.Errorf("failed to read back azure user data: %w", err)
	}

	if !bytes.Equal(retNonce, fullNonce[:32]) {
		return fmt.Errorf("read back nonce does not match set nonce (%x vs. %x)", retNonce, fullNonce[:32])
	}

	log.Debugf("Successfully updated azure user data at NV index 0x%x to %x", nvIndexTdUserData, retNonce)

	return nil
}

func GetAzureUserData() ([]byte, error) {

	log.Debugf("Fetching azure user data from vTPM NVIndex %x...", nvIndexTdUserData)

	rwc, err := OpenTpm()
	if err != nil {
		return nil, fmt.Errorf("unable to open TPM device %s: %w", tpmDevicePath, err)
	}
	defer rwc.Close()

	// Check if NV index already exists
	caps, _, err := tpm2.GetCapability(rwc, tpm2.CapabilityHandles, 20, uint32(tpm2.HandleTypeNVIndex)<<24)
	if err != nil {
		return nil, fmt.Errorf("GetCapability failed: %w", err)
	}

	indexExists := false
	for _, c := range caps {
		if h, ok := c.(tpmutil.Handle); ok && h == nvIndexTdUserData {
			indexExists = true
			break
		}
	}
	if !indexExists {
		data := make([]byte, 32)
		return data, nil
	}

	// Read NV index contents
	data, err := tpm2.NVReadEx(rwc, nvIndexTdUserData, tpm2.HandleOwner, "", 0)
	if err != nil {
		return nil, fmt.Errorf("NVRead failed: %w", err)
	}

	log.Debugf("Successfully fetched azure user data")

	// Limit to internal nonce length of 32 bytes
	return data[:32], nil
}

func GetAzureReport() ([]byte, error) {

	log.Debugf("Fetching azure report from vTPM NVIndex %x...", nvIndexTdReport)

	rwc, err := OpenTpm()
	if err != nil {
		return nil, fmt.Errorf("unable to open TPM device %s: %w", tpmDevicePath, err)
	}
	defer rwc.Close()

	// Read NV index contents
	data, err := tpm2.NVReadEx(rwc, nvIndexTdReport, tpm2.HandleOwner, "", 0)
	if err != nil {
		return nil, fmt.Errorf("NVRead failed: %w", err)
	}

	log.Debugf("Successfully fetched azure report")

	return data, nil
}

func DecodeAzureReport(data []byte) ([]byte, []byte, error) {

	log.Debugf("Length of azure report: %v", len(data))

	buf := bytes.NewBuffer(data)

	// Parse header
	var header verifier.AzureHeader
	err := binary.Read(buf, binary.LittleEndian, &header)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode Azure report header: %w", err)
	}

	log.Debug("Parsed header")
	log.Debugf("\tHeader signature       : %v", string(header.Signature[:]))
	log.Debugf("\tHeader version         : %v", header.Version)
	log.Debugf("\tHeader payload size    : %v", header.PayloadSize)
	log.Debugf("\tHeader request type    : %v", header.RequestType)

	if string(header.Signature[:]) != "HCLA" {
		return nil, nil, fmt.Errorf("unexpected header signature %q. Expected %q", string(header.Signature[:]), "HCLA")
	}
	if header.Version != 1 && header.Version != 2 {
		return nil, nil, fmt.Errorf("unsupported header version %v. Expected %v, %v", header.Version, 1, 2)
	}
	if header.RequestType != 2 {
		return nil, nil, fmt.Errorf("unsupported header request type %v. Expected %v", header.RequestType, 2)
	}

	// Extract payload
	var payload [1184]byte
	err = binary.Read(buf, binary.LittleEndian, &payload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode Azure report payload: %w", err)
	}

	// Extract runtime data
	rtdata := buf.Bytes()

	return payload[:], rtdata, nil
}

func GetTdxQuote(report []byte) ([]byte, error) {

	encodedReport := base64.RawURLEncoding.EncodeToString(report)
	imdsRequest := fmt.Sprintf(`{"report":"%s"}`, encodedReport)

	quoteResponse, err := FetchAzureTdxQuote(imdsRequest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get quote from IMDS: %v\n", err)
		os.Exit(1)
	}

	log.Debugf("Unmarshalling azure formatted TDX quote..")

	var parsed struct {
		Quote       string `json:"quote"`
		RuntimeData struct {
			Data string `json:"data"`
		} `json:"runtimeData"`
	}
	if err := json.Unmarshal(quoteResponse, &parsed); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse quote JSON: %v\n", err)
		os.Exit(1)
	}

	if parsed.Quote == "" {
		fmt.Fprintf(os.Stderr, "Received empty quote from IMDS\n")
		os.Exit(1)
	}

	quoteBytes, err := base64.RawURLEncoding.DecodeString(parsed.Quote)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode base64url quote: %v\n", err)
		os.Exit(1)
	}

	log.Debugf("Successfully retrieved quote")

	return quoteBytes, nil
}

func FetchAzureTdxQuote(jsonRequest string) ([]byte, error) {

	url := imdsEndpoint + quotePath

	log.Debugf("Fetching quote from IMDS %v...", url)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(jsonRequest)))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request to IMDS failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IMDS returned non-OK status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read IMDS response body: %w", err)
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("IMDS response was empty")
	}

	log.Debug("Successfully fetched quote")

	return body, nil
}

func createSnpMeasurement(report, claims []byte, akchain []*x509.Certificate) (ar.Measurement, error) {
	measurement := ar.Measurement{
		Type:     "Azure SNP Measurement",
		Evidence: report,
		Certs:    internal.WriteCertsDer(akchain),
		Claims:   claims,
	}
	return measurement, nil
}

func createTdxMeasurement(data, claims []byte, akchain []*x509.Certificate) (ar.Measurement, error) {

	// Decode attestation report to get FMSPC (required to fetch collateral)
	quote, err := verifier.DecodeTdxReportV4(data)
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to decode TDX quote: %w", err)
	}
	log.Tracef("PCK Leaf Certificate: %v",
		string(internal.WriteCertPem(quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert)))

	// Get FMSPC
	exts, err := pcs.PckCertificateExtensions(
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert)
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to get PCK certificate extensions: %w", err)
	}
	log.Tracef("PCK FMSPC: %v", exts.FMSPC)

	// Fetch collateral
	collateral, err := verifier.FetchCollateral(exts.FMSPC,
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert, verifier.TDX_QUOTE_TYPE)
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to get TDX collateral: %w", err)
	}

	// Create measurement
	measurement := ar.Measurement{
		Type:     "Azure TDX Measurement",
		Evidence: data,
		Certs:    internal.WriteCertsDer(akchain),
		Artifacts: []ar.Artifact{
			{
				Type: "TDX Collateral",
				Events: []ar.MeasureEvent{
					{
						IntelCollateral: collateral,
					},
				},
			},
		},
		Claims: claims,
	}

	return measurement, nil
}
