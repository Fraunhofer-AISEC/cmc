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

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"

	"github.com/Fraunhofer-AISEC/cmc/azuredriver"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	log "github.com/sirupsen/logrus"
)

func main() {

	log.SetLevel(log.TraceLevel)

	err := run()
	if err != nil {
		log.Errorf("%v", err)
	}
}

const (
	CMD_GET_AZURE_REPORT   = "get-azure-report"   // Fetches the azure report (header, hwreport, runtime-data)
	CMD_GET_AZURE_HWREPORT = "get-azure-hwreport" // Fetches the azure report payload, which is the SNP report or the TDX TDREPORT
	CMD_GET_HW_REPORT      = "get-hwreport"       // Fetches the hardware report (SNP report or TDX quote)
	CMD_GET_VTPM_QUOTE     = "get-vtpm-quote"     // Fetches the vTPM quote from the TPM
	CMD_GET_VTPM_AK_CERT   = "get-vtpm-ak-cert"   // Fetches the vTPM AK cert
	CMD_VERIFY_VTPM        = "verify-vtpm"        // Verify that SHA256(runtimeclaims) == REPORTDATA && runtimeclaims.akpub == vTPM AK
	CMD_VERIFY_VTPM_QUOTE  = "verify-vtpm-quote"  // Verify the quote signature
)

const (
	tpmDevicePath = "/dev/tpm0"                // TODO reuse tpmdriver code to distinguish between tpmrm0 and tpm0
	nvIndexAkCert = tpmutil.Handle(0x01C101D0) // NV index to read
	akHandle      = tpmutil.Handle(0x81000003)
)

func run() error {

	cmd := flag.String("cmd", "", fmt.Sprintf("command to run: %v, %v, %v, %v, %v, %v, %v",
		CMD_GET_HW_REPORT,
		CMD_GET_AZURE_REPORT,
		CMD_GET_AZURE_HWREPORT,
		CMD_GET_VTPM_QUOTE,
		CMD_GET_VTPM_AK_CERT,
		CMD_VERIFY_VTPM,
		CMD_VERIFY_VTPM_QUOTE,
	))
	flag.Parse()

	switch *cmd {

	case CMD_GET_HW_REPORT:
		quote, _, _, err := azuredriver.GetEvidence()
		if err != nil {
			return fmt.Errorf("failed to get hwreport: %w", err)
		}
		os.Stdout.Write(quote)

	case CMD_GET_AZURE_REPORT:
		tdreport, err := azuredriver.GetAzureReport()
		if err != nil {
			return fmt.Errorf("failed to get azure report: %w", err)
		}
		os.Stdout.Write(tdreport)

	case CMD_GET_AZURE_HWREPORT:
		tdreport, _, _, err := azuredriver.GetAzureHwReport()
		if err != nil {
			return fmt.Errorf("failed to get azure hwreport: %w", err)
		}
		os.Stdout.Write(tdreport)

	case CMD_GET_VTPM_QUOTE:
		quote, sig, _, err := getVtpmQuote()
		if err != nil {
			return fmt.Errorf("failed to get vtpm quote: %w", err)
		}
		os.Stdout.Write(quote)
		os.Stdout.Write(sig)

	case CMD_GET_VTPM_AK_CERT:
		akcert, err := getVtpmAkCert()
		if err != nil {
			return fmt.Errorf("failed to get vtpm ak cert: %w", err)
		}
		os.Stdout.Write(akcert)

	case CMD_VERIFY_VTPM:
		err := verifyVtpm()
		if err != nil {
			return fmt.Errorf("failed to verify vTPM: %w", err)
		}

	case CMD_VERIFY_VTPM_QUOTE:
		err := verifyVtpmQuote()
		if err != nil {
			return fmt.Errorf("failed to verify quote: %w", err)
		}

	default:
		return fmt.Errorf("unknown cmd %q. See azuretool -help", *cmd)

	}

	return nil
}

func getVtpmAkCert() ([]byte, error) {

	log.Debugf("Fetching AK cert from vTPM NVIndex %x...", nvIndexAkCert)

	// Open TPM device
	rwc, err := os.OpenFile(tpmDevicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to open TPM device %s: %w", tpmDevicePath, err)
	}
	defer rwc.Close()

	// Read NV index contents
	data, err := tpm2.NVReadEx(rwc, nvIndexAkCert, tpm2.HandleOwner, "", 0)
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

func getVtpmQuote() ([]byte, []byte, []byte, error) {

	azureAkHandle := tpmutil.Handle(akHandle)

	nonce := make([]byte, 4)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create nonce: %w", err)
	}

	log.Debugf("Fetching quote with nonce %v", hex.EncodeToString(nonce))

	sel := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	}

	tpm, err := os.OpenFile(tpmDevicePath, os.O_RDWR, 0)
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

	return quote, rawSig, nonce, nil
}

func verifyVtpm() error {

	// Get azure report
	azureReport, err := azuredriver.GetAzureReport()
	if err != nil {
		return fmt.Errorf("failed to get azure hwreport: %w", err)
	}
	log.Debugf("Length azure report: %v", len(azureReport))

	// Extract runtime claims and jwks
	buf := bytes.NewBuffer(azureReport)

	// Parse header
	var header azuredriver.Header
	err = binary.Read(buf, binary.LittleEndian, &header)
	if err != nil {
		return fmt.Errorf("failed to decode Azure report header: %w", err)
	}
	log.Debugf("Header signature: %v", string(header.Signature[:]))

	// Parse payload
	var payload [1184]byte
	err = binary.Read(buf, binary.LittleEndian, &payload)
	if err != nil {
		return fmt.Errorf("failed to decode Azure report payload: %w", err)
	}

	// Parse runtime data
	var rtdata azuredriver.RuntimeData
	err = binary.Read(buf, binary.LittleEndian, &rtdata)
	if err != nil {
		return fmt.Errorf("failed to decode Azure report payload: %w", err)
	}
	log.Debugf("RuntimeData data size: %v", rtdata.DataSize)

	if rtdata.Version != 1 {
		return fmt.Errorf("unsupported runtime data version %v. Expected %v", rtdata.Version, 1)
	}

	var reportdataPartial []byte
	switch rtdata.ReportType {
	case uint32(azuredriver.TDX):
		hwreport := payload[:1024]
		tdReport, err := verifier.DecodeTdReport(hwreport)
		if err != nil {
			return fmt.Errorf("failed to decode TDREPORT: %w", err)
		}
		reportdataPartial = tdReport.ReportMacStruct.ReportData[:32]
	default:
		report, err := verifier.DecodeSnpReport(payload[:])
		if err != nil {
			return fmt.Errorf("failed to decode SNP report: %w", err)
		}
		reportdataPartial = report.ReportData[:32]
	}
	log.Debugf("Extracted reportdata: %v", hex.EncodeToString(reportdataPartial))

	// Hash runtime claims
	rawRuntimeClaims := azureReport[1216+20 : 1216+20+rtdata.ClaimSize]
	log.Debugf("Length raw runtime claims: %v", len(rawRuntimeClaims))
	hashRuntimeClaims := sha256.Sum256(rawRuntimeClaims)
	log.Debugf("Hash runtime claims: %v", hex.EncodeToString(hashRuntimeClaims[:]))

	// Parse runtime claims
	rawClaims := buf.Bytes()[:rtdata.ClaimSize]
	log.Debugf("Parsing claims size %v", len(rawClaims))
	var claims azuredriver.RuntimeClaims
	err = json.Unmarshal(rawClaims, &claims)
	if err != nil {
		return fmt.Errorf("failed to unmarshal claims: %w", err)
	}
	for _, key := range claims.Keys {
		log.Debugf("\tJWK KeyID: %v", key.KeyID)
	}

	// Compare report data with runtime claims
	if !bytes.Equal(hashRuntimeClaims[:], reportdataPartial) {
		return fmt.Errorf("HASH(runtime_claims) != REPORTDATA")
	}

	log.Debugf("HASH(runtime_claims) matches REPORTDATA")

	// Extract vTPM AK Public from runtime claims
	if len(claims.Keys) != 2 {
		return fmt.Errorf("unexpected JWK keys length %v (expected %v)", len(claims.Keys), 2)
	}
	claimAkPub, ok := claims.Keys[0].Public().Key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("failed to extract claims ak pub")
	}

	// Get vTPM AK cert
	akRaw, err := getVtpmAkCert()
	if err != nil {
		return fmt.Errorf("failed to get vTPM AK cert")
	}

	// Extract public key from x509 certificate
	vTpmAkCert, err := x509.ParseCertificate(akRaw)
	if err != nil {
		return fmt.Errorf("failed to parse vTPM AK cert: %w", err)
	}
	vTpmAkPub, ok := vTpmAkCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("failed to extract public key from certificate")
	}

	// Compare AK cert public key with runtime claims public key
	if !reflect.DeepEqual(claimAkPub, vTpmAkPub) {
		return fmt.Errorf("vTPM AK pub does not match claims AK pub")
	}

	log.Debugf("vTPM AK pub matches claims AK pub")

	return nil
}

func verifyVtpmQuote() error {

	quote, sig, nonce, err := getVtpmQuote()
	if err != nil {
		return fmt.Errorf("failed to get vtpm quote: %w", err)
	}

	akcert, err := getVtpmAkCert()
	if err != nil {
		return fmt.Errorf("failed to get vtpm ak cert: %w", err)
	}

	log.Debugf("Parsing AK cert...")

	cert, err := x509.ParseCertificate(akcert)
	if err != nil {
		return fmt.Errorf("failed to parse AK certificate: %v", err)
	}

	log.Debugf("Decoding quote...")

	tpmsAttest, err := tpm2.DecodeAttestationData(quote)
	if err != nil {
		return fmt.Errorf("failed to decode quote: %w", err)
	}

	log.Debugf("Checking quote nonce...")

	if !bytes.Equal(nonce, tpmsAttest.ExtraData) {
		return fmt.Errorf("failed to verify nonce %v (expected %v)",
			hex.EncodeToString(tpmsAttest.ExtraData), hex.EncodeToString(nonce))
	}

	log.Debugf("Verifying quote signature...")

	result := verifier.VerifyTpmQuoteSignature(quote, sig, cert)
	if !result.Success {
		return fmt.Errorf("failed to verify tpm quote signature: %v", result.Details)
	}

	log.Debugf("Successfully verified vtpm quote")

	return nil
}
