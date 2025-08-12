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
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/azuredriver"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/google/go-tpm/legacy/tpm2"
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
	CMD_GET_AZURE_RTDATA   = "get-azure-rtdata"   // Fetches the azure report runtime data
	CMD_GET_VTPM_QUOTE     = "get-vtpm-quote"     // Fetches the vTPM quote from the TPM
	CMD_GET_VTPM_AK_CERT   = "get-vtpm-ak-cert"   // Fetches the vTPM AK cert
	CMD_VERIFY_VTPM        = "verify-vtpm"        // Verify that SHA256(runtimeclaims) == REPORTDATA && runtimeclaims.akpub == vTPM AK
	CMD_VERIFY_VTPM_QUOTE  = "verify-vtpm-quote"  // Verify the quote signature
	CMD_UPDATE_USER_DATA   = "update-user-data"   // Update azure report user data in NV index
	CMD_GET_USER_DATA      = "get-user-data"      // Read user data from NV index
)

func run() error {

	cmd := flag.String("cmd", "", fmt.Sprintf("command to run: %v, %v, %v, %v, %v, %v, %v, %v, %v, %v",
		CMD_GET_AZURE_REPORT,
		CMD_GET_AZURE_HWREPORT,
		CMD_GET_HW_REPORT,
		CMD_GET_AZURE_RTDATA,
		CMD_GET_VTPM_QUOTE,
		CMD_GET_VTPM_AK_CERT,
		CMD_VERIFY_VTPM,
		CMD_VERIFY_VTPM_QUOTE,
		CMD_UPDATE_USER_DATA,
		CMD_GET_USER_DATA,
	))
	pcrs := flag.String("pcrs", "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15", "PCRs to include in quote")
	in := flag.String("userdata", "", "Azure User Data")
	flag.Parse()

	parts := strings.Split(*pcrs, ",")
	pcrNums := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			panic(err)
		}
		pcrNums[i] = n
	}

	if *cmd == CMD_UPDATE_USER_DATA && *in == "" {
		return fmt.Errorf("missing parameter -userdata")
	}

	switch *cmd {

	case CMD_GET_HW_REPORT:
		measurement, err := azuredriver.GetCcMeasurement(nil, nil)
		if err != nil {
			return fmt.Errorf("failed to get hwreport: %w", err)
		}
		os.Stdout.Write(measurement.Evidence)

	case CMD_GET_AZURE_REPORT:
		tdreport, err := azuredriver.GetAzureReport()
		if err != nil {
			return fmt.Errorf("failed to get azure report: %w", err)
		}
		os.Stdout.Write(tdreport)

	case CMD_GET_AZURE_HWREPORT:
		azureReport, err := azuredriver.GetAzureReport()
		if err != nil {
			return fmt.Errorf("failed to get azure report: %w", err)
		}
		hwreport, rtdataRaw, err := azuredriver.DecodeAzureReport(azureReport)
		if err != nil {
			return fmt.Errorf("failed to decode azure report: %w", err)
		}
		_, _, err = verifier.DecodeAzureRtData(rtdataRaw)
		if err != nil {
			return fmt.Errorf("failed to decode runtime data: %w", err)
		}
		os.Stdout.Write(hwreport)

	case CMD_GET_AZURE_RTDATA:
		azureReport, err := azuredriver.GetAzureReport()
		if err != nil {
			return fmt.Errorf("failed to get azure report: %w", err)
		}
		_, rtdataRaw, err := azuredriver.DecodeAzureReport(azureReport)
		if err != nil {
			return fmt.Errorf("failed to decode azure report: %w", err)
		}
		os.Stdout.Write(rtdataRaw)

	case CMD_GET_VTPM_QUOTE:

		nonce, err := azuredriver.GetAzureUserData()
		if err != nil {
			return fmt.Errorf("failed to get azure user data: %w", err)
		}
		quote, sig, _, err := azuredriver.GetVtpmQuote(pcrNums, nonce)
		if err != nil {
			return fmt.Errorf("failed to get vtpm quote: %w", err)
		}
		log.Debugf("Writing quote length %v (0x%x)", len(quote), len(quote))
		os.Stdout.Write(quote)
		log.Debugf("Writing signature length %v (0x%x)", len(sig), len(sig))
		os.Stdout.Write(sig)

	case CMD_GET_VTPM_AK_CERT:
		akcert, err := azuredriver.GetVtpmAkCert()
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
		err := verifyVtpmQuote(pcrNums)
		if err != nil {
			return fmt.Errorf("failed to verify quote: %w", err)
		}

	case CMD_UPDATE_USER_DATA:
		err := azuredriver.UpdateAzureUserData([]byte(*in))
		if err != nil {
			return fmt.Errorf("failed to update azure user data: %w", err)
		}

	case CMD_GET_USER_DATA:
		data, err := azuredriver.GetAzureUserData()
		if err != nil {
			return fmt.Errorf("failed to get azure user data: %w", err)
		}
		os.Stdout.Write(data)

	default:
		return fmt.Errorf("unknown cmd %q. See azuretool -help", *cmd)

	}

	return nil
}

func verifyVtpm() error {

	log.Debugf("Verifying vTPM Chain of Trust")

	suppliedNonce := make([]byte, 64)
	_, err := rand.Read(suppliedNonce)
	if err != nil {
		return fmt.Errorf("failed to create nonce: %w", err)
	}
	log.Debugf("Created nonce %v", hex.EncodeToString(suppliedNonce))

	// Get azure report
	measurement, err := azuredriver.GetCcMeasurement(suppliedNonce, nil)
	if err != nil {
		return fmt.Errorf("failed to get azure CC measurement: %w", err)
	}

	// Extract the nonce (REPORTDATA) from TDX quote / SNP report
	reportNonce, err := verifier.GetReportNonce(measurement)
	if err != nil {
		return fmt.Errorf("failed to extract report nonce: %w", err)
	}
	log.Debugf("Extracted report nonce (HASH(runtime_claims): %v", hex.EncodeToString(reportNonce))

	// Get vTPM AK cert
	akRaw, err := azuredriver.GetVtpmAkCert()
	if err != nil {
		return fmt.Errorf("failed to get vTPM AK cert: %w", err)
	}
	ak, err := x509.ParseCertificate(akRaw)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Verify the Azure CoT: vTPM AK public embedded into REPORTDATA
	err = verifier.VerifyAzureCoT(measurement.Claims, suppliedNonce, reportNonce, ak)
	if err != nil {
		return fmt.Errorf("failed to verify azure chain of trust: %w", err)
	}

	log.Debugf("Successfully verified vTPM Chain of Trust")

	return nil
}

func verifyVtpmQuote(pcrs []int) error {

	nonce := make([]byte, 4)
	_, err := rand.Read(nonce)
	if err != nil {
		return fmt.Errorf("failed to read random bytes: %w", err)
	}

	quote, sig, _, err := azuredriver.GetVtpmQuote(pcrs, nonce)
	if err != nil {
		return fmt.Errorf("failed to get vtpm quote: %w", err)
	}

	akcert, err := azuredriver.GetVtpmAkCert()
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

	log.Debugf("Successfully verified quote nonce: %v", hex.EncodeToString(nonce))

	log.Debugf("Verifying quote signature...")

	result := verifier.VerifyTpmQuoteSignature(quote, sig, cert)
	if result.Status != ar.StatusSuccess {
		return fmt.Errorf("failed to verify tpm quote signature: %v", result.Details)
	}

	log.Debugf("Successfully verified vtpm quote")

	return nil
}
