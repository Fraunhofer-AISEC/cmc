// Copyright (c) 2025 - 2026 Fraunhofer AISEC
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
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers/azuredriver"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/google/go-tpm/legacy/tpm2"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

const (
	pcrsFlag     = "pcrs"
	mrsFlag      = "mrs"
	userdataFlag = "userdata"

	defaultPcrs = "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15"
)

func main() {

	log.SetLevel(log.TraceLevel)

	cmd := &cli.Command{
		Name: "azuretool",
		Usage: "Tool to set nonces and fetch hardware reports (SNP reports, TDX quotes) via the " +
			"Azure-specific vTPM NVIndex mechanism, fetch Azure reports (hardware reports " +
			"including metadata), and interact with the vTPM",
		Commands: []*cli.Command{
			{
				Name: "get-hcl-report",
				Usage: "Fetch the azure HCL report (comprises hcl header, SNP report / TDX " +
					"TDREPORT, runtime-data). Note: does fetch the TDREPORT, not the TDX Quote. " +
					"To fetch a TDX quote, use the get-quote command",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: userdataFlag,
						Usage: "user data to inject as nonce before triggering report " +
							"regeneration (if unset, the currently stored NV user data is reused)",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return getAzureReport(cmd)
				},
			},
			{
				Name:  "get-hcl-payload",
				Usage: "Fetch the azure HCL report payload (SNP report or TDX TDREPORT)",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: userdataFlag,
						Usage: "user data to inject as nonce before triggering report " +
							"regeneration (if unset, the currently stored NV user data is reused)",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return getAzureHwReport(cmd)
				},
			},
			{
				Name: "get-quote",
				Usage: "Fetch the hardware quote (SNP report or TDX quote). For SNP, this is the " +
					"HCL payload extracted from the HCL report. For TDX, the HCL payload is sent " +
					"to the Azure IMDS service, which converts the TDREPORT into a TDX Quote",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: userdataFlag,
						Usage: "user data to inject as nonce before fetching (if unset, " +
							"currently set NV data is used)",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return getHwReport(cmd)
				},
			},
			{
				Name:  "get-azure-rtdata",
				Usage: "Fetch the azure report runtime data",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return getAzureRtData()
				},
			},
			{
				Name:  "get-vtpm-quote",
				Usage: "Fetch a vTPM quote from the TPM",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    pcrsFlag,
						Usage:   "PCRs to include in quote (comma-separated)",
						Value:   defaultPcrs,
						Aliases: []string{mrsFlag},
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					pcrs, err := parsePcrs(cmd.String(pcrsFlag))
					if err != nil {
						return err
					}
					return getVtpmQuote(pcrs)
				},
			},
			{
				Name:  "get-vtpm-ak-cert",
				Usage: "Fetch the vTPM AK certificate",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return getVtpmAkCert()
				},
			},
			{
				Name: "verify-vtpm",
				Usage: "Verify that SHA256(runtimeclaims) == REPORTDATA && " +
					"runtimeclaims.akpub == vTPM AK",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return verifyVtpm()
				},
			},
			{
				Name:  "verify-vtpm-quote",
				Usage: "Verify a vTPM quote signature",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    pcrsFlag,
						Usage:   "PCRs to include in quote (comma-separated)",
						Value:   defaultPcrs,
						Aliases: []string{mrsFlag},
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					pcrs, err := parsePcrs(cmd.String(pcrsFlag))
					if err != nil {
						return err
					}
					return verifyVtpmQuote(pcrs)
				},
			},
			{
				Name:  "update-user-data",
				Usage: "Update azure hcl report user data (nonce) in the NV index",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     userdataFlag,
						Usage:    "user data to write to the NV index",
						Required: true,
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return azuredriver.UpdateAzureUserData([]byte(cmd.String(userdataFlag)))
				},
			},
			{
				Name:  "get-user-data",
				Usage: "Read azure hcl report user data (nonce) from the NV index",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					data, err := azuredriver.GetAzureUserData()
					if err != nil {
						return fmt.Errorf("failed to get azure user data: %w", err)
					}
					os.Stdout.Write(data)
					return nil
				},
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Errorf("%v", err)
		os.Exit(1)
	}
}

func parsePcrs(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	pcrs := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("invalid pcr %q: %w", p, err)
		}
		pcrs[i] = n
	}
	return pcrs, nil
}

func getAzureReport(cmd *cli.Command) error {
	report, err := fetchAzureReport(cmd)
	if err != nil {
		return err
	}
	os.Stdout.Write(report)
	return nil
}

func getAzureHwReport(cmd *cli.Command) error {
	report, err := fetchAzureReport(cmd)
	if err != nil {
		return err
	}
	hwreport, rtdataRaw, err := azuredriver.DecodeAzureReport(report)
	if err != nil {
		return fmt.Errorf("failed to decode azure report: %w", err)
	}
	if _, _, err := verifier.DecodeAzureRtData(rtdataRaw); err != nil {
		return fmt.Errorf("failed to decode runtime data: %w", err)
	}
	os.Stdout.Write(hwreport)
	return nil
}

// fetchAzureReport writes the nonce to the NV user data (triggering the Azure
// firmware to regenerate the HCL report) and checks if the returned report
// reflects that nonce. Does some retries as this did not work reliably in
// the past
func fetchAzureReport(cmd *cli.Command) ([]byte, error) {
	var nonce []byte
	if cmd.IsSet(userdataFlag) {
		nonce = []byte(cmd.String(userdataFlag))
	} else {
		data, err := azuredriver.GetAzureUserData()
		if err != nil {
			return nil, fmt.Errorf("failed to get azure user data: %w", err)
		}
		nonce = data
	}

	if err := azuredriver.UpdateAzureUserData(nonce); err != nil {
		return nil, fmt.Errorf("failed to update azure user data: %w", err)
	}

	fullNonce := make([]byte, 64)
	copy(fullNonce, nonce)

	for i := 0; i < 3; i++ {
		report, err := azuredriver.GetAzureReport()
		if err != nil {
			return nil, fmt.Errorf("failed to get azure report: %w", err)
		}
		_, rtdataRaw, err := azuredriver.DecodeAzureReport(report)
		if err != nil {
			return nil, fmt.Errorf("failed to decode azure report: %w", err)
		}
		_, claims, err := verifier.DecodeAzureRtData(rtdataRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to decode runtime data: %w", err)
		}
		userData, err := hex.DecodeString(claims.UserData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode user data: %w", err)
		}
		if bytes.Equal(userData, fullNonce) {
			return report, nil
		}
		// Sometimes the nonce written to the NVindex is not effective immediately
		log.Warnf("Nonce does not match NVIndex nonce (%x vs. %x). Trying again...",
			userData, fullNonce)
		time.Sleep(3 * time.Second)
	}
	return nil, fmt.Errorf("failed to bind report to specified nonce")
}

func getHwReport(cmd *cli.Command) error {
	var nonce []byte
	if cmd.IsSet(userdataFlag) {
		nonce = []byte(cmd.String(userdataFlag))
	} else {
		data, err := azuredriver.GetAzureUserData()
		if err != nil {
			return fmt.Errorf("failed to get azure user data: %w", err)
		}
		nonce = data
	}
	evidence, err := azuredriver.GetCcEvidence(nonce)
	if err != nil {
		return fmt.Errorf("failed to get hwreport: %w", err)
	}
	os.Stdout.Write(evidence.Data)
	return nil
}

func getAzureRtData() error {
	azureReport, err := azuredriver.GetAzureReport()
	if err != nil {
		return fmt.Errorf("failed to get azure report: %w", err)
	}
	_, rtdataRaw, err := azuredriver.DecodeAzureReport(azureReport)
	if err != nil {
		return fmt.Errorf("failed to decode azure report: %w", err)
	}
	os.Stdout.Write(rtdataRaw)
	return nil
}

func getVtpmQuote(pcrs []int) error {
	nonce, err := azuredriver.GetAzureUserData()
	if err != nil {
		return fmt.Errorf("failed to get azure user data: %w", err)
	}
	quote, sig, err := azuredriver.GetVtpmQuote(pcrs, nonce)
	if err != nil {
		return fmt.Errorf("failed to get vtpm quote: %w", err)
	}
	log.Debugf("Writing quote length %v (0x%x)", len(quote), len(quote))
	os.Stdout.Write(quote)
	log.Debugf("Writing signature length %v (0x%x)", len(sig), len(sig))
	os.Stdout.Write(sig)
	return nil
}

func getVtpmAkCert() error {
	akcert, err := azuredriver.GetVtpmAkCert()
	if err != nil {
		return fmt.Errorf("failed to get vtpm ak cert: %w", err)
	}
	os.Stdout.Write(akcert)
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
	evidence, err := azuredriver.GetCcEvidence(suppliedNonce)
	if err != nil {
		return fmt.Errorf("failed to get azure CC measurement: %w", err)
	}

	// Extract the nonce (REPORTDATA) from TDX quote / SNP report
	reportNonce, err := verifier.GetReportNonce(evidence)
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
	err = verifier.VerifyAzureCoT(evidence.AddData, suppliedNonce, reportNonce, ak)
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

	quote, sig, err := azuredriver.GetVtpmQuote(pcrs, nonce)
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
