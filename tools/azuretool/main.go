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
	"encoding/binary"
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
	nonceFlag    = "nonce"
	quoteFlag    = "quote"
	akCertFlag   = "ak-cert"
	outFlag      = "out"
	inFlag       = "in"

	defaultPcrs = "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15"
)

func main() {

	log.SetLevel(log.TraceLevel)

	cmd := &cli.Command{
		Name: "azuretool",
		Usage: "Tool to set nonces and fetch hardware reports (SNP reports, TDX quotes) via the " +
			"Azure-specific vTPM NVIndex mechanism, fetch Azure reports (hardware reports " +
			"including metadata), and interact with the vTPM. For design details about the " +
			"Azure-specific CVM guest attestation, refer to: " +
			"https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  outFlag,
				Usage: "output file (writes to stdout if unset)",
			},
		},
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
				Name: "get-azure-rtdata",
				Usage: "Fetch the azure report runtime data (starting at azure hcl attestation " +
					"report offset 1216, the runtime data contains the hardware report type " +
					"and the runtime claims, which include the user nonce, the vTPM public keys " +
					"and the user data. For more information, refer to: " +
					"https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return getAzureRtData(cmd)
				},
			},
			{
				Name: "compute-reportdata",
				Usage: "Compute the expected REPORTDATA (SHA256 of the Azure runtime-claims " +
					"JSON) that Azure firmware will produce for a supplied user nonce. Takes " +
					"the firmware-generated fields (vTPM AK / EK JWKs, VM configuration) from " +
					"an rtdata blob acquired via get-azure-rtdata.",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     inFlag,
						Usage:    "path to an Azure runtime-data blob (see get-azure-rtdata)",
						Required: true,
					},
					&cli.StringFlag{
						Name:     userdataFlag,
						Usage:    "raw string user nonce",
						Required: true,
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return computeReportData(cmd)
				},
			},
			{
				Name: "show-rtdata",
				Usage: "Decode and print all fields of an Azure runtime-data blob acquired via " +
					"get-azure-rtdata.",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     inFlag,
						Usage:    "path to an Azure runtime-data blob (see get-azure-rtdata)",
						Required: true,
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return showRtData(cmd)
				},
			},
			{
				Name: "get-vtpm-quote",
				Usage: "Fetch a vTPM quote from the TPM via the standard /dev/tpm0 or " +
					"/dev/tpmrm0 mechanism. The quote and signature are written to stdout " +
					"in a serialized format that is readable by other commands of this tool",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    pcrsFlag,
						Usage:   "PCRs to include in quote (comma-separated)",
						Value:   defaultPcrs,
						Aliases: []string{mrsFlag},
					},
					&cli.StringFlag{
						Name:  nonceFlag,
						Usage: "raw string nonce to embed in the quote (if unset, 0x00)",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					pcrs, err := parsePcrs(cmd.String(pcrsFlag))
					if err != nil {
						return err
					}
					return getVtpmQuote(cmd, pcrs, nonceFromFlag(cmd))
				},
			},
			{
				Name: "get-vtpm-ak-cert",
				Usage: "Fetch the vTPM AK certificate (stored in NV index 0x01C101D0). See " +
					"https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design" +
					" for more information",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return getVtpmAkCert(cmd)
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
				Name: "verify-vtpm-quote-signature",
				Usage: "Verify a vTPM quote signature. If --" + quoteFlag + " and --" +
					akCertFlag + " are not set, a fresh quote and AK certificate are " +
					"fetched from the vTPM.",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    pcrsFlag,
						Usage:   "PCRs to include when fetching a fresh quote (comma-separated)",
						Value:   defaultPcrs,
						Aliases: []string{mrsFlag},
					},
					&cli.StringFlag{
						Name: nonceFlag,
						Usage: "raw string nonce expected in the quote (if unset, use 0x00 " +
							"used when fetching a fresh quote and when verifying the nonce of a " +
							"pre-fetched quote",
					},
					&cli.StringFlag{
						Name: quoteFlag,
						Usage: "path to a pre-fetched quote+signature file as written by " +
							"get-vtpm-quote. if unset, a fresh quote is fetched",
					},
					&cli.StringFlag{
						Name: akCertFlag,
						Usage: "path to a pre-fetched AK certificate. If unset, the AK " +
							"certificate is read from the vTPM NV index",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return verifyVtpmQuote(cmd)
				},
			},
			{
				Name:  "update-user-data",
				Usage: "Update azure hcl report user data (nonce) in the NV index 0x01400002",
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
				Usage: "Read azure hcl report user data (nonce) from the NV index 0x01400002",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					data, err := azuredriver.GetAzureUserData()
					if err != nil {
						return fmt.Errorf("failed to get azure user data: %w", err)
					}
					if err := writeOutput(cmd, data); err != nil {
						return fmt.Errorf("failed to write output: %w", err)
					}
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
	if err := writeOutput(cmd, report); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}
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

	if err := writeOutput(cmd, hwreport); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

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

	if err := writeOutput(cmd, evidence.Data); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}
	return nil
}

func getAzureRtData(cmd *cli.Command) error {
	azureReport, err := azuredriver.GetAzureReport()
	if err != nil {
		return fmt.Errorf("failed to get azure report: %w", err)
	}
	_, rtdataRaw, err := azuredriver.DecodeAzureReport(azureReport)
	if err != nil {
		return fmt.Errorf("failed to decode azure report: %w", err)
	}
	if err := writeOutput(cmd, rtdataRaw); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}
	return nil
}

func computeReportData(cmd *cli.Command) error {
	rtdataRaw, err := os.ReadFile(cmd.String(inFlag))
	if err != nil {
		return fmt.Errorf("failed to read rtdata file: %w", err)
	}

	rtdata, claims, err := verifier.DecodeAzureRtData(rtdataRaw)
	if err != nil {
		return fmt.Errorf("failed to decode azure runtime data: %w", err)
	}

	// The user nonce lives in the claims JSON as a hex-encoded 64-byte string
	if len(claims.UserData) != 128 {
		return fmt.Errorf("unexpected user-data length in rtdata: %d hex chars (expected %d)",
			len(claims.UserData), 128)
	}

	nonce := []byte(cmd.String(userdataFlag))
	if len(nonce) > 32 {
		return fmt.Errorf("nonce length %d exceeds maximum length accepted by the NV index (32 bytes)",
			len(nonce))
	}
	padded := make([]byte, 64)
	copy(padded, nonce)
	newUserData := hex.EncodeToString(padded)

	headerSize := binary.Size(*rtdata)
	end := headerSize + int(rtdata.ClaimSize)
	if end > len(rtdataRaw) {
		return fmt.Errorf("runtime data too short: need %d bytes, have %d", end, len(rtdataRaw))
	}
	claimsJSON := rtdataRaw[headerSize:end]

	if n := bytes.Count(claimsJSON, []byte(claims.UserData)); n != 1 {
		return fmt.Errorf("could not locate user-data in claims JSON (found %d occurrences)", n)
	}

	// Byte-substitute the user-data value so the JSON encoding Azure
	// firmware produced is preserved. Re-marshalling would risk a field-ordering mismatch.
	modified := make([]byte, len(rtdataRaw))
	copy(modified, rtdataRaw)
	udOff := bytes.Index(modified[headerSize:end], []byte(claims.UserData))
	copy(modified[headerSize+udOff:], newUserData)

	hash, err := verifier.HashAzureRuntimeClaims(rtdata, modified)
	if err != nil {
		return fmt.Errorf("failed to hash runtime claims: %w", err)
	}

	log.Infof("Expected REPORTDATA (SHA256 of runtime claims with supplied nonce): %v",
		hex.EncodeToString(hash))
	if err := writeOutput(cmd, hash); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}
	return nil
}

func showRtData(cmd *cli.Command) error {
	rtdataRaw, err := os.ReadFile(cmd.String(inFlag))
	if err != nil {
		return fmt.Errorf("failed to read rtdata file: %w", err)
	}
	rtdata, claims, err := verifier.DecodeAzureRtData(rtdataRaw)
	if err != nil {
		return fmt.Errorf("failed to decode azure runtime data: %w", err)
	}
	verifier.DumpAzureRuntimeClaims(rtdata, claims, log.Infof)
	return nil
}

func getVtpmQuote(cmd *cli.Command, pcrs []int, nonce []byte) error {
	quote, sig, err := azuredriver.GetVtpmQuote(pcrs, nonce)
	if err != nil {
		return fmt.Errorf("failed to get vtpm quote: %w", err)
	}
	log.Debugf("Writing quote length %v (0x%x)", len(quote), len(quote))
	log.Debugf("Writing signature length %v (0x%x)", len(sig), len(sig))
	blob := encodeQuoteBlob(quote, sig)
	if err := writeOutput(cmd, blob); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}
	return nil
}

func nonceFromFlag(cmd *cli.Command) []byte {
	if cmd.IsSet(nonceFlag) {
		return []byte(cmd.String(nonceFlag))
	}
	return []byte{0}
}

func encodeQuoteBlob(quote, sig []byte) []byte {
	buf := make([]byte, 4+len(quote)+4+len(sig))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(quote)))
	copy(buf[4:4+len(quote)], quote)
	binary.BigEndian.PutUint32(buf[4+len(quote):4+len(quote)+4], uint32(len(sig)))
	copy(buf[4+len(quote)+4:], sig)
	return buf
}

func readQuoteBlob(path string) (quote, sig []byte, err error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read quote file %q: %w", path, err)
	}
	if len(buf) < 4 {
		return nil, nil, fmt.Errorf("quote file %q too short for quote length prefix", path)
	}
	qLen := binary.BigEndian.Uint32(buf[:4])
	if uint64(len(buf)) < 4+uint64(qLen)+4 {
		return nil, nil, fmt.Errorf("quote file %q too short for quote of length %d", path, qLen)
	}
	quote = buf[4 : 4+qLen]
	sigOff := 4 + qLen
	sLen := binary.BigEndian.Uint32(buf[sigOff : sigOff+4])
	if uint64(len(buf)) != uint64(sigOff)+4+uint64(sLen) {
		return nil, nil, fmt.Errorf("quote file %q length %d does not match framed lengths (quote %d + sig %d)",
			path, len(buf), qLen, sLen)
	}
	sig = buf[sigOff+4 : sigOff+4+sLen]
	return quote, sig, nil
}

func getVtpmAkCert(cmd *cli.Command) error {
	akcert, err := azuredriver.GetVtpmAkCert()
	if err != nil {
		return fmt.Errorf("failed to get vtpm ak cert: %w", err)
	}
	if err := writeOutput(cmd, akcert); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
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

func verifyVtpmQuote(cmd *cli.Command) error {

	nonce := nonceFromFlag(cmd)

	var (
		quote, sig []byte
		err        error
	)
	if quotePath := cmd.String(quoteFlag); quotePath != "" {
		log.Debugf("Reading pre-fetched quote from %v", quotePath)
		quote, sig, err = readQuoteBlob(quotePath)
		if err != nil {
			return err
		}
	} else {
		pcrs, perr := parsePcrs(cmd.String(pcrsFlag))
		if perr != nil {
			return perr
		}
		quote, sig, err = azuredriver.GetVtpmQuote(pcrs, nonce)
		if err != nil {
			return fmt.Errorf("failed to get vtpm quote: %w", err)
		}
	}

	var akcert []byte
	if akCertPath := cmd.String(akCertFlag); akCertPath != "" {
		log.Debugf("Reading pre-fetched AK certificate from %v", akCertPath)
		akcert, err = os.ReadFile(akCertPath)
		if err != nil {
			return fmt.Errorf("failed to read ak cert file %q: %w", akCertPath, err)
		}
	} else {
		akcert, err = azuredriver.GetVtpmAkCert()
		if err != nil {
			return fmt.Errorf("failed to get vtpm ak cert: %w", err)
		}
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

func writeOutput(cmd *cli.Command, data []byte) error {
	if path := cmd.String(outFlag); path != "" {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
		return nil
	}
	if _, err := os.Stdout.Write(data); err != nil {
		return fmt.Errorf("failed to write stdout: %w", err)
	}
	return nil
}
