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
	"fmt"
	"os"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/report"
	"github.com/google/go-tdx-guest/pcs"
	log "github.com/sirupsen/logrus"
)

func main() {
	err := dumpQuote()
	if err != nil {
		log.Fatalf("Failed to dump quote: %v", err)
	}
	log.Infof("Successfully dumped all data")
}

func dumpQuote() error {

	log.Infof("Generating TDX quote")

	nonce := make([]byte, 64)

	// Generate Quote
	req := &report.Request{
		InBlob:     nonce,
		GetAuxBlob: false,
	}
	resp, err := linuxtsm.GetReport(req)
	if err != nil {
		return fmt.Errorf("failed to get TDX quote via configfs: %w", err)
	}

	// Decode attestation report to get FMSPC and certificate chain
	quote, err := verifier.DecodeTdxReportV4(resp.OutBlob)
	if err != nil {
		return fmt.Errorf("failed to decode TDX quote: %v", err)
	}
	log.Tracef("PCK Leaf Certificate: %v",
		string(internal.WriteCertPem(quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert)))

	// Get FMSPC
	exts, err := pcs.PckCertificateExtensions(
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert)
	if err != nil {
		return fmt.Errorf("failed to get PCK certificate extensions: %w", err)
	}
	log.Tracef("PCK FMSPC: %v", exts.FMSPC)

	// Convert certificate chain to PEM format
	pck := internal.WriteCertPem(quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert)
	intermediate := internal.WriteCertPem(quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.IntermediateCert)
	ca := internal.WriteCertPem(quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.RootCACert)

	// Dump all data to files
	err = os.WriteFile("quote", resp.OutBlob, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}
	err = os.WriteFile("pck.pem", pck, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}
	err = os.WriteFile("intermediate.pem", intermediate, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}
	err = os.WriteFile("ca.pem", ca, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}
	err = os.WriteFile("fmspc", []byte(exts.FMSPC), 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}
	err = os.WriteFile("nonce", nonce, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	return nil
}
