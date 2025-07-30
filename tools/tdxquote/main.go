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
	"errors"
	"flag"
	"fmt"
	"os"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/tdxdriver"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/google/go-tdx-guest/pcs"
	log "github.com/sirupsen/logrus"
)

func main() {
	err := run()
	if err != nil {
		log.Errorf("%v", err)
	}
}

const (
	CMD_QUOTE      = "quote"
	CMD_CERTCHAIN  = "certchain"
	CMD_TCBINFO    = "tcbinfo"
	CMD_QEIDENTITY = "qeidentity"
	CMD_FMSPC      = "fmspc"
)

func run() error {

	cmd := flag.String("cmd", "", fmt.Sprintf("command to run: %v, %v, %v, %v, %v",
		CMD_QUOTE,
		CMD_CERTCHAIN,
		CMD_TCBINFO,
		CMD_QEIDENTITY,
		CMD_FMSPC,
	))
	flag.Parse()

	switch *cmd {

	case CMD_QUOTE:
		quote, err := getQuoteRaw()
		if err != nil {
			return fmt.Errorf("failed to get TDX Quote: %w", err)
		}
		os.Stdout.Write(quote)

	case CMD_CERTCHAIN:
		certChain, err := getQuoteCertChain()
		if err != nil {
			return fmt.Errorf("failed to get TDX cet chain: %w", err)
		}
		os.Stdout.Write(certChain)

	case CMD_TCBINFO:
		collateral, err := getCollateral()
		if err != nil {
			return fmt.Errorf("failed to get TDX collateral: %w", err)
		}
		os.Stdout.Write(collateral.TcbInfo)

	case CMD_QEIDENTITY:
		collateral, err := getCollateral()
		if err != nil {
			return fmt.Errorf("failed to get TDX collateral: %w", err)
		}
		os.Stdout.Write(collateral.QeIdentity)

	case CMD_FMSPC:
		fmspc, err := getFmspc()
		if err != nil {
			return fmt.Errorf("failed to get FMSPC: %w", err)
		}
		fmt.Printf("%v\n", fmspc)

	default:
		return fmt.Errorf("unknown cmd %q. See tdxquote -help", *cmd)

	}

	return nil
}

func getQuoteRaw() ([]byte, error) {
	nonce := make([]byte, 64)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce: %w", err)
	}

	data, err := tdxdriver.GetMeasurement(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get TDX Quote: %w", err)
	}

	return data, nil
}

func getQuote() (*verifier.TdxReportV4, error) {

	nonce := make([]byte, 64)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce: %w", err)
	}

	data, err := tdxdriver.GetMeasurement(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get TDX Quote: %w", err)
	}

	quote, err := verifier.DecodeTdxReportV4(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TDX quote: %w", err)
	}

	// Check nonce
	if !bytes.Equal(quote.QuoteBody.ReportData[:], nonce) {
		return nil, errors.New("freshness check failed for TDX quote")
	}

	return &quote, nil
}

func getCollateral() (*ar.IntelCollateral, error) {

	quote, err := getQuote()
	if err != nil {
		return nil, fmt.Errorf("failed to get quote: %v", err)
	}

	log.Tracef("PCK Leaf Certificate: %v",
		string(internal.WriteCertPem(quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert)))

	// Get FMSPC
	exts, err := pcs.PckCertificateExtensions(
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert)
	if err != nil {
		return nil, fmt.Errorf("failed to get PCK certificate extensions: %w", err)
	}
	log.Tracef("PCK FMSPC: %v", exts.FMSPC)

	// Fetch collateral
	collateral, err := verifier.FetchCollateral(exts.FMSPC,
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert, verifier.TDX_QUOTE_TYPE)
	if err != nil {
		return nil, fmt.Errorf("failed to get TDX collateral: %w", err)
	}

	return collateral, nil
}

func getQuoteCertChain() ([]byte, error) {

	quote, err := getQuote()
	if err != nil {
		return nil, fmt.Errorf("failed to get quote: %v", err)
	}

	certs := []*x509.Certificate{
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert,
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.IntermediateCert,
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.RootCACert,
	}

	pems := make([]byte, 0)
	for _, cert := range certs {
		pem := internal.WriteCertPem(cert)
		pems = append(pems, pem...)
	}
	return pems, nil
}

func getFmspc() (string, error) {

	quote, err := getQuote()
	if err != nil {
		return "", fmt.Errorf("failed to get quote: %v", err)
	}

	exts, err := pcs.PckCertificateExtensions(
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert)
	if err != nil {
		return "", fmt.Errorf("failed to get PCK certificate extensions: %w", err)
	}

	return exts.FMSPC, nil
}
