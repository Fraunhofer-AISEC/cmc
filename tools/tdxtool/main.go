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

	log.SetLevel(log.TraceLevel)

	err := run()
	if err != nil {
		log.Errorf("%v", err)
	}
}

const (
	CMD_GET_QUOTE               = "get-quote"
	CMD_GET_TCBINFO             = "get-tcbinfo"
	CMD_GET_QEIDENTITY          = "get-qeidentity"
	CMD_PARSE_CERTCHAIN         = "parse-certchain"
	CMD_PARSE_PCK_CERT          = "parse-pck-cert"
	CMD_PARSE_INTERMEDIATE_CERT = "parse-intermediate-cert"
	CMD_PARSE_ROOT_CA_CERT      = "parse-root-ca-cert"
	CMD_PARSE_FMSPC             = "parse-fmspc"
	CMD_PARSE_QUOTE             = "parse-quote"
	CMD_PARSE_TDREPORT          = "parse-tdreport"
)

func run() error {

	cmd := flag.String("cmd", "", fmt.Sprintf("command to run: %v, %v, %v, %v, %v, %v, %v, %v, %v, %v",
		CMD_GET_QUOTE,
		CMD_GET_TCBINFO,
		CMD_GET_QEIDENTITY,
		CMD_PARSE_CERTCHAIN,
		CMD_PARSE_PCK_CERT,
		CMD_PARSE_INTERMEDIATE_CERT,
		CMD_PARSE_ROOT_CA_CERT,
		CMD_PARSE_FMSPC,
		CMD_PARSE_QUOTE,
		CMD_PARSE_TDREPORT,
	))
	in := flag.String("in", "", "input file")
	flag.Parse()

	if *cmd == CMD_PARSE_FMSPC || *cmd == CMD_PARSE_QUOTE || *cmd == CMD_PARSE_TDREPORT {
		if *in == "" {
			return fmt.Errorf("missing parameter -in")
		}
	}

	switch *cmd {

	case CMD_GET_QUOTE:
		quote, err := getQuoteRaw()
		if err != nil {
			return fmt.Errorf("failed to get TDX Quote: %w", err)
		}
		os.Stdout.Write(quote)

	case CMD_GET_TCBINFO:
		collateral, err := getCollateral()
		if err != nil {
			return fmt.Errorf("failed to get TDX collateral: %w", err)
		}
		os.Stdout.Write(collateral.TcbInfo)

	case CMD_GET_QEIDENTITY:
		collateral, err := getCollateral()
		if err != nil {
			return fmt.Errorf("failed to get TDX collateral: %w", err)
		}
		os.Stdout.Write(collateral.QeIdentity)

	case CMD_PARSE_CERTCHAIN:
		certChain, err := parseQuoteCertChain(*in)
		if err != nil {
			return fmt.Errorf("failed to get TDX cert chain: %w", err)
		}
		os.Stdout.Write(certChain)

	case CMD_PARSE_PCK_CERT:
		certChain, err := parseQuotePCKCert(*in)
		if err != nil {
			return fmt.Errorf("failed to get TDX PCK cert: %w", err)
		}
		os.Stdout.Write(certChain)

	case CMD_PARSE_INTERMEDIATE_CERT:
		certChain, err := parseQuoteIntermediateCert(*in)
		if err != nil {
			return fmt.Errorf("failed to get TDX intermediate cert: %w", err)
		}
		os.Stdout.Write(certChain)

	case CMD_PARSE_ROOT_CA_CERT:
		certChain, err := parseQuoteRootCaCert(*in)
		if err != nil {
			return fmt.Errorf("failed to get TDX Root CA cert: %w", err)
		}
		os.Stdout.Write(certChain)

	case CMD_PARSE_FMSPC:
		fmspc, err := parseFmspc(*in)
		if err != nil {
			return fmt.Errorf("failed to parse FMSPC: %w", err)
		}
		fmt.Printf("%v\n", fmspc)

	case CMD_PARSE_QUOTE:
		err := parseQuote(*in)
		if err != nil {
			return fmt.Errorf("failed to parse quote")
		}

	case CMD_PARSE_TDREPORT:
		err := parseTdReport(*in)
		if err != nil {
			return fmt.Errorf("failed to parse TDREPORT")
		}

	default:
		return fmt.Errorf("unknown cmd %q. See tdxtool -help", *cmd)

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

func parseQuoteCertChain(in string) ([]byte, error) {

	data, err := os.ReadFile(in)
	if err != nil {
		return nil, fmt.Errorf("failed to read quote: %w", err)
	}

	quote, err := verifier.DecodeTdxReportV4(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TDX quote: %w", err)
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

func parseQuotePCKCert(in string) ([]byte, error) {

	data, err := os.ReadFile(in)
	if err != nil {
		return nil, fmt.Errorf("failed to read quote: %w", err)
	}

	quote, err := verifier.DecodeTdxReportV4(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TDX quote: %w", err)
	}

	cert := quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert
	pem := internal.WriteCertPem(cert)

	return pem, nil

}

func parseQuoteIntermediateCert(in string) ([]byte, error) {

	data, err := os.ReadFile(in)
	if err != nil {
		return nil, fmt.Errorf("failed to read quote: %w", err)
	}

	quote, err := verifier.DecodeTdxReportV4(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TDX quote: %w", err)
	}

	cert := quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.IntermediateCert
	pem := internal.WriteCertPem(cert)

	return pem, nil
}

func parseQuoteRootCaCert(in string) ([]byte, error) {

	data, err := os.ReadFile(in)
	if err != nil {
		return nil, fmt.Errorf("failed to read quote: %w", err)
	}

	quote, err := verifier.DecodeTdxReportV4(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TDX quote: %w", err)
	}

	cert := quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.RootCACert
	pem := internal.WriteCertPem(cert)

	return pem, nil
}

func parseFmspc(in string) (string, error) {

	data, err := os.ReadFile(in)
	if err != nil {
		return "", fmt.Errorf("failed to read quote: %w", err)
	}

	quote, err := verifier.DecodeTdxReportV4(data)
	if err != nil {
		return "", fmt.Errorf("failed to decode TDX quote: %w", err)
	}

	exts, err := pcs.PckCertificateExtensions(
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert)
	if err != nil {
		return "", fmt.Errorf("failed to get PCK certificate extensions: %w", err)
	}

	return exts.FMSPC, nil
}

func parseQuote(in string) error {

	data, err := os.ReadFile(in)
	if err != nil {
		return fmt.Errorf("failed to read quote: %w", err)
	}

	quote, err := verifier.DecodeTdxReportV4(data)
	if err != nil {
		return fmt.Errorf("failed to decode TDX quote: %w", err)
	}
	body := quote.QuoteBody

	log.Info("TDX Quote:")
	log.Infof("\tREPORTDATA    : %v", hex.EncodeToString(body.ReportData[:]))
	log.Infof("\tMRTD          : %v", hex.EncodeToString(body.MrTd[:]))
	log.Infof("\tRTMR0         : %v", hex.EncodeToString(body.RtMr0[:]))
	log.Infof("\tRTMR2         : %v", hex.EncodeToString(body.RtMr1[:]))
	log.Infof("\tRTMR2         : %v", hex.EncodeToString(body.RtMr2[:]))
	log.Infof("\tRTMR3         : %v", hex.EncodeToString(body.RtMr3[:]))
	log.Infof("\tMRCONFIGID    : %v", hex.EncodeToString(body.MrConfigId[:]))
	log.Infof("\tMROWNER       : %v", hex.EncodeToString(body.MrOwner[:]))
	log.Infof("\tMROWNERCONFIG : %v", hex.EncodeToString(body.MrOwnerConfig[:]))
	log.Infof("\tMRSEAM        : %v", hex.EncodeToString(body.MrSeam[:]))
	log.Infof("\tMRSIGNERSEAM  : %v", hex.EncodeToString(body.MrSignerSeam[:]))
	log.Infof("\tSEAMATTRIBUTES: %v", hex.EncodeToString(body.SeamAttributes[:]))
	log.Infof("\tTDATTRIBUTES  : %v", hex.EncodeToString(body.TdAttributes[:]))
	log.Infof("\tTEETCBSVN     : %v", hex.EncodeToString(body.TeeTcbSvn[:]))
	log.Infof("\tXFAM          : %v", hex.EncodeToString(body.XFAM[:]))

	return nil
}

func parseTdReport(in string) error {

	data, err := os.ReadFile(in)
	if err != nil {
		return fmt.Errorf("failed to read quote: %w", err)
	}

	tdReport, err := verifier.DecodeTdReport(data)
	if err != nil {
		return fmt.Errorf("failed to decode TDREPORT: %w", err)
	}

	log.Info("TDREPORT:")
	log.Infof("\tREPORTDATA: %v", hex.EncodeToString(tdReport.ReportMacStruct.ReportData[:]))
	log.Infof("\tMRTD      : %v", hex.EncodeToString(tdReport.TdInfo.Mrtd[:]))
	log.Infof("\tRTMR0     : %v", hex.EncodeToString(tdReport.TdInfo.RtMr0[:]))
	log.Infof("\tRTMR2     : %v", hex.EncodeToString(tdReport.TdInfo.RtMr1[:]))
	log.Infof("\tRTMR2     : %v", hex.EncodeToString(tdReport.TdInfo.RtMr2[:]))
	log.Infof("\tRTMR3     : %v", hex.EncodeToString(tdReport.TdInfo.RtMr3[:]))

	return nil
}
