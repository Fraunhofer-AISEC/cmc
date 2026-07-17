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
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers/tdxdriver"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision/endorser"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-tdx-guest/pcs"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

const (
	inFlag     = "in"
	formatFlag = "format"

	formatCbor = "cbor"
	formatJson = "json"
)

type collateralSelector func(*ar.IntelCollateral) []byte

var collateralSelectors = map[string]collateralSelector{
	"get-tcbinfo":                       func(c *ar.IntelCollateral) []byte { return c.TcbInfo },
	"get-qeidentity":                    func(c *ar.IntelCollateral) []byte { return c.QeIdentity },
	"get-root-ca-crl":                   func(c *ar.IntelCollateral) []byte { return c.RootCaCrl },
	"get-pck-crl":                       func(c *ar.IntelCollateral) []byte { return c.PckCrl },
	"get-pck-crl-intermediate-cert":     func(c *ar.IntelCollateral) []byte { return c.PckCrlIntermediateCert },
	"get-pck-crl-root-cert":             func(c *ar.IntelCollateral) []byte { return c.PckCrlRootCert },
	"get-tcb-info-intermediate-cert":    func(c *ar.IntelCollateral) []byte { return c.TcbInfoIntermediateCert },
	"get-tcb-info-root-cert":            func(c *ar.IntelCollateral) []byte { return c.TcbInfoRootCert },
	"get-qe-identity-intermediate-cert": func(c *ar.IntelCollateral) []byte { return c.QeIdentityIntermediateCert },
	"get-qe-identity-root-cert":         func(c *ar.IntelCollateral) []byte { return c.QeIdentityRootCert },
}

func main() {

	log.SetLevel(log.TraceLevel)

	subcommands := []*cli.Command{
		{
			Name:  "get-quote",
			Usage: "Fetch a raw TDX quote from the platform",
			Action: func(ctx context.Context, cmd *cli.Command) error {
				quote, err := getQuoteRaw()
				if err != nil {
					return fmt.Errorf("failed to get TDX Quote: %w", err)
				}
				os.Stdout.Write(quote)
				return nil
			},
		},
		{
			Name:  "parse-quote",
			Usage: "Parse a TDX quote and log its fields",
			Flags: inFileFlag(),
			Action: func(ctx context.Context, cmd *cli.Command) error {
				return parseQuote(cmd.String(inFlag))
			},
		},
		{
			Name:  "parse-certchain",
			Usage: "Extract the certificate chain from a TDX quote",
			Flags: inFileFlag(),
			Action: func(ctx context.Context, cmd *cli.Command) error {
				out, err := parseQuoteCertChain(cmd.String(inFlag))
				if err != nil {
					return fmt.Errorf("failed to get TDX cert chain: %w", err)
				}
				os.Stdout.Write(out)
				return nil
			},
		},
		{
			Name:  "parse-pck-cert",
			Usage: "Extract the PCK certificate from a TDX quote",
			Flags: inFileFlag(),
			Action: func(ctx context.Context, cmd *cli.Command) error {
				out, err := parseQuotePCKCert(cmd.String(inFlag))
				if err != nil {
					return fmt.Errorf("failed to get TDX PCK cert: %w", err)
				}
				os.Stdout.Write(out)
				return nil
			},
		},
		{
			Name:  "parse-intermediate-cert",
			Usage: "Extract the intermediate certificate from a TDX quote",
			Flags: inFileFlag(),
			Action: func(ctx context.Context, cmd *cli.Command) error {
				out, err := parseQuoteIntermediateCert(cmd.String(inFlag))
				if err != nil {
					return fmt.Errorf("failed to get TDX intermediate cert: %w", err)
				}
				os.Stdout.Write(out)
				return nil
			},
		},
		{
			Name:  "parse-root-ca-cert",
			Usage: "Extract the Root CA certificate from a TDX quote",
			Flags: inFileFlag(),
			Action: func(ctx context.Context, cmd *cli.Command) error {
				out, err := parseQuoteRootCaCert(cmd.String(inFlag))
				if err != nil {
					return fmt.Errorf("failed to get TDX Root CA cert: %w", err)
				}
				os.Stdout.Write(out)
				return nil
			},
		},
		{
			Name:  "parse-fmspc",
			Usage: "Print the FMSPC extracted from a TDX quote's PCK cert",
			Flags: inFileFlag(),
			Action: func(ctx context.Context, cmd *cli.Command) error {
				fmspc, err := parseFmspc(cmd.String(inFlag))
				if err != nil {
					return fmt.Errorf("failed to parse FMSPC: %w", err)
				}
				fmt.Printf("%v\n", fmspc)
				return nil
			},
		},
		{
			Name:  "parse-tdreport",
			Usage: "Parse a TDREPORT structure and log its fields",
			Flags: inFileFlag(),
			Action: func(ctx context.Context, cmd *cli.Command) error {
				return parseTdReport(cmd.String(inFlag))
			},
		},
		{
			Name:  "parse-pck-cert-tcb",
			Usage: "Log the SGX-extension TCB fields from a TDX quote's PCK cert",
			Flags: inFileFlag(),
			Action: func(ctx context.Context, cmd *cli.Command) error {
				return parseQuotePCKCertTcb(cmd.String(inFlag))
			},
		},
		{
			Name:  "fetch-collateral",
			Usage: "Fetch the full TDX collateral for a quote",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     inFlag,
					Usage:    "input file (TDX quote binary)",
					Required: true,
				},
				&cli.StringFlag{
					Name:  formatFlag,
					Usage: "output format for the collateral blob [cbor, json]",
					Value: formatCbor,
				},
			},
			Action: func(ctx context.Context, cmd *cli.Command) error {
				return fetchCollateral(cmd.String(inFlag), cmd.String(formatFlag))
			},
		},
	}

	for name, selector := range collateralSelectors {
		subcommands = append(subcommands, collateralCommand(name, selector))
	}

	cmd := &cli.Command{
		Name:     "tdxtool",
		Usage:    "TDX quote and collateral inspection utility",
		Commands: subcommands,
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Errorf("%v", err)
		os.Exit(1)
	}
}

func inFileFlag() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:     inFlag,
			Usage:    "input file (TDX quote binary)",
			Required: true,
		},
	}
}

func collateralCommand(name string, selector collateralSelector) *cli.Command {
	return &cli.Command{
		Name: name,
		Usage: fmt.Sprintf("Extract field %q from a pre-fetched collateral blob (see fetch-collateral)",
			strings.TrimPrefix(name, "get-")),
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     inFlag,
				Usage:    "input file (TDX collateral blob written by fetch-collateral, CBOR or JSON)",
				Required: true,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			collateral, err := readCollateralBlob(cmd.String(inFlag))
			if err != nil {
				return fmt.Errorf("failed to read TDX collateral blob: %w", err)
			}
			os.Stdout.Write(selector(collateral))
			return nil
		},
	}
}

func fetchCollateral(quotePath, format string) error {
	collateral, err := getCollateral(quotePath)
	if err != nil {
		return fmt.Errorf("failed to fetch TDX collateral: %w", err)
	}

	var data []byte
	switch strings.ToLower(format) {
	case formatCbor:
		data, err = cbor.Marshal(collateral)
	case formatJson:
		data, err = json.MarshalIndent(collateral, "", "  ")
	default:
		return fmt.Errorf("unknown format %q (want %v or %v)", format, formatCbor, formatJson)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal collateral as %v: %w", format, err)
	}

	os.Stdout.Write(data)
	return nil
}

func readCollateralBlob(path string) (*ar.IntelCollateral, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read collateral blob: %w", err)
	}

	var c ar.IntelCollateral
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '{' {
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("failed to unmarshal collateral blob as JSON: %w", err)
		}
	} else {
		if err := cbor.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("failed to unmarshal collateral blob as CBOR: %w", err)
		}
	}
	return &c, nil
}

func getQuoteRaw() ([]byte, error) {
	nonce := make([]byte, 64)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce: %w", err)
	}

	data, err := tdxdriver.GetReport(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get TDX Quote: %w", err)
	}

	return data, nil
}

func getCollateral(in string) (*ar.IntelCollateral, error) {

	data, err := os.ReadFile(in)
	if err != nil {
		return nil, fmt.Errorf("failed to read quote: %w", err)
	}

	quote, err := verifier.DecodeTdxReportV4(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TDX quote: %w", err)
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
	endorser, err := endorser.NewTdxEndorser(endorser.PcsUrl, "", nil, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create TDX endorser: %w", err)
	}
	collateral, err := endorser.FetchCollateral(exts.FMSPC,
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert,
		ar.TDX_QUOTE_TYPE)
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

	log.Info("TDX Quote Body:")
	log.Infof("\tREPORTDATA     : %v", hex.EncodeToString(body.ReportData[:]))
	log.Infof("\tMRTD           : %v", hex.EncodeToString(body.MrTd[:]))
	log.Infof("\tRTMR0          : %v", hex.EncodeToString(body.RtMr0[:]))
	log.Infof("\tRTMR2          : %v", hex.EncodeToString(body.RtMr1[:]))
	log.Infof("\tRTMR2          : %v", hex.EncodeToString(body.RtMr2[:]))
	log.Infof("\tRTMR3          : %v", hex.EncodeToString(body.RtMr3[:]))
	log.Infof("\tMRCONFIGID     : %v", hex.EncodeToString(body.MrConfigId[:]))
	log.Infof("\tMROWNER        : %v", hex.EncodeToString(body.MrOwner[:]))
	log.Infof("\tMROWNERCONFIG  : %v", hex.EncodeToString(body.MrOwnerConfig[:]))
	log.Infof("\tMRSEAM         : %v", hex.EncodeToString(body.MrSeam[:]))
	log.Infof("\tMRSIGNERSEAM   : %v", hex.EncodeToString(body.MrSignerSeam[:]))
	log.Infof("\tSEAMATTRIBUTES : %v", hex.EncodeToString(body.SeamAttributes[:]))
	log.Infof("\tTDATTRIBUTES   : %v", hex.EncodeToString(body.TdAttributes[:]))
	log.Infof("\tTEETCBSVN      : %v", hex.EncodeToString(body.TeeTcbSvn[:]))
	log.Infof("\tXFAM           : %v", hex.EncodeToString(body.XFAM[:]))
	log.Info("TDX Quote Signature Data")
	log.Infof("\tAttestation key: %v", hex.EncodeToString(quote.QuoteSignatureData.ECDSAAttestationKey[:]))
	log.Infof("\tQuote Signature: %v", hex.EncodeToString(quote.QuoteSignatureData.QuoteSignature[:]))
	log.Infof("\tQECertDataType : %v", quote.QuoteSignatureData.QECertificationData.QECertificationDataType)
	log.Info("TDX Quote QE Report")
	log.Infof("\tAttributes     : %v", hex.EncodeToString(quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.QEReport.Attributes[:]))
	log.Infof("\tMRENCLAVE      : %v", hex.EncodeToString(quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.QEReport.MRENCLAVE[:]))
	log.Infof("\tMRSIGNER       : %v", hex.EncodeToString(quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.QEReport.MRSIGNER[:]))
	log.Infof("\tReportData     : %v", hex.EncodeToString(quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.QEReport.ReportData[:]))
	log.Infof("\tCPUSVN         : %v", hex.EncodeToString(quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.QEReport.CPUSVN[:]))
	log.Infof("\tMISCSELECT     : %v", quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.QEReport.MISCSELECT)
	log.Infof("\tISVSVN         : %v", quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.QEReport.ISVSVN)
	log.Infof("\tISVProdID      : %v", quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.QEReport.ISVProdID)

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

func parseQuotePCKCertTcb(in string) error {

	data, err := os.ReadFile(in)
	if err != nil {
		return fmt.Errorf("failed to read quote: %w", err)
	}

	quote, err := verifier.DecodeTdxReportV4(data)
	if err != nil {
		return fmt.Errorf("failed to decode TDX quote: %w", err)
	}

	cert := quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert

	// Skip the first value (not relevant)
	exts, err := verifier.ParseSGXExtensions(cert.Extensions[verifier.SGX_EXTENSION_INDEX].Value[4:])
	if err != nil {
		return fmt.Errorf("failed to parse SGX Extensions from PCK Certificate: %v", err)
	}

	log.Infof("PPID              : %v = %v", exts.Ppid.Id.String(), hex.EncodeToString(exts.Ppid.Value))
	log.Infof("TCB ID            : %v", exts.Tcb.Id.String())
	log.Infof("TCB Comp_01       : %v", getTcbComp(exts.Tcb.Value.Comp_01))
	log.Infof("TCB Comp_02       : %v", getTcbComp(exts.Tcb.Value.Comp_02))
	log.Infof("TCB Comp_03       : %v", getTcbComp(exts.Tcb.Value.Comp_03))
	log.Infof("TCB Comp_04       : %v", getTcbComp(exts.Tcb.Value.Comp_04))
	log.Infof("TCB Comp_05       : %v", getTcbComp(exts.Tcb.Value.Comp_05))
	log.Infof("TCB Comp_06       : %v", getTcbComp(exts.Tcb.Value.Comp_06))
	log.Infof("TCB Comp_07       : %v", getTcbComp(exts.Tcb.Value.Comp_07))
	log.Infof("TCB Comp_08       : %v", getTcbComp(exts.Tcb.Value.Comp_08))
	log.Infof("TCB Comp_09       : %v", getTcbComp(exts.Tcb.Value.Comp_09))
	log.Infof("TCB Comp_10       : %v", getTcbComp(exts.Tcb.Value.Comp_10))
	log.Infof("TCB Comp_11       : %v", getTcbComp(exts.Tcb.Value.Comp_11))
	log.Infof("TCB Comp_12       : %v", getTcbComp(exts.Tcb.Value.Comp_12))
	log.Infof("TCB Comp_13       : %v", getTcbComp(exts.Tcb.Value.Comp_13))
	log.Infof("TCB Comp_14       : %v", getTcbComp(exts.Tcb.Value.Comp_14))
	log.Infof("TCB Comp_15       : %v", getTcbComp(exts.Tcb.Value.Comp_15))
	log.Infof("TCB Comp_16       : %v", getTcbComp(exts.Tcb.Value.Comp_16))
	log.Infof("TCB PCESVN        : %v", getTcbComp(exts.Tcb.Value.PceSvn))
	log.Infof("TCB CPUSVN        : %v = %v", exts.Tcb.Value.CpuSvn.Svn.String(), hex.EncodeToString(exts.Tcb.Value.CpuSvn.Value))
	log.Infof("PCEID             : %v = %v", exts.PceId.Id.String(), hex.EncodeToString(exts.PceId.Value))
	log.Infof("FMSPC             : %v = %v", exts.Fmspc.Id.String(), hex.EncodeToString(exts.Fmspc.Value))
	log.Infof("SGX Type          : %v = %v", exts.SgxType.Id.String(), exts.SgxType.Value)
	log.Infof("PlatformInstanceId: %v = %v", exts.PlatformInstanceId.Id.String(), hex.EncodeToString(exts.PlatformInstanceId.Value))

	return nil

}

func getTcbComp(in verifier.TCBComp) string {
	return fmt.Sprintf("%v = %v", in.Svn.String(), in.Value)
}
