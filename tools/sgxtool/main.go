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
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers/sgxdriver"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision/endorser"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/google/go-tdx-guest/pcs"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

const (
	inFlag = "in"
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
			Usage: "Fetch a raw SGX quote from the platform",
			Action: func(ctx context.Context, cmd *cli.Command) error {
				quote, err := getQuoteRaw()
				if err != nil {
					return fmt.Errorf("failed to get SGX Quote: %w", err)
				}
				os.Stdout.Write(quote)
				return nil
			},
		},
		{
			Name:  "parse-quote",
			Usage: "Parse an SGX quote and log its fields",
			Flags: inFileFlag(),
			Action: func(ctx context.Context, cmd *cli.Command) error {
				return parseQuote(cmd.String(inFlag))
			},
		},
		{
			Name:  "parse-certchain",
			Usage: "Extract the certificate chain from an SGX quote",
			Flags: inFileFlag(),
			Action: func(ctx context.Context, cmd *cli.Command) error {
				out, err := parseQuoteCertChain(cmd.String(inFlag))
				if err != nil {
					return fmt.Errorf("failed to get SGX cert chain: %w", err)
				}
				os.Stdout.Write(out)
				return nil
			},
		},
		{
			Name:  "parse-pck-cert",
			Usage: "Extract the PCK certificate from an SGX quote",
			Flags: inFileFlag(),
			Action: func(ctx context.Context, cmd *cli.Command) error {
				out, err := parseQuotePCKCert(cmd.String(inFlag))
				if err != nil {
					return fmt.Errorf("failed to get SGX PCK cert: %w", err)
				}
				os.Stdout.Write(out)
				return nil
			},
		},
		{
			Name:  "parse-intermediate-cert",
			Usage: "Extract the intermediate certificate from an SGX quote",
			Flags: inFileFlag(),
			Action: func(ctx context.Context, cmd *cli.Command) error {
				out, err := parseQuoteIntermediateCert(cmd.String(inFlag))
				if err != nil {
					return fmt.Errorf("failed to get SGX intermediate cert: %w", err)
				}
				os.Stdout.Write(out)
				return nil
			},
		},
		{
			Name:  "parse-root-ca-cert",
			Usage: "Extract the Root CA certificate from an SGX quote",
			Flags: inFileFlag(),
			Action: func(ctx context.Context, cmd *cli.Command) error {
				out, err := parseQuoteRootCaCert(cmd.String(inFlag))
				if err != nil {
					return fmt.Errorf("failed to get SGX Root CA cert: %w", err)
				}
				os.Stdout.Write(out)
				return nil
			},
		},
		{
			Name:  "parse-fmspc",
			Usage: "Print the FMSPC extracted from an SGX quote's PCK cert",
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
			Name:  "parse-pck-cert-tcb",
			Usage: "Log the SGX-extension TCB fields from an SGX quote's PCK cert",
			Flags: inFileFlag(),
			Action: func(ctx context.Context, cmd *cli.Command) error {
				return parseQuotePCKCertTcb(cmd.String(inFlag))
			},
		},
	}

	// Register collateral subcommands
	for name, selector := range collateralSelectors {
		subcommands = append(subcommands, collateralCommand(name, selector))
	}

	cmd := &cli.Command{
		Name:     "sgxtool",
		Usage:    "SGX quote and collateral inspection utility",
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
			Usage:    "input file (SGX quote binary)",
			Required: true,
		},
	}
}

func collateralCommand(name string, selector collateralSelector) *cli.Command {
	return &cli.Command{
		Name: name,
		Usage: fmt.Sprintf("Fetch collateral and extract field %q",
			strings.TrimPrefix(name, "get-")),
		Flags: inFileFlag(),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			collateral, err := getCollateral(cmd.String(inFlag))
			if err != nil {
				return fmt.Errorf("failed to get SGX collateral: %w", err)
			}
			os.Stdout.Write(selector(collateral))
			return nil
		},
	}
}

func getQuoteRaw() ([]byte, error) {
	nonce := make([]byte, 64)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce: %w", err)
	}

	data, err := sgxdriver.GetQuote(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get SGX Quote: %w", err)
	}

	return data, nil
}

func getQuoteCertChain(in string) (*verifier.SgxCertificates, error) {
	data, err := os.ReadFile(in)
	if err != nil {
		return nil, fmt.Errorf("failed to read quote: %w", err)
	}

	quote, err := verifier.DecodeSgxReport(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SGX quote: %w", err)
	}

	quoteCerts, err := verifier.ParseCertificates(quote.QuoteSignatureData.QECertData, true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate chain from QECertData: %w", err)
	}
	return &quoteCerts, nil
}

func getCollateral(in string) (*ar.IntelCollateral, error) {

	quoteCerts, err := getQuoteCertChain(in)
	if err != nil {
		return nil, fmt.Errorf("failed to extract quote certificate chain: %w", err)
	}

	log.Tracef("PCK Leaf Certificate: %v",
		string(internal.WriteCertPem(quoteCerts.PCKCert)))

	// Get FMSPC
	exts, err := pcs.PckCertificateExtensions(quoteCerts.PCKCert)
	if err != nil {
		return nil, fmt.Errorf("failed to get PCK certificate extensions: %w", err)
	}
	log.Tracef("PCK FMSPC: %v", exts.FMSPC)

	// Fetch collateral
	endorser, err := endorser.NewTdxEndorser(endorser.PcsUrl, "", nil, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create TDX endorser: %w", err)
	}
	collateral, err := endorser.FetchCollateral(exts.FMSPC, quoteCerts.PCKCert,
		ar.SGX_QUOTE_TYPE)
	if err != nil {
		return nil, fmt.Errorf("failed to get SGX collateral: %w", err)
	}

	return collateral, nil
}

func parseQuoteCertChain(in string) ([]byte, error) {

	quoteCerts, err := getQuoteCertChain(in)
	if err != nil {
		return nil, fmt.Errorf("failed to extract quote certificate chain: %w", err)
	}

	certs := []*x509.Certificate{
		quoteCerts.PCKCert,
		quoteCerts.IntermediateCert,
		quoteCerts.RootCACert,
	}

	pems := make([]byte, 0)
	for _, cert := range certs {
		pem := internal.WriteCertPem(cert)
		pems = append(pems, pem...)
	}
	return pems, nil
}

func parseQuotePCKCert(in string) ([]byte, error) {

	quoteCerts, err := getQuoteCertChain(in)
	if err != nil {
		return nil, fmt.Errorf("failed to extract quote certificate chain: %w", err)
	}

	pem := internal.WriteCertPem(quoteCerts.PCKCert)

	return pem, nil

}

func parseQuoteIntermediateCert(in string) ([]byte, error) {

	quoteCerts, err := getQuoteCertChain(in)
	if err != nil {
		return nil, fmt.Errorf("failed to extract quote certificate chain: %w", err)
	}

	pem := internal.WriteCertPem(quoteCerts.IntermediateCert)

	return pem, nil
}

func parseQuoteRootCaCert(in string) ([]byte, error) {

	quoteCerts, err := getQuoteCertChain(in)
	if err != nil {
		return nil, fmt.Errorf("failed to extract quote certificate chain: %w", err)
	}

	pem := internal.WriteCertPem(quoteCerts.RootCACert)

	return pem, nil
}

func parseFmspc(in string) (string, error) {

	quoteCerts, err := getQuoteCertChain(in)
	if err != nil {
		return "", fmt.Errorf("failed to extract quote certificate chain: %w", err)
	}

	exts, err := pcs.PckCertificateExtensions(
		quoteCerts.PCKCert)
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

	quote, err := verifier.DecodeSgxReport(data)
	if err != nil {
		return fmt.Errorf("failed to decode SGX quote: %w", err)
	}
	body := quote.ISVEnclaveReport

	log.Info("SGX Quote Body:")
	log.Infof("\tREPORTDATA     : %x", body.ReportData[:])
	log.Infof("\tMRTD           : %x", body.CPUSVN[:])
	log.Infof("\tRTMR0          : %v", body.MISCSELECT)
	log.Infof("\tRTMR2          : %x", body.Attributes[:])
	log.Infof("\tRTMR2          : %x", body.MRENCLAVE[:])
	log.Infof("\tRTMR3          : %x", body.MRSIGNER[:])
	log.Infof("\tISVPRODID      : %v", body.ISVProdID)
	log.Infof("\tMRCONFIGID     : %v", body.ISVSVN)

	return nil
}

func parseQuotePCKCertTcb(in string) error {

	quoteCerts, err := getQuoteCertChain(in)
	if err != nil {
		return fmt.Errorf("failed to extract quote certificate chain: %w", err)
	}

	// Skip the first value (not relevant)
	exts, err := verifier.ParseSGXExtensions(quoteCerts.PCKCert.Extensions[verifier.SGX_EXTENSION_INDEX].Value[4:])
	if err != nil {
		return fmt.Errorf("failed to parse SGX Extensions from PCK Certificate: %v", err)
	}

	log.Infof("PPID              : %v = %x", exts.Ppid.Id.String(), exts.Ppid.Value)
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
	log.Infof("TCB CPUSVN        : %v = %x", exts.Tcb.Value.CpuSvn.Svn.String(), exts.Tcb.Value.CpuSvn.Value)
	log.Infof("PCEID             : %v = %x", exts.PceId.Id.String(), exts.PceId.Value)
	log.Infof("FMSPC             : %v = %x", exts.Fmspc.Id.String(), exts.Fmspc.Value)
	log.Infof("SGX Type          : %v = %v", exts.SgxType.Id.String(), exts.SgxType.Value)
	log.Infof("PlatformInstanceId: %v = %x", exts.PlatformInstanceId.Id.String(), exts.PlatformInstanceId.Value)

	return nil

}

func getTcbComp(in verifier.TCBComp) string {
	return fmt.Sprintf("%v = %v", in.Svn.String(), in.Value)
}
