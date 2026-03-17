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
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
	"os"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers/sgxdriver"
	"github.com/Fraunhofer-AISEC/cmc/internal"
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

type collateralSelector func(*ar.IntelCollateral) []byte

var collateralCommands = map[string]collateralSelector{
	CMD_GET_TCBINFO:                func(c *ar.IntelCollateral) []byte { return c.TcbInfo },
	CMD_GET_QEIDENTITY:             func(c *ar.IntelCollateral) []byte { return c.QeIdentity },
	CMD_GET_ROOT_CA_CRL:            func(c *ar.IntelCollateral) []byte { return c.RootCaCrl },
	CMD_GET_PCK_CRL:                func(c *ar.IntelCollateral) []byte { return c.PckCrl },
	CMD_GET_PCK_CRL_INTER_CERT:     func(c *ar.IntelCollateral) []byte { return c.PckCrlIntermediateCert },
	CMD_GET_PCK_CRL_ROOT_CERT:      func(c *ar.IntelCollateral) []byte { return c.PckCrlRootCert },
	CMD_GET_TCB_INFO_INTER_CERT:    func(c *ar.IntelCollateral) []byte { return c.TcbInfoIntermediateCert },
	CMD_GET_TCB_INFO_ROOT_CERT:     func(c *ar.IntelCollateral) []byte { return c.TcbInfoRootCert },
	CMD_GET_QE_IDENTITY_INTER_CERT: func(c *ar.IntelCollateral) []byte { return c.QeIdentityIntermediateCert },
	CMD_GET_QE_IDENTITY_ROOT_CERT:  func(c *ar.IntelCollateral) []byte { return c.QeIdentityRootCert },
}

const (
	// Quote commands
	CMD_GET_QUOTE               = "get-quote"
	CMD_PARSE_QUOTE             = "parse-quote"
	CMD_PARSE_CERTCHAIN         = "parse-certchain"
	CMD_PARSE_PCK_CERT          = "parse-pck-cert"
	CMD_PARSE_INTERMEDIATE_CERT = "parse-intermediate-cert"
	CMD_PARSE_ROOT_CA_CERT      = "parse-root-ca-cert"
	CMD_PARSE_FMSPC             = "parse-fmspc"
	CMD_PARSE_PCKCERT_TCB       = "parse-pck-cert-tcb"

	// Collateral commands
	CMD_GET_TCBINFO                = "get-tcbinfo"
	CMD_GET_QEIDENTITY             = "get-qeidentity"
	CMD_GET_ROOT_CA_CRL            = "get-root-ca-crl"
	CMD_GET_PCK_CRL                = "get-pck-crl"
	CMD_GET_PCK_CRL_INTER_CERT     = "get-pck-crl-intermediate-cert"
	CMD_GET_PCK_CRL_ROOT_CERT      = "get-pck-crl-root-cert"
	CMD_GET_TCB_INFO_INTER_CERT    = "get-tcb-info-intermediate-cert"
	CMD_GET_TCB_INFO_ROOT_CERT     = "get-tcb-info-root-cert"
	CMD_GET_QE_IDENTITY_INTER_CERT = "get-qe-identity-intermediate-cert"
	CMD_GET_QE_IDENTITY_ROOT_CERT  = "get-qe-identity-root-cert"
)

func run() error {

	cmd := flag.String("cmd", "",
		fmt.Sprintf("command to run: %v, %v, %v, %v, %v, %v, %v, %v, %v, %v, %v, %v, %v, %v, %v, %v, %v, %v",
			CMD_GET_QUOTE,
			CMD_PARSE_CERTCHAIN,
			CMD_PARSE_PCK_CERT,
			CMD_PARSE_INTERMEDIATE_CERT,
			CMD_PARSE_ROOT_CA_CERT,
			CMD_PARSE_FMSPC,
			CMD_PARSE_QUOTE,
			CMD_PARSE_PCKCERT_TCB,
			CMD_GET_TCBINFO,
			CMD_GET_QEIDENTITY,
			CMD_GET_ROOT_CA_CRL,
			CMD_GET_PCK_CRL,
			CMD_GET_PCK_CRL_INTER_CERT,
			CMD_GET_PCK_CRL_ROOT_CERT,
			CMD_GET_TCB_INFO_INTER_CERT,
			CMD_GET_TCB_INFO_ROOT_CERT,
			CMD_GET_QE_IDENTITY_INTER_CERT,
			CMD_GET_QE_IDENTITY_ROOT_CERT,
		))
	in := flag.String("in", "", "input file")
	flag.Parse()

	if *cmd == CMD_PARSE_QUOTE ||
		*cmd == CMD_GET_TCBINFO ||
		*cmd == CMD_GET_QEIDENTITY ||
		*cmd == CMD_GET_ROOT_CA_CRL ||
		*cmd == CMD_GET_PCK_CRL ||
		*cmd == CMD_GET_PCK_CRL_INTER_CERT ||
		*cmd == CMD_GET_PCK_CRL_ROOT_CERT ||
		*cmd == CMD_GET_TCB_INFO_INTER_CERT ||
		*cmd == CMD_GET_TCB_INFO_ROOT_CERT ||
		*cmd == CMD_GET_QE_IDENTITY_INTER_CERT ||
		*cmd == CMD_GET_QE_IDENTITY_ROOT_CERT {
		if *in == "" {
			return fmt.Errorf("missing parameter -in")
		}
	}

	switch *cmd {

	case CMD_GET_QUOTE:
		quote, err := getQuoteRaw()
		if err != nil {
			return fmt.Errorf("failed to get SGX Quote: %w", err)
		}
		os.Stdout.Write(quote)

	case CMD_PARSE_QUOTE:
		err := parseQuote(*in)
		if err != nil {
			return fmt.Errorf("failed to parse quote")
		}

	case CMD_PARSE_CERTCHAIN:
		certChain, err := parseQuoteCertChain(*in)
		if err != nil {
			return fmt.Errorf("failed to get SGX cert chain: %w", err)
		}
		os.Stdout.Write(certChain)

	case CMD_PARSE_PCK_CERT:
		certChain, err := parseQuotePCKCert(*in)
		if err != nil {
			return fmt.Errorf("failed to get SGX PCK cert: %w", err)
		}
		os.Stdout.Write(certChain)

	case CMD_PARSE_INTERMEDIATE_CERT:
		certChain, err := parseQuoteIntermediateCert(*in)
		if err != nil {
			return fmt.Errorf("failed to get SGX intermediate cert: %w", err)
		}
		os.Stdout.Write(certChain)

	case CMD_PARSE_ROOT_CA_CERT:
		certChain, err := parseQuoteRootCaCert(*in)
		if err != nil {
			return fmt.Errorf("failed to get SGX Root CA cert: %w", err)
		}
		os.Stdout.Write(certChain)

	case CMD_PARSE_FMSPC:
		fmspc, err := parseFmspc(*in)
		if err != nil {
			return fmt.Errorf("failed to parse FMSPC: %w", err)
		}
		fmt.Printf("%v\n", fmspc)

	case CMD_PARSE_PCKCERT_TCB:
		err := parseQuotePCKCertTcb(*in)
		if err != nil {
			return fmt.Errorf("failed to get SGX PCK cert: %w", err)
		}

	default:
		if selector, ok := collateralCommands[*cmd]; ok {
			collateral, err := getCollateral(*in)
			if err != nil {
				return fmt.Errorf("failed to get SGX collateral: %w", err)
			}
			os.Stdout.Write(selector(collateral))
			return nil
		} else {
			return fmt.Errorf("unknown cmd %q. See sgxtool -help", *cmd)
		}

	}

	return nil
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
	collateral, err := verifier.FetchCollateral(exts.FMSPC, quoteCerts.PCKCert, verifier.SGX_QUOTE_TYPE)
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
	log.Infof("\tMRCONFIGID     : %v", body.ISVProdID)
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
