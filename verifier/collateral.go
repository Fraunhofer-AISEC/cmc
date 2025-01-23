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

package verifier

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/google/go-tdx-guest/pcs"
)

func FetchCollateral(fmspc string, pckcert *x509.Certificate, quoteType QuoteType) (*ar.IntelCollateral, error) {

	caType, err := getCaTypeFromPck(pckcert)
	if err != nil {
		return nil, fmt.Errorf("failed to get CA type from PCK cert")
	}

	log.Debug("Fetching TCB Info from Intel PCS")
	tcbInfo, interTcbInfo, rootTcbInfo, err := fetchTcbInfo(fmspc, quoteType)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch TCB info: %w", err)
	}

	log.Debug("Fetching QE Identity from Intel PCS")
	qeIdentity, interQe, rootQe, err := fetchQeIdentity(quoteType)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch QE identity: %w", err)
	}

	log.Debugf("Fetching PCK %v CRL from Intel PCS", caType)
	pckCrl, interPckCrl, rootPckCrl, err := fetchPckCrl(caType)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch PCK CRL: %w", err)
	}

	log.Debug("Fetching root CA CRL from Intel PCS")
	rootCrl, err := fetchRootCrl(rootQe.CRLDistributionPoints)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Root CA CRL: %w", err)
	}

	return &ar.IntelCollateral{
		TcbInfo:                    tcbInfo,
		TcbInfoIntermediateCert:    interTcbInfo.Raw,
		TcbInfoRootCert:            rootTcbInfo.Raw,
		QeIdentity:                 qeIdentity,
		QeIdentityIntermediateCert: interQe.Raw,
		QeIdentityRootCert:         rootQe.Raw,
		RootCaCrl:                  rootCrl.Raw,
		PckCrl:                     pckCrl.Raw,
		PckCrlIntermediateCert:     interPckCrl.Raw,
		PckCrlRootCert:             rootPckCrl.Raw,
	}, nil
}

func fetchTcbInfo(fmspc string, quoteType QuoteType) ([]byte, *x509.Certificate, *x509.Certificate, error) {

	var tcbInfoUrl string
	if quoteType == TDX_QUOTE_TYPE {
		tcbInfoUrl = pcs.TcbInfoURL(fmspc)
	} else if quoteType == SGX_QUOTE_TYPE {
		tcbInfoUrl = fmt.Sprintf("https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc=%v", fmspc)
	} else {
		return nil, nil, nil, fmt.Errorf("unknown quote type %v", quoteType)
	}
	log.Debugf("Fetching TCB Info for FMSPC %v from: %v", fmspc, tcbInfoUrl)

	resp, err := http.Get(tcbInfoUrl)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get HTTPS TCB Info response: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read HTTPS TCB Info body: %w", err)
	}

	inter, root, err := extractChainFromHeader(resp.Header, pcs.TcbInfoIssuerChainPhrase)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to extract TCB info issuer cert chain from HTTPS header: %w", err)
	}

	return body, inter, root, nil
}

func fetchQeIdentity(quoteType QuoteType) ([]byte, *x509.Certificate, *x509.Certificate, error) {

	var qeIdentityUrl string
	if quoteType == TDX_QUOTE_TYPE {
		qeIdentityUrl = pcs.QeIdentityURL()
	} else if quoteType == SGX_QUOTE_TYPE {
		qeIdentityUrl = "https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity"
	} else {
		return nil, nil, nil, fmt.Errorf("unknown quote type %v", quoteType)
	}
	log.Debugf("Fetching QE Identity: %v", qeIdentityUrl)

	resp, err := http.Get(qeIdentityUrl)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get HTTPS QE identity response: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read HTTPS TCB Info body: %w", err)
	}

	inter, root, err := extractChainFromHeader(resp.Header, pcs.SgxQeIdentityIssuerChainPhrase)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to extract TCB info issuer cert chain from HTTPS header: %w", err)
	}

	return body, inter, root, nil
}

func fetchPckCrl(ca string) (*x509.RevocationList, *x509.Certificate, *x509.Certificate, error) {

	pckCrlUrl := pcs.PckCrlURL(ca)
	log.Debugf("Fetching PCK CRL: %v", pckCrlUrl)

	resp, err := http.Get(pckCrlUrl)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to fetch PCK CRL: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read HTTPS PCK CRL body: %w", err)
	}

	inter, root, err := extractChainFromHeader(resp.Header, pcs.SgxPckCrlIssuerChainPhrase)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to extract PCK CRL issuer cert chain from header: %w", err)
	}

	pckCrl, err := x509.ParseRevocationList(body)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse PCK CRL from %v: %w", pckCrlUrl, err)
	}

	return pckCrl, inter, root, nil
}

func fetchRootCrl(urls []string) (*x509.RevocationList, error) {

	if len(urls) == 0 {
		return nil, fmt.Errorf("root CA CRLs are empty")
	}

	log.Debugf("Fetching Root CA CRLs from: %v", urls)
	for _, url := range urls {
		resp, err := http.Get(url)
		if err != nil {
			log.Warnf("failed to fetch root CA CRL from %v: %v", url, err)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Warnf("failed to read HTTPS root CA CRL body from %v: %v", url, err)
			continue
		}
		rootCrl, err := x509.ParseRevocationList(body)
		if err != nil {
			log.Warnf("failed to parse root CA CRL from %v: %v", url, err)
		}
		return rootCrl, nil
	}

	return nil, fmt.Errorf("failed to fetch root CA CRL from locations: %v", urls)
}

func extractChainFromHeader(header map[string][]string, phrase string) (*x509.Certificate, *x509.Certificate, error) {

	h, ok := header[phrase]
	if !ok {
		return nil, nil, fmt.Errorf("header %v does not exist", phrase)
	}
	if len(h) != 1 {
		return nil, nil, fmt.Errorf("unexpeted issuer chain length %v", len(h))
	}

	chain, err := url.QueryUnescape(h[0])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode issuer chain in %v: %w", phrase, err)
	}

	block, rem := pem.Decode([]byte(chain))
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM-formatted certificate from %v", phrase)
	}
	intermediate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse intermediate certificate from %v: %w", phrase, err)
	}
	log.Tracef("Parsed certificate CN=%v", intermediate.Subject.CommonName)

	block, rem = pem.Decode(rem)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM-formatted certificate from %v", phrase)
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse intermediate certificate from %v: %w", phrase, err)
	}
	log.Tracef("Parsed certificate CN=%v", root.Subject.CommonName)

	if len(rem) != 0 {
		return nil, nil, fmt.Errorf("issuer chain of unexpected length")
	}

	// return intermediate and root certificate
	return intermediate, root, nil
}

func getCaTypeFromPck(pck *x509.Certificate) (string, error) {

	if pck.Issuer.CommonName == "Intel SGX PCK Platform CA" {
		return "platform", nil
	}
	if pck.Issuer.CommonName == "Intel SGX PCK Processor CA" {
		return "processor", nil
	}
	return "", fmt.Errorf("failed to get PCK CA type from PCK cert")
}
