// Copyright (c) 2026 Fraunhofer AISEC
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

package provision

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers"
	"github.com/google/go-tdx-guest/pcs"
)

const tdxCacheTtl = 24 * time.Hour

type TdxEndorser struct {
	baseUrl string
	cache   *tdxCache
}

// Implement the EndorserProvider interface
func (endorser *TdxEndorser) Snp() (drivers.SnpEndorser, bool) {
	return nil, false
}

func (endorser *TdxEndorser) Tdx() (drivers.TdxEndorser, bool) {
	return endorser, true
}

func (endorser *TdxEndorser) Tpm() (drivers.TpmEndorser, bool) {
	return nil, false
}

// NewTdxEndorser initializes a new TDX endorser. baseUrl is the address of the
// collateral server (Intel PCS or custom PCCS). If a cacheFolder is specified,
// collateral is also cached to disk
func NewTdxEndorser(baseUrl, cacheFolder string) *TdxEndorser {
	return &TdxEndorser{
		baseUrl: strings.TrimRight(baseUrl, "/"),
		cache:   newTdxCache(cacheFolder, tdxCacheTtl),
	}
}

func (endorser *TdxEndorser) FetchCollateral(
	fmspc string,
	pckcert *x509.Certificate,
	quoteType ar.IntelQuoteType,
) (*ar.IntelCollateral, error) {

	log.Tracef("Fetching collateral for FMSPC %v, PCK cert CN=%v, quote type %v", fmspc,
		pckcert.Subject.CommonName, quoteType)

	caType, err := getCaTypeFromPck(pckcert)
	if err != nil {
		return nil, fmt.Errorf("failed to get CA type from PCK cert")
	}

	log.Debug("Fetching TCB Info")
	tcbInfo, interTcbInfo, rootTcbInfo, err := endorser.fetchTcbInfo(fmspc, quoteType)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch TCB info: %w", err)
	}

	log.Debug("Fetching QE Identity")
	qeIdentity, interQe, rootQe, err := endorser.fetchQeIdentity(quoteType)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch QE identity: %w", err)
	}

	log.Debugf("Fetching PCK %v CRL", caType)
	pckCrl, interPckCrl, rootPckCrl, err := endorser.fetchPckCrl(caType)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch PCK CRL: %w", err)
	}

	log.Debug("Fetching root CA CRL")
	rootCrl, err := endorser.fetchRootCrl(rootQe.CRLDistributionPoints)
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

// cachedFetch wraps a server fetch with TTL-based caching
func (endorser *TdxEndorser) cachedFetch(
	key string,
	fetch func() (body []byte, issuerChain string, err error),
) ([]byte, string, error) {

	cached, fresh := endorser.cache.get(key)
	if fresh {
		log.Tracef("Using cached %v (age %v)", key, time.Since(cached.FetchedAt).Round(time.Second))
		return cached.Body, cached.IssuerChain, nil
	}

	body, issuerChain, err := fetch()
	if err != nil {
		if cached != nil {
			log.Warnf("Refresh of %v failed, using stale cache (age %v): %v",
				key, time.Since(cached.FetchedAt).Round(time.Second), err)
			return cached.Body, cached.IssuerChain, nil
		}
		return nil, "", err
	}

	endorser.cache.put(key, &cachedCollateral{
		FetchedAt:   time.Now(),
		Body:        body,
		IssuerChain: issuerChain,
	})
	return body, issuerChain, nil
}

func (endorser *TdxEndorser) fetchTcbInfo(fmspc string, quoteType ar.IntelQuoteType,
) ([]byte, *x509.Certificate, *x509.Certificate, error) {

	key := fmt.Sprintf("tcb_%v_%v", quoteType, fmspc)
	body, issuerChain, err := endorser.cachedFetch(key, func() ([]byte, string, error) {
		return endorser.fetchTcbInfoFromServer(fmspc, quoteType)
	})
	if err != nil {
		return nil, nil, nil, err
	}
	inter, root, err := parseIssuerChain(issuerChain)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse TCB info issuer chain: %w", err)
	}
	return body, inter, root, nil
}

func (endorser *TdxEndorser) fetchTcbInfoFromServer(fmspc string, quoteType ar.IntelQuoteType,
) ([]byte, string, error) {

	var tcbInfoUrl string
	switch quoteType {
	case ar.TDX_QUOTE_TYPE:
		tcbInfoUrl = fmt.Sprintf("%s/tdx/certification/v4/tcb?fmspc=%s", endorser.baseUrl, fmspc)
	case ar.SGX_QUOTE_TYPE:
		tcbInfoUrl = fmt.Sprintf("%s/sgx/certification/v4/tcb?fmspc=%v", endorser.baseUrl, fmspc)
	default:
		return nil, "", fmt.Errorf("unknown quote type %v", quoteType)
	}
	log.Debugf("Fetching TCB Info for FMSPC %q from: %v", fmspc, tcbInfoUrl)

	resp, err := http.Get(tcbInfoUrl)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get HTTPS TCB Info response: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read HTTPS TCB Info body: %w", err)
	}

	rawChain, err := extractChainFromHeader(resp.Header, pcs.TcbInfoIssuerChainPhrase)
	if err != nil {
		return nil, "", fmt.Errorf("failed to extract TCB info issuer cert chain from HTTPS header: %w", err)
	}

	return body, rawChain, nil
}

func (endorser *TdxEndorser) fetchQeIdentity(quoteType ar.IntelQuoteType,
) ([]byte, *x509.Certificate, *x509.Certificate, error) {

	key := fmt.Sprintf("qe_%v", quoteType)
	body, issuerChain, err := endorser.cachedFetch(key, func() ([]byte, string, error) {
		return endorser.fetchQeIdentityFromServer(quoteType)
	})
	if err != nil {
		return nil, nil, nil, err
	}
	inter, root, err := parseIssuerChain(issuerChain)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse QE identity issuer chain: %w", err)
	}
	return body, inter, root, nil
}

func (endorser *TdxEndorser) fetchQeIdentityFromServer(quoteType ar.IntelQuoteType,
) ([]byte, string, error) {

	var qeIdentityUrl string
	switch quoteType {
	case ar.TDX_QUOTE_TYPE:
		qeIdentityUrl = fmt.Sprintf("%s/tdx/certification/v4/qe/identity", endorser.baseUrl)
	case ar.SGX_QUOTE_TYPE:
		qeIdentityUrl = fmt.Sprintf("%s/sgx/certification/v4/qe/identity", endorser.baseUrl)
	default:
		return nil, "", fmt.Errorf("unknown quote type %v", quoteType)
	}
	log.Debugf("Fetching QE Identity: %v", qeIdentityUrl)

	resp, err := http.Get(qeIdentityUrl)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get HTTPS QE identity response: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read HTTPS QE identity body: %w", err)
	}

	rawChain, err := extractChainFromHeader(resp.Header, pcs.SgxQeIdentityIssuerChainPhrase)
	if err != nil {
		return nil, "", fmt.Errorf("failed to extract QE identity issuer cert chain from HTTPS header: %w", err)
	}

	return body, rawChain, nil
}

func (endorser *TdxEndorser) fetchPckCrl(ca string,
) (*x509.RevocationList, *x509.Certificate, *x509.Certificate, error) {

	key := fmt.Sprintf("pckcrl_%v", ca)
	body, issuerChain, err := endorser.cachedFetch(key, func() ([]byte, string, error) {
		return endorser.fetchPckCrlFromServer(ca)
	})
	if err != nil {
		return nil, nil, nil, err
	}
	pckCrl, err := x509.ParseRevocationList(body)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse PCK CRL: %w", err)
	}
	inter, root, err := parseIssuerChain(issuerChain)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse PCK CRL issuer chain: %w", err)
	}
	return pckCrl, inter, root, nil
}

func (endorser *TdxEndorser) fetchPckCrlFromServer(ca string) ([]byte, string, error) {

	pckCrlUrl := fmt.Sprintf("%s/sgx/certification/v4/pckcrl?ca=%s&encoding=der", endorser.baseUrl, ca)
	log.Debugf("Fetching PCK CRL: %v", pckCrlUrl)

	resp, err := http.Get(pckCrlUrl)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch PCK CRL: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read HTTPS PCK CRL body: %w", err)
	}

	rawChain, err := extractChainFromHeader(resp.Header, pcs.SgxPckCrlIssuerChainPhrase)
	if err != nil {
		return nil, "", fmt.Errorf("failed to extract PCK CRL issuer cert chain from header: %w", err)
	}

	return body, rawChain, nil
}

func (endorser *TdxEndorser) fetchRootCrl(urls []string) (*x509.RevocationList, error) {

	const key = "rootcrl"

	cached, fresh := endorser.cache.get(key)
	if fresh {
		log.Tracef("Using cached %v (age %v)", key, time.Since(cached.FetchedAt).Round(time.Second))
		return x509.ParseRevocationList(cached.Body)
	}

	body, srcUrl, err := fetchRootCrlFromServer(urls)
	if err != nil {
		if cached != nil {
			log.Warnf("Refresh of %v failed, using stale cache (age %v): %v",
				key, time.Since(cached.FetchedAt).Round(time.Second), err)
			return x509.ParseRevocationList(cached.Body)
		}
		return nil, err
	}

	rootCrl, err := x509.ParseRevocationList(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root CA CRL from %v: %w", srcUrl, err)
	}

	endorser.cache.put(key, &cachedCollateral{
		FetchedAt:  time.Now(),
		Body:       body,
		SourceUrls: []string{srcUrl},
	})
	return rootCrl, nil
}

func fetchRootCrlFromServer(urls []string) ([]byte, string, error) {

	if len(urls) == 0 {
		return nil, "", fmt.Errorf("root CA CRLs are empty")
	}

	log.Debugf("Fetching Root CA CRLs from: %v", urls)
	for _, url := range urls {
		resp, err := http.Get(url)
		if err != nil {
			log.Warnf("failed to fetch root CA CRL from %v: %v", url, err)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Warnf("failed to read HTTPS root CA CRL body from %v: %v", url, err)
			continue
		}
		if _, err := x509.ParseRevocationList(body); err != nil {
			log.Warnf("failed to parse root CA CRL from %v: %v", url, err)
			continue
		}
		return body, url, nil
	}

	return nil, "", fmt.Errorf("failed to fetch root CA CRL from locations: %v", urls)
}

func extractChainFromHeader(header map[string][]string, phrase string) (string, error) {

	h, ok := header[phrase]
	if !ok {
		return "", fmt.Errorf("header %v does not exist", phrase)
	}
	if len(h) != 1 {
		return "", fmt.Errorf("unexpeted issuer chain length %v", len(h))
	}
	return h[0], nil
}

func parseIssuerChain(raw string) (*x509.Certificate, *x509.Certificate, error) {

	chain, err := url.QueryUnescape(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode issuer chain: %w", err)
	}

	block, rem := pem.Decode([]byte(chain))
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode intermediate certificate PEM block")
	}
	intermediate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse intermediate certificate: %w", err)
	}
	log.Tracef("Parsed certificate CN=%v", intermediate.Subject.CommonName)

	block, rem = pem.Decode(rem)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode root certificate PEM block")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse root certificate: %w", err)
	}
	log.Tracef("Parsed certificate CN=%v", root.Subject.CommonName)

	if len(rem) != 0 {
		return nil, nil, fmt.Errorf("issuer chain of unexpected length")
	}

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
