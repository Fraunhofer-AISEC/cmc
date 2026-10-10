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

package endorser

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/google/go-tdx-guest/pcs"
)

const (
	tdxCacheTtl = 24 * time.Hour

	// IntelRootCaCrlPath is the path of the CRL distribution point within the Intel
	// SGX root CA certificate. Collateral proxies serve the root CA CRL under this
	// path, so that CVMs without internet access can fetch it from the proxy
	IntelRootCaCrlPath = "/IntelSGXRootCA.der"

	// lenFmspc is the length of a hex-encoded FMSPC (6 bytes)
	lenFmspc = 12
)

type TdxEndorser struct {
	baseUrl      string
	proxyRootCrl bool
	cache        *tdxCache
	client       *http.Client
}

// TdxOption configures optional TDX endorser behavior
type TdxOption func(*TdxEndorser)

// WithProxiedRootCaCrl makes the endorser fetch the root CA CRL from the collateral
// server instead of directly from the CRL distribution points within the Intel root
// CA certificate, falling back to the distribution points if the server does not
// serve it. This allows CVMs without internet access to obtain the root CA CRL
func WithProxiedRootCaCrl() TdxOption {
	return func(e *TdxEndorser) {
		e.proxyRootCrl = true
	}
}

// Implement the EndorserProvider interface
func (endorser *TdxEndorser) Snp() (drivers.SnpEndorser, error) {
	return nil, fmt.Errorf("internal error: requesting SNP from TDX endorser")
}

func (endorser *TdxEndorser) Tdx() (drivers.TdxEndorser, error) {
	return endorser, nil
}

func (endorser *TdxEndorser) Tpm() (drivers.TpmEndorser, error) {
	return nil, fmt.Errorf("internal error: requesting TPM from TDX endorser")
}

// NewTdxEndorser initializes a new TDX endorser. baseUrl is the address of the
// collateral server (Intel PCS or custom PCCS). If a cacheFolder is specified,
// collateral is also cached to disk
func NewTdxEndorser(
	baseUrl, cacheFolder string,
	rootCas []*x509.Certificate,
	allowSystemCerts bool,
	opts ...TdxOption,
) (*TdxEndorser, error) {
	client, err := internal.NewHttpClient(rootCas, allowSystemCerts, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create TDX endorser HTTP client: %w", err)
	}
	endorser := &TdxEndorser{
		baseUrl: strings.TrimRight(baseUrl, "/"),
		cache:   newTdxCache(cacheFolder, tdxCacheTtl),
		client:  client,
	}
	for _, opt := range opts {
		opt(endorser)
	}
	return endorser, nil
}

// get performs an HTTP GET request and fails on any non-OK status, so that error
// pages are not mistaken for collateral.
func (endorser *TdxEndorser) get(url string) (*http.Response, error) {

	resp, err := endorser.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to perform HTTP GET: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP response status %v (%v): %v",
			resp.StatusCode, resp.Status, strings.TrimSpace(string(msg)))
	}

	return resp, nil
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

// GetTcbInfo returns the raw TCB info for the given FMSPC together with the
// URL-encoded PEM issuer chain the collateral server returns in the HTTP header.
func (endorser *TdxEndorser) GetTcbInfo(fmspc string, quoteType ar.IntelQuoteType,
) ([]byte, string, error) {

	if err := ValidateFmspc(fmspc); err != nil {
		return nil, "", err
	}

	key := fmt.Sprintf("tcb_%v_%v", quoteType, fmspc)
	return endorser.cachedFetch(key, func() ([]byte, string, error) {
		return endorser.fetchTcbInfoFromServer(fmspc, quoteType)
	})
}

func (endorser *TdxEndorser) fetchTcbInfo(fmspc string, quoteType ar.IntelQuoteType,
) ([]byte, *x509.Certificate, *x509.Certificate, error) {

	body, issuerChain, err := endorser.GetTcbInfo(fmspc, quoteType)
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

	resp, err := endorser.get(tcbInfoUrl)
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

// GetQeIdentity returns the raw QE identity together with the URL-encoded PEM
// issuer chain the collateral server returns in the HTTP header.
func (endorser *TdxEndorser) GetQeIdentity(quoteType ar.IntelQuoteType,
) ([]byte, string, error) {

	key := fmt.Sprintf("qe_%v", quoteType)
	return endorser.cachedFetch(key, func() ([]byte, string, error) {
		return endorser.fetchQeIdentityFromServer(quoteType)
	})
}

func (endorser *TdxEndorser) fetchQeIdentity(quoteType ar.IntelQuoteType,
) ([]byte, *x509.Certificate, *x509.Certificate, error) {

	body, issuerChain, err := endorser.GetQeIdentity(quoteType)
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

	resp, err := endorser.get(qeIdentityUrl)
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

// GetPckCrl returns the DER-encoded PCK CRL for the given CA type together with the URL-encoded
// PEM issuer chain the collateral server returns in the HTTP header.
func (endorser *TdxEndorser) GetPckCrl(ca string) ([]byte, string, error) {

	if err := ValidatePckCa(ca); err != nil {
		return nil, "", err
	}

	key := fmt.Sprintf("pckcrl_%v", ca)
	return endorser.cachedFetch(key, func() ([]byte, string, error) {
		return endorser.fetchPckCrlFromServer(ca)
	})
}

func (endorser *TdxEndorser) fetchPckCrl(ca string,
) (*x509.RevocationList, *x509.Certificate, *x509.Certificate, error) {

	body, issuerChain, err := endorser.GetPckCrl(ca)
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

	resp, err := endorser.get(pckCrlUrl)
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

// GetRootCaCrl returns the DER-encoded Intel root CA CRL. The CRL distribution points are taken
// from the root cert the collateral server serves in its QE identity issuer chain (the Intel PCS
// does not serve the root CA CRL).
func (endorser *TdxEndorser) GetRootCaCrl() ([]byte, error) {

	_, _, root, err := endorser.fetchQeIdentity(ar.SGX_QUOTE_TYPE)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch QE identity issuer chain: %w", err)
	}

	rootCrl, err := endorser.fetchRootCrl(root.CRLDistributionPoints)
	if err != nil {
		return nil, err
	}

	return rootCrl.Raw, nil
}

func (endorser *TdxEndorser) fetchRootCrl(urls []string) (*x509.RevocationList, error) {

	const key = "rootcrl"

	cached, fresh := endorser.cache.get(key)
	if fresh {
		log.Tracef("Using cached %v (age %v)", key, time.Since(cached.FetchedAt).Round(time.Second))
		return x509.ParseRevocationList(cached.Body)
	}

	body, srcUrl, err := endorser.fetchRootCrlFromServer(urls)
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

func (endorser *TdxEndorser) fetchRootCrlFromServer(urls []string) ([]byte, string, error) {

	if len(urls) == 0 {
		return nil, "", fmt.Errorf("root CA CRLs are empty")
	}

	locations := endorser.rootCrlUrls(urls)

	log.Debugf("Fetching Root CA CRLs from: %v", locations)
	for _, url := range locations {
		resp, err := endorser.get(url)
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

	return nil, "", fmt.Errorf("failed to fetch root CA CRL from locations: %v", locations)
}

// rootCrlUrls returns the locations to fetch the root CA CRL from. If the endorser
// is configured to fetch it from the collateral proxy, the proxy is tried first,
// with the original distribution points kept as fallback
func (endorser *TdxEndorser) rootCrlUrls(urls []string) []string {

	if !endorser.proxyRootCrl {
		return urls
	}

	locations := make([]string, 0, 2*len(urls))
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			log.Warnf("failed to parse root CA CRL distribution point %v: %v", u, err)
			continue
		}
		locations = append(locations, endorser.baseUrl+parsed.EscapedPath())
	}

	return append(locations, urls...)
}

// ValidateFmspc checks that the FMSPC is a hex-encoded 6 byte value. Collateral
// servers use it in URLs and cache file names, so it must not be used unchecked
func ValidateFmspc(fmspc string) error {
	if len(fmspc) != lenFmspc {
		return fmt.Errorf("invalid fmspc length %v (expected %v)", len(fmspc), lenFmspc)
	}
	if _, err := hex.DecodeString(fmspc); err != nil {
		return fmt.Errorf("invalid fmspc %q: %w", fmspc, err)
	}
	return nil
}

// ValidatePckCa checks that the PCK CA type is one of the types the Intel PCS
// defines. Collateral servers use it in URLs and cache file names, so it must not
// be used unchecked
func ValidatePckCa(ca string) error {
	if ca != "platform" && ca != "processor" {
		return fmt.Errorf("invalid PCK CA type %q (expected platform or processor)", ca)
	}
	return nil
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

// cachedCollateral stores entries in the TDX collateral cache. It stores the raw
// HTTP body together with the URL-encoded PEM issuer chain that PCS returns in
// the response header. SourceUrls is only used for the root CA CRL
type cachedCollateral struct {
	FetchedAt   time.Time `json:"fetchedAt"`
	Body        []byte    `json:"body"`
	IssuerChain string    `json:"issuerChain,omitempty"`
	SourceUrls  []string  `json:"sourceUrls,omitempty"`
}

// tdxCache caches TDX collateral fetched from Intel PCS or PCCS
type tdxCache struct {
	mu     sync.Mutex
	folder string
	mem    map[string]*cachedCollateral
	ttl    time.Duration
}

// cacheKeyPattern matches the cache keys that are safe to use as file names.
var cacheKeyPattern = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// filePath returns the cache file of the given key within the cache folder
func (c *tdxCache) filePath(key string) (string, error) {
	if !cacheKeyPattern.MatchString(key) {
		return "", fmt.Errorf("invalid cache key %q", key)
	}
	return path.Join(c.folder, key+".json"), nil
}

// newTdxCache creates a new TDX collateral cache
func newTdxCache(folder string, ttl time.Duration) *tdxCache {
	return &tdxCache{
		folder: folder,
		mem:    make(map[string]*cachedCollateral),
		ttl:    ttl,
	}
}

// get returns the cached entry for key plus a freshness flag
func (c *tdxCache) get(key string) (entry *cachedCollateral, fresh bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.mem[key]; ok {
		return e, time.Since(e.FetchedAt) < c.ttl
	}
	if c.folder == "" {
		return nil, false
	}

	filePath, err := c.filePath(key)
	if err != nil {
		log.Warnf("failed to read TDX cache: %v", err)
		return nil, false
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("failed to read TDX cache file %v: %v", filePath, err)
		}
		return nil, false
	}
	e := &cachedCollateral{}
	if err := json.Unmarshal(data, e); err != nil {
		log.Warnf("failed to parse TDX cache file %v: %v", filePath, err)
		return nil, false
	}
	c.mem[key] = e
	return e, time.Since(e.FetchedAt) < c.ttl
}

// put stores the entry under key, in memory and (if configured) on disk.
func (c *tdxCache) put(key string, entry *cachedCollateral) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.mem[key] = entry

	if c.folder == "" {
		return
	}
	filePath, err := c.filePath(key)
	if err != nil {
		log.Warnf("failed to cache TDX collateral on disk: %v", err)
		return
	}
	if _, err := os.Stat(c.folder); err != nil {
		if err := os.MkdirAll(c.folder, 0755); err != nil {
			log.Warnf("failed to create TDX cache folder %v: %v", c.folder, err)
			return
		}
	}
	data, err := json.Marshal(entry)
	if err != nil {
		log.Warnf("failed to encode TDX cache entry %v: %v", key, err)
		return
	}
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		log.Warnf("failed to write TDX cache file %v: %v", filePath, err)
		return
	}
	log.Tracef("Cached TDX collateral at %v", filePath)
}
