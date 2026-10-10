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

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/provision/endorser"
	"github.com/google/go-tdx-guest/pcs"
)

const (
	testFmspc      = "90c06f000000"
	testTcbInfo    = `{"tcbInfo":{"id":"TDX","fmspc":"90c06f000000"},"signature":"00"}`
	testQeIdentity = `{"enclaveIdentity":{"id":"TD_QE"},"signature":"00"}`
)

// TestCollateralProxy runs a guest TDX endorser against the EST server collateral
// proxy, which in turn is backed by a server mimicking the Intel PCS. It verifies
// that all collateral, including the issuer chains travelling in the HTTP headers
// and the root CA CRL, arrives at the guest unmodified
func TestCollateralProxy(t *testing.T) {

	pki := newTestPki(t)

	pcsServer, pcsRequests := newTestPcs(t, pki)
	defer pcsServer.Close()

	proxy, proxyRequests := newTestProxy(t, pcsServer.URL)
	defer proxy.Close()

	// The guest obtains all collateral from the proxy, including the root CA CRL
	guest, err := endorser.NewTdxEndorser(proxy.URL, "", nil, false,
		endorser.WithProxiedRootCaCrl())
	if err != nil {
		t.Fatalf("failed to create guest endorser: %v", err)
	}

	collateral, err := guest.FetchCollateral(testFmspc, pki.pckCert, ar.TDX_QUOTE_TYPE)
	if err != nil {
		t.Fatalf("failed to fetch collateral: %v", err)
	}

	for _, tc := range []struct {
		name     string
		got      []byte
		expected []byte
	}{
		{"TCB info", collateral.TcbInfo, []byte(testTcbInfo)},
		{"TCB info intermediate cert", collateral.TcbInfoIntermediateCert, pki.intermediate.Raw},
		{"TCB info root cert", collateral.TcbInfoRootCert, pki.root.Raw},
		{"QE identity", collateral.QeIdentity, []byte(testQeIdentity)},
		{"QE identity intermediate cert", collateral.QeIdentityIntermediateCert, pki.intermediate.Raw},
		{"QE identity root cert", collateral.QeIdentityRootCert, pki.root.Raw},
		{"PCK CRL", collateral.PckCrl, pki.pckCrl},
		{"PCK CRL intermediate cert", collateral.PckCrlIntermediateCert, pki.intermediate.Raw},
		{"PCK CRL root cert", collateral.PckCrlRootCert, pki.root.Raw},
		{"root CA CRL", collateral.RootCaCrl, pki.rootCrl},
	} {
		if !bytes.Equal(tc.got, tc.expected) {
			t.Errorf("%v does not match the collateral the Intel PCS served", tc.name)
		}
	}

	// The guest must have taken the root CA CRL from the proxy, not from the
	// distribution point within the Intel root CA certificate
	if proxyRequests.count(endorser.IntelRootCaCrlPath) != 1 {
		t.Errorf("guest requested the root CA CRL %v times from the proxy, expected 1",
			proxyRequests.count(endorser.IntelRootCaCrlPath))
	}

	// The proxy must request the TDX TCB info, not the SGX TCB info
	if pcsRequests.count("/tdx/certification/v4/tcb") != 1 {
		t.Errorf("proxy requested the TDX TCB info %v times, expected 1",
			pcsRequests.count("/tdx/certification/v4/tcb"))
	}

	// A second fetch must be served from the cache, without any upstream request
	upstream := pcsRequests.total()
	if _, err := guest.FetchCollateral(testFmspc, pki.pckCert, ar.TDX_QUOTE_TYPE); err != nil {
		t.Fatalf("failed to fetch collateral from cache: %v", err)
	}
	if pcsRequests.total() != upstream {
		t.Errorf("cached fetch caused %v additional Intel PCS requests, expected 0",
			pcsRequests.total()-upstream)
	}
}

// TestCollateralProxyIssuerChain verifies that the issuer chain is forwarded
// byte-identically, as clients parse the certificate chain from the header
func TestCollateralProxyIssuerChain(t *testing.T) {

	pki := newTestPki(t)

	pcsServer, _ := newTestPcs(t, pki)
	defer pcsServer.Close()

	proxy, _ := newTestProxy(t, pcsServer.URL)
	defer proxy.Close()

	for _, tc := range []struct {
		name        string
		endpoint    string
		header      string
		contentType string
		expected    []byte
	}{
		{
			"SGX TCB info", "/sgx/certification/v4/tcb?fmspc=" + testFmspc,
			pcs.TcbInfoIssuerChainPhrase, contentTypeJson, []byte(testTcbInfo),
		},
		{
			"TDX TCB info", "/tdx/certification/v4/tcb?fmspc=" + testFmspc,
			pcs.TcbInfoIssuerChainPhrase, contentTypeJson, []byte(testTcbInfo),
		},
		{
			"SGX QE identity", "/sgx/certification/v4/qe/identity",
			pcs.SgxQeIdentityIssuerChainPhrase, contentTypeJson, []byte(testQeIdentity),
		},
		{
			"TDX QE identity", "/tdx/certification/v4/qe/identity",
			pcs.SgxQeIdentityIssuerChainPhrase, contentTypeJson, []byte(testQeIdentity),
		},
		{
			"PCK CRL DER", "/sgx/certification/v4/pckcrl?ca=platform&encoding=der",
			pcs.SgxPckCrlIssuerChainPhrase, contentTypeCrl, pki.pckCrl,
		},
		{
			"PCK CRL PEM", "/sgx/certification/v4/pckcrl?ca=platform",
			pcs.SgxPckCrlIssuerChainPhrase, contentTypePem,
			pem.EncodeToMemory(&pem.Block{Type: pemTypeX509Crl, Bytes: pki.pckCrl}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := testGet(t, proxy.URL+tc.endpoint)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("unexpected status %v: %v", resp.StatusCode, string(body))
			}
			if !bytes.Equal(body, tc.expected) {
				t.Errorf("body does not match the Intel PCS response")
			}
			if got := resp.Header.Get("Content-Type"); got != tc.contentType {
				t.Errorf("content type is %q, expected %q", got, tc.contentType)
			}
			if got := resp.Header.Get(tc.header); got != pki.issuerChain {
				t.Errorf("issuer chain header %v is\n%v\nexpected\n%v",
					tc.header, got, pki.issuerChain)
			}
		})
	}
}

// TestCollateralProxyBadRequest verifies that the proxy rejects parameters it
// would otherwise use in upstream URLs and cache file names
func TestCollateralProxyBadRequest(t *testing.T) {

	pki := newTestPki(t)

	pcsServer, pcsRequests := newTestPcs(t, pki)
	defer pcsServer.Close()

	proxy, _ := newTestProxy(t, pcsServer.URL)
	defer proxy.Close()

	for _, tc := range []struct {
		name     string
		endpoint string
	}{
		{"missing fmspc", "/tdx/certification/v4/tcb"},
		{"fmspc of wrong length", "/tdx/certification/v4/tcb?fmspc=90c06f0000"},
		{"non-hex fmspc", "/tdx/certification/v4/tcb?fmspc=90c06f00000z"},
		{"fmspc path traversal", "/tdx/certification/v4/tcb?fmspc=../../../etc"},
		{"missing pck ca", "/sgx/certification/v4/pckcrl?encoding=der"},
		{"unknown pck ca", "/sgx/certification/v4/pckcrl?ca=unknown&encoding=der"},
		{"unknown encoding", "/sgx/certification/v4/pckcrl?ca=platform&encoding=txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := testGet(t, proxy.URL+tc.endpoint)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status is %v, expected %v", resp.StatusCode, http.StatusBadRequest)
			}
		})
	}

	if pcsRequests.total() != 0 {
		t.Errorf("rejected requests caused %v Intel PCS requests, expected 0",
			pcsRequests.total())
	}
}

// TestCollateralProxyDisabled verifies that the Intel endpoints are not served
// if no upstream Intel PCS or PCCS is configured
func TestCollateralProxyDisabled(t *testing.T) {

	mux := http.NewServeMux()
	(&Server{}).registerCollateralEndpoints(mux)
	proxy := httptest.NewServer(mux)
	defer proxy.Close()

	resp, _ := testGet(t, proxy.URL+"/tdx/certification/v4/tcb?fmspc="+testFmspc)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status is %v, expected %v", resp.StatusCode, http.StatusNotFound)
	}
}

// newTestProxy creates an EST server collateral proxy backed by the Intel PCS at
// pcsUrl, together with a recorder for the requests the proxy receives
func newTestProxy(t *testing.T, pcsUrl string) (*httptest.Server, *requestLog) {
	t.Helper()

	tdxEndorser, err := endorser.NewTdxEndorser(pcsUrl, "", nil, true)
	if err != nil {
		t.Fatalf("failed to create proxy endorser: %v", err)
	}

	mux := http.NewServeMux()
	(&Server{tdxEndorser: tdxEndorser}).registerCollateralEndpoints(mux)

	requests := &requestLog{}
	return httptest.NewServer(requests.record(mux)), requests
}

// newTestPcs creates a server mimicking the Intel PCS, including the issuer chain
// headers and the CRL distribution point of the Intel root CA certificate
func newTestPcs(t *testing.T, pki *testPki) (*httptest.Server, *requestLog) {
	t.Helper()

	collateral := func(contentType, chainHeader string, body []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", contentType)
			w.Header().Set(chainHeader, pki.issuerChain)
			if _, err := w.Write(body); err != nil {
				t.Errorf("failed to write test PCS response: %v", err)
			}
		}
	}

	tcbInfo := func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Query().Get("fmspc") != testFmspc {
			http.Error(w, "unknown fmspc", http.StatusNotFound)
			return
		}
		collateral(contentTypeJson, pcs.TcbInfoIssuerChainPhrase, []byte(testTcbInfo))(w, req)
	}

	pckCrl := func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Query().Get("ca") != "platform" || req.URL.Query().Get("encoding") != "der" {
			http.Error(w, "unknown ca or encoding", http.StatusNotFound)
			return
		}
		collateral(contentTypeCrl, pcs.SgxPckCrlIssuerChainPhrase, pki.pckCrl)(w, req)
	}

	qeIdentity := collateral(contentTypeJson, pcs.SgxQeIdentityIssuerChainPhrase,
		[]byte(testQeIdentity))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /sgx/certification/v4/tcb", tcbInfo)
	mux.HandleFunc("GET /tdx/certification/v4/tcb", tcbInfo)
	mux.HandleFunc("GET /sgx/certification/v4/qe/identity", qeIdentity)
	mux.HandleFunc("GET /tdx/certification/v4/qe/identity", qeIdentity)
	mux.HandleFunc("GET /sgx/certification/v4/pckcrl", pckCrl)

	// The CRL distribution point of the Intel root CA certificate, which the
	// Intel PCS itself does not serve
	mux.HandleFunc("GET "+endorser.IntelRootCaCrlPath,
		func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "binary/octet-stream")
			if _, err := w.Write(pki.rootCrl); err != nil {
				t.Errorf("failed to write test root CA CRL: %v", err)
			}
		})

	requests := &requestLog{}
	server := httptest.NewServer(requests.record(mux))

	// The distribution point is part of the certificates, which can only be
	// created once the server address is known
	pki.setup(t, server.URL)

	return server, requests
}

// testPki holds the Intel-shaped certificates, CRLs and issuer chain the test
// Intel PCS serves
type testPki struct {
	root         *x509.Certificate
	intermediate *x509.Certificate
	pckCert      *x509.Certificate
	rootCrl      []byte
	pckCrl       []byte
	issuerChain  string
}

func newTestPki(t *testing.T) *testPki {
	t.Helper()
	return &testPki{}
}

// setup creates an Intel-shaped PKI with the root CA CRL distribution point
// pointing to baseUrl
func (pki *testPki) setup(t *testing.T, baseUrl string) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}
	pki.root = createTestCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Intel SGX Root CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		CRLDistributionPoints: []string{baseUrl + endorser.IntelRootCaCrlPath},
	}, nil, nil, rootKey)

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate intermediate key: %v", err)
	}
	pki.intermediate = createTestCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Intel SGX TCB Signing"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, pki.root, rootKey, interKey)

	// The CA type of the PCK CRL is derived from the issuer of the PCK certificate
	pckCaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate PCK CA key: %v", err)
	}
	pckCa := createTestCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "Intel SGX PCK Platform CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, pki.root, rootKey, pckCaKey)

	pckKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate PCK key: %v", err)
	}
	pki.pckCert = createTestCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "Intel SGX PCK Certificate"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, pckCa, pckCaKey, pckKey)

	pki.rootCrl = createTestCrl(t, pki.root, rootKey)
	pki.pckCrl = createTestCrl(t, pckCa, pckCaKey)

	// The Intel PCS returns the issuer chain URL-encoded, with spaces encoded as
	// %20 instead of +
	chain := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.intermediate.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.root.Raw})...)
	pki.issuerChain = strings.ReplaceAll(url.QueryEscape(string(chain)), "+", "%20")
}

func createTestCert(t *testing.T, template, parent *x509.Certificate,
	parentKey *ecdsa.PrivateKey, key *ecdsa.PrivateKey,
) *x509.Certificate {
	t.Helper()

	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(24 * time.Hour)

	if parent == nil {
		parent = template
		parentKey = key
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

func createTestCrl(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) []byte {
	t.Helper()

	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}, ca, caKey)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}
	return crl
}

// requestLog records the requested paths of an HTTP handler
type requestLog struct {
	mu    sync.Mutex
	paths []string
}

func (l *requestLog) record(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		l.mu.Lock()
		l.paths = append(l.paths, req.URL.Path)
		l.mu.Unlock()
		h.ServeHTTP(w, req)
	})
}

func (l *requestLog) count(path string) int {
	l.mu.Lock()
	defer l.mu.Unlock()

	n := 0
	for _, p := range l.paths {
		if p == path {
			n++
		}
	}
	return n
}

func (l *requestLog) total() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.paths)
}

func testGet(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()

	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("failed to GET %v: %v", url, err)
	}
	defer resp.Body.Close()

	body := &bytes.Buffer{}
	if _, err := body.ReadFrom(resp.Body); err != nil {
		t.Fatalf("failed to read body of %v: %v", url, err)
	}
	return resp, body.Bytes()
}
