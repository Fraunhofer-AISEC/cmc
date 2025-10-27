// Copyright (c) 2024 Fraunhofer AISEC
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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	// local modules

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	ahttp "github.com/Fraunhofer-AISEC/cmc/attestedhttp"
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	pub "github.com/Fraunhofer-AISEC/cmc/publish"
)

// HTTP header constants
const (
	ContentTypeHeader = "Content-Type"
)

// MIME type constants.
const (
	MimeParamBoundary     = "boundary"
	MimeParamSMIMEType    = "smime-type"
	MimeTypeJSON          = "application/json"
	MimeTypeOctetStream   = "application/octet-stream"
	MimeTypeTextPlain     = "text/plain"
	MimeTypeTextPlainUTF8 = "text/plain; charset=utf-8"
)

// Creates an attested HTTPS connection and performs the specified requests
func requestInternal(c *config, api atls.CmcApiSelect, cmc *cmc.Cmc) {

	// Add trusted server root CAs
	trustedRootCas := x509.NewCertPool()
	for _, ca := range c.identityCas {
		trustedRootCas.AddCert(ca)
	}

	// Load certificate from CMC if mutual TLS is activated and
	// create basic TLS configuration for aTLS
	var tlsConfig *tls.Config
	log.Debug("Creating aTLS configuration")
	if c.Mtls {
		cert, err := atls.GetCert(
			atls.WithCmcAddr(c.CmcAddr),
			atls.WithCmcApi(api),
			atls.WithApiSerializer(c.apiSerializer),
			atls.WithCmc(cmc))
		if err != nil {
			log.Fatalf("failed to get TLS Certificate: %v", err)
		}
		// Create TLS config with root CA and own certificate for authentication
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      trustedRootCas,
		}
	} else {
		// Create TLS config with root CA only
		tlsConfig = &tls.Config{
			RootCAs:       trustedRootCas,
			Renegotiation: tls.RenegotiateNever,
		}
	}
	internal.PrintTlsConfig(tlsConfig, c.identityCas)

	// Create an attested HTTP Transport structure. This is a wrapper around http.Transport,
	// look for the descriptions of the parameters there. Additionally, the aTLS parameters
	// must be configured
	transport := &ahttp.Transport{
		IdleConnTimeout: 60 * time.Second,
		TLSClientConfig: tlsConfig,

		Attest:        c.attest,
		MutualTls:     c.Mtls,
		CmcAddr:       c.CmcAddr,
		CmcApi:        api,
		ApiSerializer: c.apiSerializer,
		Cmc:           cmc,
		CmcPolicies:   c.policies,
		ResultCb: func(result *ar.VerificationResult) {
			// Publish the attestation result asynchronously if publishing address was specified and
			// and attestation was performed
			if c.attest == atls.Attest_Mutual || c.attest == atls.Attest_Server {
				wg := new(sync.WaitGroup)
				wg.Add(1)
				defer wg.Wait()
				go pub.PublishResultAsync(c.Publish, c.ResultFile, result, wg)
			}
		},
	}

	// Create an attested HTTPS Client
	client := &ahttp.Client{Transport: transport}

	for _, addr := range c.Addr {

		log.Debugf("HTTP %v request to %v", c.Method, addr)

		// Create a new HTTP request and add body in case of POST or PUT request
		var body io.Reader
		if strings.EqualFold(c.Method, "POST") || strings.EqualFold(c.Method, "PUT") {
			body = io.NopCloser(bytes.NewBuffer([]byte(c.Data)))
		}
		req, err := http.NewRequest(c.Method, addr, body)
		if err != nil {
			log.Fatalf("failed to make new HTTP request: %v", err)
		}

		// Set the user specified HTTP headers
		log.Tracef("Number of specified headers: %v", len(c.Header))
		for _, h := range c.Header {
			s := strings.SplitN(h, ":", 2)
			if len(s) != 2 {
				log.Fatalf("invalid header %v", h)
			}
			log.Tracef("Setting header '%v: %v'", s[0], s[1])
			req.Header.Set(s[0], s[1])
		}

		// Perform the actual, user specified request
		resp, err := client.Do(req)
		if err != nil {
			log.Warnf("HTTP %v failed: %v", c.Method, err)
			return
		}
		defer resp.Body.Close()

		log.Debug("Response Status: ", resp.Status)
		if resp.StatusCode != 200 {
			log.Warnf("HTTP request returned status %v", resp.Status)
		}

		content, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Warn("Failed to read response")
		} else {
			log.Infof("Received from server: '%v'", string(content))
			log.Debugf("Client-side aHTTPS request completed")
		}

	}
}

func serveInternal(c *config, api atls.CmcApiSelect, cmc *cmc.Cmc) {

	// Add trusted client root CAs
	trustedRootCas := x509.NewCertPool()
	for _, ca := range c.identityCas {
		trustedRootCas.AddCert(ca)
	}

	// Load certificate from CMC
	cert, err := atls.GetCert(
		atls.WithCmcAddr(c.CmcAddr),
		atls.WithCmcApi(api),
		atls.WithApiSerializer(c.apiSerializer),
		atls.WithCmc(cmc))
	if err != nil {
		log.Fatalf("failed to get TLS Certificate: %v", err)
	}

	var clientAuth tls.ClientAuthType
	if c.Mtls {
		// Mandate client authentication
		clientAuth = tls.RequireAndVerifyClientCert
	} else {
		// Make client authentication optional
		clientAuth = tls.VerifyClientCertIfGiven
	}

	// Overwrite specified TLS config to enforce aTLS as configured
	tlsConfig := &tls.Config{
		Certificates:  []tls.Certificate{cert},
		ClientAuth:    clientAuth,
		ClientCAs:     trustedRootCas,
		Renegotiation: tls.RenegotiateNever,
	}

	internal.PrintTlsConfig(tlsConfig, c.identityCas)

	// Config allows to specify more than one address for dialing,
	// always use first address for listening
	addr := ""
	if len(c.Addr) > 0 {
		addr = c.Addr[0]
	}

	// Create an attested HTTP server. The inner http.Server can be
	// configured as usual. Additionally, aTLS parameters must be
	// specified
	server := &ahttp.Server{
		Server: &http.Server{
			Addr:      addr,
			TLSConfig: tlsConfig,
		},
		Attest:        c.attest,
		MutualTls:     c.Mtls,
		CmcAddr:       c.CmcAddr,
		CmcApi:        api,
		ApiSerializer: c.apiSerializer,
		Cmc:           cmc,
		CmcPolicies:   c.policies,
		ResultCb: func(result *ar.VerificationResult) {
			if c.attest == atls.Attest_Mutual || c.attest == atls.Attest_Client {
				// Publish the attestation result if publishing address was specified
				// and result is not empty
				go pub.PublishResult(c.Publish, c.ResultFile, result)
			}
		},
	}

	// Use the golang net/http module functions to configure the server
	// as usual
	http.HandleFunc("/", handleRootRequest)
	http.HandleFunc("/data", handleDataRequest)
	http.HandleFunc("/post", handlePostRequest)

	// Call the attested ListenAndServe method from the attested HTTP server
	// to run the server
	err = server.ListenAndServe()
	if err != nil {
		log.Warnf("Failed to serve HTTPS: %v", err)
	}
}

// Just an example HTTP handler
func handleRootRequest(w http.ResponseWriter, req *http.Request) {
	log.Debugf("Received '/' %v request from %v", req.Method, req.RemoteAddr)
	w.Header().Set("Content-Type", "text/html")

	log.Debugf("Sending HTTP response")
	fmt.Fprintf(w, "<h1>Hello from HTML</h1>")
}

// Just an example HTTP handler
func handleDataRequest(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received '/data' %v request from %v", req.Method, req.RemoteAddr)

	if strings.Compare(req.Method, "GET") != 0 {
		writeHttpErrorf(w, "Method %v not implemented for /post request", req.Method)
		return
	}

	for k, v := range req.Header {
		log.Tracef("HTTP Header %v: %v", k, v)
	}

	payload := []byte(`{"test": "hello from json"}`)

	w.Header().Set(ContentTypeHeader, MimeTypeJSON)
	w.WriteHeader(http.StatusOK)

	log.Debugf("Sending HTTP response")
	n, err := w.Write(payload)
	if err != nil {
		log.Warnf("failed to write HTTP: %v", err)
	}
	if n != len(payload) {
		log.Warnf("Failed to handle data request: Only %v of %v bytes sent", n, len(payload))
	}
}

// Just an example HTTP handler
func handlePostRequest(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received '/post' %v request from %v", req.Method, req.RemoteAddr)

	if strings.Compare(req.Method, "POST") != 0 {
		writeHttpErrorf(w, "Method %v not implemented for /post request", req.Method)
		return
	}

	for k, v := range req.Header {
		log.Debugf("HTTP Header %v: %v", k, v)
	}

	payload, err := io.ReadAll(req.Body)
	if err != nil {
		writeHttpErrorf(w, "failed to read payload from request: %v", err)
		return
	}

	log.Infof("Received from client: '%v'", string(payload))

	payload = []byte(`{"test": "hello from json"}`)

	w.Header().Set(ContentTypeHeader, MimeTypeJSON)
	w.WriteHeader(http.StatusOK)

	log.Debugf("Sending HTTP response")
	n, err := w.Write(payload)
	if err != nil {
		log.Warnf("failed to write HTTP: %v", err)
	}
	if n != len(payload) {
		log.Warnf("Failed to handle post request: Only %v of %v bytes sent", n, len(payload))
	} else {
		log.Debugf("Server-side aHTTPS request completed")
	}
}

func writeHttpErrorf(w http.ResponseWriter, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Warn(msg)
	http.Error(w, msg, http.StatusBadRequest)
}
