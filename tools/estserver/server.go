// Copyright (c) 2021 Fraunhofer AISEC
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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision"
	"github.com/Fraunhofer-AISEC/cmc/provision/endorser"
	"github.com/Fraunhofer-AISEC/cmc/provision/est"
	log "github.com/sirupsen/logrus"

	_ "github.com/mattn/go-sqlite3"
)

type Server struct {
	server            *http.Server
	estCaKey          crypto.PrivateKey
	estCaChain        []*x509.Certificate
	rootCas           []*x509.Certificate
	snpEndorser       *endorser.SnpEndorser
	tdxEndorser       *endorser.TdxEndorser
	tpmConf           provision.TpmConfig
	authMethods       internal.AuthMethod
	tokenPath         string
	publishResults    string
	publishOcsf       string
	publishNetwork    string
	publishFile       string
	publishToken      []byte
	allowSystemCerts  bool
	publishClientCert *tls.Certificate
	namingPolicy      NamingPolicy
	certValidity      time.Duration

	//Configuration of OMSP server for fetching manifest revocation information
	omspFolder  string
	omspKey     crypto.PrivateKey
	omspCaChain []*x509.Certificate
	omspUrl     string
}

func NewServer(c *config) (*Server, error) {

	var tlsCaChain [][]byte
	for _, c := range c.tlsCaChain {
		tlsCaChain = append(tlsCaChain, c.Raw)
	}

	tlsCfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		// The client does authenticate itself via an attestation and/or
		// a token as configured
		ClientAuth: tls.NoClientCert,
		ClientCAs:  nil,
		Certificates: []tls.Certificate{
			{
				Certificate: tlsCaChain,
				PrivateKey:  c.tlsKey,
				Leaf:        c.tlsCaChain[0],
			},
		},
	}

	// The client does authenticate itself via a certificate if configured
	if c.authMethods.Has(internal.AuthCertificate) {
		log.Debugf("Enforcing client authentication via certificate")
		rootpool, err := internal.CreateCertPool(c.rootCas, c.AllowSystemCerts)
		if err != nil {
			return nil, fmt.Errorf("failed to create cert pool: %w", err)
		}
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		tlsCfg.ClientCAs = rootpool
	}

	var publishToken []byte
	if c.PublishToken != "" {
		var err error
		publishToken, err = os.ReadFile(c.PublishToken)
		if err != nil {
			return nil, fmt.Errorf("failed to read publish token: %w", err)
		}
		publishToken = bytes.TrimSpace(publishToken)
	}

	var publishClientCert *tls.Certificate
	if c.PublishCert != "" && c.PublishKey != "" {
		cert, err := tls.LoadX509KeyPair(c.PublishCert, c.PublishKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load publish client cert: %w", err)
		}
		publishClientCert = &cert
	}

	// Use the system CA root store regardless of the CMC trust
	// pool as the AMD KDS is a production service under a global ca
	snpEndorser, err := endorser.NewSnpEndorser(endorser.AmdKdsUrl, c.VendorCache, nil, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create snp endorser: %w", err)
	}

	// Collateral proxy for Intel TDX/SGX is optional, as it requires an upstream
	// Intel PCS or PCCS
	var tdxEndorser *endorser.TdxEndorser
	if c.IntelPcsUrl != "" {
		// Additionally use the system CA root store regardless of the CMC trust pool:
		// the Intel PCS is a production service under a global CA, and the root CA CRL
		// is always fetched from the Intel distribution point. Custom PCCS instances
		// with their own certificate are configured via intelPcsRootCas
		tdxEndorser, err = endorser.NewTdxEndorser(c.IntelPcsUrl, c.VendorCache,
			c.intelPcsRootCas, true)
		if err != nil {
			return nil, fmt.Errorf("failed to create tdx endorser: %w", err)
		}
	}

	s := &http.Server{
		Addr:              c.EstAddr,
		Handler:           nil,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	server := &Server{
		server:     s,
		estCaKey:   c.estCaKey,
		estCaChain: c.estCaChain,
		rootCas:    c.rootCas,
		tpmConf: provision.TpmConfig{
			VerifyEkCert: c.VerifyEkCert,
			DbPath:       c.TpmEkCertDb,
		},
		snpEndorser:       snpEndorser,
		tdxEndorser:       tdxEndorser,
		authMethods:       c.authMethods,
		tokenPath:         c.TokenPath,
		publishResults:    c.PublishResults,
		publishOcsf:       c.PublishOcsf,
		publishNetwork:    c.PublishNetwork,
		publishFile:       c.PublishFile,
		publishToken:      publishToken,
		allowSystemCerts:  c.AllowSystemCerts,
		publishClientCert: publishClientCert,
		namingPolicy:      CsrPassthrough{},
		certValidity:      c.certValidity,
		omspFolder:        c.OmspFolder,
		omspKey:           c.omspKey,
		omspCaChain:       c.omspCaChain,
		omspUrl:           c.OmspUrl,
	}

	// EST endpoints
	http.HandleFunc(est.EndpointPrefix+est.CacertsEndpoint, server.handleCacerts)
	http.HandleFunc(est.EndpointPrefix+est.EnrollEndpoint, server.handleSimpleenroll)

	// Custom EST endpoints
	http.HandleFunc(est.EndpointPrefix+est.TpmActivateEnrollEndpoint, server.handleTpmActivateEnroll)
	http.HandleFunc(est.EndpointPrefix+est.TpmCertifyEnrollEndpoint, server.handleTpmCertifyEnroll)
	http.HandleFunc(est.EndpointPrefix+est.AttestEnrollEndpoint, server.handleAttestEnroll)

	// Hardware vendor collateral endpoints
	server.registerCollateralEndpoints(http.DefaultServeMux)

	// Metadata file serving
	httpHandleMetadata(c.HttpFolder)

	// OMSP Server for fetching manifest revocation information (optional)
	if c.OmspUrl != "" {
		u, err := url.Parse(c.OmspUrl)
		if err != nil {
			return nil, fmt.Errorf("failed to parse omsp Endpoint from provided OmspURL: %w", err)
		}
		http.HandleFunc(u.Path, server.handleRevocationRequest)
	}

	// Log and return 404 for unmatched routes
	http.HandleFunc("/", server.handleNotFound)

	return server, nil
}

// registerCollateralEndpoints registers the hardware vendor collateral endpoints,
// which proxy and cache the rate-limited AMD KDS and the Intel PCS or a PCCS. The
// endpoints mirror the vendor APIs, so that CVMs can fetch all collateral from a
// single address without requiring internet access. The Intel endpoints are only
// served if an upstream Intel PCS or PCCS is configured
func (s *Server) registerCollateralEndpoints(mux *http.ServeMux) {

	mux.HandleFunc("GET /vcek/v1/{codeName}/cert_chain", s.handleVcekCertChain)
	mux.HandleFunc("GET /vlek/v1/{codeName}/cert_chain", s.handleVlekCertChain)
	mux.HandleFunc("GET /vcek/v1/{codeName}/{chipId}", s.handleVcek)

	if s.tdxEndorser == nil {
		return
	}

	mux.HandleFunc("GET /sgx/certification/v4/pckcrl", s.handlePckCrl)
	mux.HandleFunc("GET /sgx/certification/v4/tcb", s.handleSgxTcbInfo)
	mux.HandleFunc("GET /tdx/certification/v4/tcb", s.handleTdxTcbInfo)
	mux.HandleFunc("GET /sgx/certification/v4/qe/identity", s.handleSgxQeIdentity)
	mux.HandleFunc("GET /tdx/certification/v4/qe/identity", s.handleTdxQeIdentity)
	mux.HandleFunc("GET "+endorser.IntelRootCaCrlPath, s.handleRootCaCrl)
}

func (s *Server) Serve() error {
	log.Infof("Waiting for EST requests on %v (https)", s.server.Addr)
	err := s.server.ListenAndServeTLS("", "")
	if err != nil {
		return fmt.Errorf("EST server failed: %w", err)
	}
	return nil
}

func httpHandleMetadata(path string) {

	log.Debugf("Serving Directory: %v", path)

	d := filepath.Base(path)

	fs := http.FileServer(http.Dir(path))
	http.Handle("/"+d+"/", logRequest(http.StripPrefix("/"+d, fs)))
}

func logRequest(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debugf("Received request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		h.ServeHTTP(w, r)
	})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	log.Debugf("Received request: %s %s from %s - not found", r.Method, r.URL.Path, r.RemoteAddr)
	http.NotFound(w, r)
}

func sendResponse(w http.ResponseWriter, contentType, transferEncoding string, payload []byte,
) error {

	if contentType != "" {
		w.Header().Set(internal.HttpContentTypeHeader, contentType)
	}
	if transferEncoding != "" {
		w.Header().Set(internal.HttpTransferEncodingHeader, transferEncoding)
	}
	w.WriteHeader(http.StatusOK)

	log.Tracef("Sending HTTP response")
	n, err := w.Write(payload)
	if err != nil {
		return fmt.Errorf("failed to send HTTP response: %w", err)
	}
	if n != len(payload) {
		log.Warnf("Failed to send HTTP response: Only %v of %v bytes sent",
			n, len(payload))
	}

	return nil
}

func writeHttpErrorf(w http.ResponseWriter, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Warnf("%v", msg)
	http.Error(w, msg, http.StatusBadRequest)
}

// writeBadRequest rejects a malformed collateral proxy request
func writeBadRequest(w http.ResponseWriter, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Warnf("%v", msg)
	http.Error(w, msg, http.StatusBadRequest)
}

// writeProxyError reports a failure to obtain collateral from the upstream
// vendor service (AMD KDS, Intel PCS or PCCS)
func writeProxyError(w http.ResponseWriter, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Warnf("%v", msg)
	http.Error(w, msg, http.StatusBadGateway)
}

func verifyBootStrapToken(tokenPath string, req *http.Request) error {

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return fmt.Errorf("missing or invalid authorization header")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	token = strings.TrimSpace(token)

	if err := est.VerifyToken(tokenPath, token, ""); err != nil {
		return fmt.Errorf("failed to verify bootstrap token: %w", err)
	}

	return nil
}
