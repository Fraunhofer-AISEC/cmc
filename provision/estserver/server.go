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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision"
	"github.com/Fraunhofer-AISEC/cmc/provision/est"
	log "github.com/sirupsen/logrus"

	_ "github.com/mattn/go-sqlite3"
)

type Server struct {
	server       *http.Server
	estCaKey     crypto.PrivateKey
	estCaChain   []*x509.Certificate
	metadataCas  []*x509.Certificate
	snpEndorser  *provision.SnpEndorser
	tpmConf      provision.TpmConfig
	authMethods  internal.AuthMethod
	tokenPath    string
	publishAddr  string
	publishFile  string
	publishToken []byte
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
		clientRoots := x509.NewCertPool()
		for _, ca := range c.ClientTlsCas {
			c, err := internal.ReadCert(ca)
			if err != nil {
				return nil, fmt.Errorf("failed to parse client CA certificate: %w", err)
			}
			clientRoots.AddCert(c)
		}
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		tlsCfg.ClientCAs = clientRoots
	}

	var publishToken []byte
	if c.PublishToken != "" {
		var err error
		publishToken, err = os.ReadFile(c.PublishToken)
		if err != nil {
			return nil, fmt.Errorf("failed to read publish token: %w", err)
		}
	}

	s := &http.Server{
		Addr:      c.EstAddr,
		Handler:   nil,
		TLSConfig: tlsCfg,
	}

	server := &Server{
		server:      s,
		estCaKey:    c.estCaKey,
		estCaChain:  c.estCaChain,
		metadataCas: c.metadataCas,
		tpmConf: provision.TpmConfig{
			VerifyEkCert: c.VerifyEkCert,
			DbPath:       c.TpmEkCertDb,
		},
		snpEndorser:  provision.NewSnpEndorser(c.VcekCacheFolder),
		authMethods:  c.authMethods,
		tokenPath:    c.TokenPath,
		publishAddr:  c.PublishAddr,
		publishFile:  c.PublishFile,
		publishToken: publishToken,
	}

	// EST endpoints
	http.HandleFunc(est.EndpointPrefix+est.CacertsEndpoint, server.handleCacerts)
	http.HandleFunc(est.EndpointPrefix+est.EnrollEndpoint, server.handleSimpleenroll)

	// Custom EST endpoints
	http.HandleFunc(est.EndpointPrefix+est.TpmActivateEnrollEndpoint, server.handleTpmActivateEnroll)
	http.HandleFunc(est.EndpointPrefix+est.TpmCertifyEnrollEndpoint, server.handleTpmCertifyEnroll)
	http.HandleFunc(est.EndpointPrefix+est.AttestEnrollEndpoint, server.handleAttestEnroll)
	http.HandleFunc(est.EndpointPrefix+est.SnpVcekEndpoint, server.handleSnpVcek)
	http.HandleFunc(est.EndpointPrefix+est.SnpCaCertsEndpoint, server.handleSnpCa)

	// Metadata file serving
	httpHandleMetadata(c.HttpFolder)

	return server, nil
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

func sendResponse(w http.ResponseWriter, contentType, transferEncoding string, payload []byte,
) error {

	if contentType != "" {
		w.Header().Set(est.ContentTypeHeader, contentType)
	}
	if transferEncoding != "" {
		w.Header().Set(est.TransferEncodingHeader, transferEncoding)
	}
	w.WriteHeader(http.StatusOK)

	log.Tracef("Sending EST response")
	n, err := w.Write(payload)
	if err != nil {
		return fmt.Errorf("failed to handle cacerts request: %w", err)
	}
	if n != len(payload) {
		log.Warnf("Failed to handle cacerts request: Only %v of %v bytes sent",
			n, len(payload))
	}

	return nil
}

func writeHttpErrorf(w http.ResponseWriter, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Warn(msg)
	http.Error(w, msg, http.StatusBadRequest)
}

func verifyBootStrapToken(tokenPath string, req *http.Request) error {

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return fmt.Errorf("missing or invalid authorization header")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	token = strings.TrimSpace(token)

	if err := est.VerifyToken(tokenPath, token); err != nil {
		return fmt.Errorf("failed to verify bootstrap token: %w", err)
	}

	return nil
}
