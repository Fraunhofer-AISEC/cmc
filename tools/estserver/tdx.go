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
	"encoding/pem"
	"net/http"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision/endorser"
	"github.com/google/go-tdx-guest/pcs"
	log "github.com/sirupsen/logrus"
)

const (
	fmspcParam    = "fmspc"
	caParam       = "ca"
	encodingParam = "encoding"

	contentTypeJson = "application/json"
	contentTypeCrl  = "application/pkix-crl"
	contentTypePem  = "application/x-pem-file"

	pemTypeX509Crl = "X509 CRL"
)

func (s *Server) handleSgxTcbInfo(w http.ResponseWriter, req *http.Request) {
	s.serveTcbInfo(w, req, ar.SGX_QUOTE_TYPE)
}

func (s *Server) handleTdxTcbInfo(w http.ResponseWriter, req *http.Request) {
	s.serveTcbInfo(w, req, ar.TDX_QUOTE_TYPE)
}

func (s *Server) handleSgxQeIdentity(w http.ResponseWriter, req *http.Request) {
	s.serveQeIdentity(w, req, ar.SGX_QUOTE_TYPE)
}

func (s *Server) handleTdxQeIdentity(w http.ResponseWriter, req *http.Request) {
	s.serveQeIdentity(w, req, ar.TDX_QUOTE_TYPE)
}

func (s *Server) serveTcbInfo(w http.ResponseWriter, req *http.Request, quoteType ar.IntelQuoteType) {

	log.Debugf("Received TCB info request %v from %v", req.URL.RequestURI(), req.RemoteAddr)

	fmspc := req.URL.Query().Get(fmspcParam)
	if err := endorser.ValidateFmspc(fmspc); err != nil {
		writeBadRequest(w, "%v", err)
		return
	}

	tcbInfo, issuerChain, err := s.tdxEndorser.GetTcbInfo(fmspc, quoteType)
	if err != nil {
		writeProxyError(w, "failed to get TCB info for FMSPC %v: %v", fmspc, err)
		return
	}

	w.Header().Set(pcs.TcbInfoIssuerChainPhrase, issuerChain)
	writeCollateral(w, contentTypeJson, tcbInfo)
}

func (s *Server) serveQeIdentity(w http.ResponseWriter, req *http.Request, quoteType ar.IntelQuoteType) {

	log.Debugf("Received QE identity request %v from %v", req.URL.RequestURI(), req.RemoteAddr)

	qeIdentity, issuerChain, err := s.tdxEndorser.GetQeIdentity(quoteType)
	if err != nil {
		writeProxyError(w, "failed to get QE identity: %v", err)
		return
	}

	w.Header().Set(pcs.SgxQeIdentityIssuerChainPhrase, issuerChain)
	writeCollateral(w, contentTypeJson, qeIdentity)
}

func (s *Server) handlePckCrl(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received PCK CRL request %v from %v", req.URL.RequestURI(), req.RemoteAddr)

	ca := req.URL.Query().Get(caParam)
	if err := endorser.ValidatePckCa(ca); err != nil {
		writeBadRequest(w, "%v", err)
		return
	}

	// As the Intel PCS, return PEM unless DER is explicitly requested
	encoding := strings.ToLower(req.URL.Query().Get(encodingParam))
	if encoding != "" && encoding != "der" && encoding != "pem" {
		writeBadRequest(w, "invalid encoding %q (expected der or pem)", encoding)
		return
	}

	der, issuerChain, err := s.tdxEndorser.GetPckCrl(ca)
	if err != nil {
		writeProxyError(w, "failed to get %v PCK CRL: %v", ca, err)
		return
	}

	crl := der
	contentType := contentTypeCrl
	if encoding != "der" {
		crl = pem.EncodeToMemory(&pem.Block{Type: pemTypeX509Crl, Bytes: der})
		contentType = contentTypePem
	}

	w.Header().Set(pcs.SgxPckCrlIssuerChainPhrase, issuerChain)
	writeCollateral(w, contentType, crl)
}

// handleRootCaCrl serves the Intel root CA CRL under the path the CRL distribution
// point of the Intel root CA certificate specifies, so that CVMs without internet
// access can fetch it from this server instead of from the Intel service
func (s *Server) handleRootCaCrl(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received root CA CRL request from %v", req.RemoteAddr)

	crl, err := s.tdxEndorser.GetRootCaCrl()
	if err != nil {
		writeProxyError(w, "failed to get Intel root CA CRL: %v", err)
		return
	}

	writeCollateral(w, contentTypeCrl, crl)
}

// writeCollateral sends collateral to the client. Issuer chain headers must already
// have been set by the caller: clients parse the certificate chains from the
// headers the Intel PCS delivers them in, so they must be forwarded verbatim
func writeCollateral(w http.ResponseWriter, contentType string, payload []byte) {

	w.Header().Set(internal.HttpContentTypeHeader, contentType)
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(payload); err != nil {
		log.Warnf("failed to write collateral response: %v", err)
	}
}
