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
	"crypto/x509"
	"net/http"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision/est"
	log "github.com/sirupsen/logrus"
)

func (s *Server) handleSnpVcek(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received /snpvcek request from %v", req.RemoteAddr)

	if strings.Compare(req.Method, "POST") != 0 {
		writeHttpErrorf(w, "Method %v not implemented for snpenroll request", req.Method)
		return
	}

	if s.authMethods.Has(internal.AuthToken) {
		if err := verifyBootStrapToken(s.tokenPath, req); err != nil {
			writeHttpErrorf(w, "%v (Failed to verify bootstrap token: %v)", http.StatusUnauthorized, err)
			return
		}
	}

	var chipId []byte
	var tcb uint64
	var codeName string

	_, err := est.DecodeMultipart(
		req.Body,
		[]est.MimeMultipart{
			{ContentType: est.MimeTypeOctetStream, Data: &chipId},
			{ContentType: est.MimeTypeOctetStream, Data: &tcb},
			{ContentType: est.MimeTypeOctetStream, Data: &codeName},
		},
		req.Header.Get(est.ContentTypeHeader),
	)
	if err != nil {
		writeHttpErrorf(w, "Failed to decode multipart: %v", err)
		return
	}

	vcek, err := s.snpConf.GetVcek(codeName, chipId, tcb)
	if err != nil {
		writeHttpErrorf(w, "Failed to get VCEK: %v", err)
		return
	}

	body, err := est.EncodePkcs7CertsOnly([]*x509.Certificate{vcek})
	if err != nil {
		writeHttpErrorf(w, "Failed to encode PKCS7 certs-only: %v", err)
		return
	}
	encoded := est.EncodeBase64(body)

	err = sendResponse(w, est.MimeTypePKCS7, est.EncodingTypeBase64, encoded)
	if err != nil {
		writeHttpErrorf(w, "Failed to send generated certificate: %v", err)
		return
	}
}

func (s *Server) handleSnpCa(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received /snpca request from %v", req.RemoteAddr)

	if strings.Compare(req.Method, "POST") != 0 {
		writeHttpErrorf(w, "Method %v not implemented for /snpca request", req.Method)
		return
	}

	if s.authMethods.Has(internal.AuthToken) {
		if err := verifyBootStrapToken(s.tokenPath, req); err != nil {
			writeHttpErrorf(w, "%v (Failed to verify bootstrap token: %v)", http.StatusUnauthorized, err)
			return
		}
	}

	var akTypeRaw []byte
	var codeName string

	_, err := est.DecodeMultipart(
		req.Body,
		[]est.MimeMultipart{
			{ContentType: est.MimeTypeOctetStream, Data: &akTypeRaw},
			{ContentType: est.MimeTypeOctetStream, Data: &codeName},
		},
		req.Header.Get(est.ContentTypeHeader),
	)
	if err != nil {
		writeHttpErrorf(w, "Failed to decode multipart: %v", err)
		return
	}

	akType := internal.AkType(akTypeRaw[0])

	log.Debugf("Get SNP CA for %q, ak type %d", codeName, akType)

	ca, err := s.snpConf.GetSnpCa(codeName, akType)
	if err != nil {
		writeHttpErrorf(w, "Failed to get VCEK: %v", err)
		return
	}

	body, err := est.EncodePkcs7CertsOnly(ca)
	if err != nil {
		writeHttpErrorf(w, "Failed to encode PKCS7 certs-only: %v", err)
		return
	}
	encoded := est.EncodeBase64(body)

	err = sendResponse(w, est.MimeTypePKCS7, est.EncodingTypeBase64, encoded)
	if err != nil {
		writeHttpErrorf(w, "Failed to send generated certificate: %v", err)
		return
	}
}
