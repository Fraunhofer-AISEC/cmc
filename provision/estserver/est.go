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
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision"
	"github.com/Fraunhofer-AISEC/cmc/provision/est"
	"github.com/google/go-attestation/attest"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/pkcs7"

	_ "github.com/mattn/go-sqlite3"
)

func (s *Server) handleCacerts(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received /cacerts %v request from %v", req.Method, req.RemoteAddr)

	if strings.Compare(req.Method, "GET") != 0 {
		writeHttpErrorf(w, "Only method GET implemented for cacerts request")
		return
	}

	// RFC7030: The EST server SHOULD NOT require client authentication for /cacerts
	// endpoint, thus we do not perform token authentication, even if configured

	body, err := est.EncodePkcs7CertsOnly(s.estCaChain)
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

func (s *Server) handleSimpleenroll(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received /simpleenroll request from %v", req.RemoteAddr)

	if strings.Compare(req.Method, "POST") != 0 {
		writeHttpErrorf(w, "Only method POST implemented for simpleenroll request")
		return
	}

	if s.authMethods.Has(internal.AuthToken) {
		if err := verifyBootStrapToken(s.tokenPath, req); err != nil {
			writeHttpErrorf(w, "%v (Failed to verify bootstrap token: %v)", http.StatusUnauthorized, err)
			return
		}
	}

	// Check content type pkcs10 CSR
	t, _, err := mime.ParseMediaType(req.Header.Get(est.ContentTypeHeader))
	if err != nil {
		writeHttpErrorf(w, "failed to parse media type %s: %v",
			est.ContentTypeHeader, err)
		return
	}
	if !strings.HasPrefix(t, est.MimeTypePKCS10) {
		writeHttpErrorf(w, "invalid %s %s, must begin with %s", est.ContentTypeHeader,
			t, est.MimeTypePKCS10)
		return
	}

	csr, err := est.ParsePkcs10Csr(req.Body)
	if err != nil {
		writeHttpErrorf(w, "Failed to parse CSR: %v", err)
		return
	}

	cert, err := enrollCert(csr, s.estCaKey, s.estCaChain[0])
	if err != nil {
		writeHttpErrorf(w, "Failed to enroll certificate: %v", err)
		return
	}

	body, err := est.EncodePkcs7CertsOnly([]*x509.Certificate{cert})
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

func (s *Server) handleTpmActivateEnroll(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received /tpmactivateenroll request from %v", req.RemoteAddr)

	if strings.Compare(req.Method, "POST") != 0 {
		writeHttpErrorf(w, "Only method POST implemented for tpmactivateenroll request")
		return
	}

	if s.authMethods.Has(internal.AuthToken) {
		if err := verifyBootStrapToken(s.tokenPath, req); err != nil {
			writeHttpErrorf(w, "%v (Failed to verify bootstrap token: %v)", http.StatusUnauthorized, err)
			return
		}
	}

	var tpmInfo string
	var ekCertUrl string
	var csr *x509.CertificateRequest
	var ekCertDer []byte
	var ekPubPkix []byte
	var akPublic []byte
	var akCreateData []byte
	var akCreateAttestation []byte
	var akCreateSignature []byte

	_, err := est.DecodeMultipart(
		req.Body,
		[]est.MimeMultipart{
			{ContentType: est.MimeTypeTextPlain, Data: &tpmInfo},
			{ContentType: est.MimeTypeTextPlain, Data: &ekCertUrl},
			{ContentType: est.MimeTypePKCS10, Data: &csr},
			{ContentType: est.MimeTypeOctetStream, Data: &akPublic},
			{ContentType: est.MimeTypeOctetStream, Data: &akCreateData},
			{ContentType: est.MimeTypeOctetStream, Data: &akCreateAttestation},
			{ContentType: est.MimeTypeOctetStream, Data: &akCreateSignature},
			{ContentType: est.MimeTypeOctetStream, Data: &ekPubPkix},
			{ContentType: est.MimeTypeOctetStream, Data: &ekCertDer},
		},
		req.Header.Get(est.ContentTypeHeader),
	)
	if err != nil {
		writeHttpErrorf(w, "Failed to decode multipart: %v", err)
		return
	}

	err = provision.VerifyEk(ekPubPkix, ekCertDer, tpmInfo, ekCertUrl, s.tpmConf.DbPath, s.tpmConf.VerifyEkCert)
	if err != nil {
		writeHttpErrorf(w, "Failed to verify EK: %v", err)
		return
	}

	ekPub, err := x509.ParsePKIXPublicKey(ekPubPkix)
	if err != nil {
		writeHttpErrorf(w, "failed to parse PKIX public key: %v", err)
		return
	}

	params := attest.ActivationParameters{
		EK: ekPub,
		AK: attest.AttestationParameters{
			Public:                  akPublic,
			UseTCSDActivationFormat: false,
			CreateData:              akCreateData,
			CreateAttestation:       akCreateAttestation,
			CreateSignature:         akCreateSignature,
		},
	}

	// Generate the credential activation challenge. This includes verifying, that the
	// AK is a restricted, fixedTPM, fixedParent key
	secret, encryptedCredentials, err := params.Generate()
	if err != nil {
		writeHttpErrorf(w, "failed to generate AK credentials: %v", err)
		return
	}

	// Verify that activated AK is actually the certificate public key
	err = provision.VerifyTpmCsr(akPublic, csr)
	if err != nil {
		writeHttpErrorf(w, "failed to verify AK: %v", err)
		return
	}

	cert, err := enrollCert(csr, s.estCaKey, s.estCaChain[0])
	if err != nil {
		writeHttpErrorf(w, "Failed to enroll certificate: %v", err)
		return
	}

	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256GCM
	encryptedCert, err := pkcs7.EncryptUsingPSK(cert.Raw, secret)
	if err != nil {
		writeHttpErrorf(w, "Failed to encrypt using PSK: %v", err)
		return
	}

	payload, contentType, err := est.EncodeMultiPart(
		[]est.MimeMultipart{
			{ContentType: est.MimeTypeOctetStream, Data: encryptedCredentials.Credential},
			{ContentType: est.MimeTypeOctetStream, Data: encryptedCredentials.Secret},
			{ContentType: est.MimeTypePKCS7Enveloped, Data: encryptedCert},
		},
	)
	if err != nil {
		writeHttpErrorf(w, "Failed to encode multipart: %v", err)
		return
	}

	err = sendResponse(w, contentType, "", payload.Bytes())
	if err != nil {
		writeHttpErrorf(w, "Failed to send generated certificate: %v", err)
	}
}

func (s *Server) handleTpmCertifyEnroll(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received /tpmcertifyenroll request from %v", req.RemoteAddr)

	if strings.Compare(req.Method, "POST") != 0 {
		writeHttpErrorf(w, "Only method POST implemented for tpmcertifyenroll request")
		return
	}

	if s.authMethods.Has(internal.AuthToken) {
		if err := verifyBootStrapToken(s.tokenPath, req); err != nil {
			writeHttpErrorf(w, "%v (Failed to verify bootstrap token: %v)", http.StatusUnauthorized, err)
			return
		}
	}

	var csr *x509.CertificateRequest
	var ikPublic []byte
	var ikCreateData []byte
	var ikCreateAttestation []byte
	var ikCreateSignature []byte
	var akPublic []byte
	var report []byte

	_, err := est.DecodeMultipart(
		req.Body,
		[]est.MimeMultipart{
			{ContentType: est.MimeTypePKCS10, Data: &csr},
			{ContentType: est.MimeTypeOctetStream, Data: &ikPublic},
			{ContentType: est.MimeTypeOctetStream, Data: &ikCreateData},
			{ContentType: est.MimeTypeOctetStream, Data: &ikCreateAttestation},
			{ContentType: est.MimeTypeOctetStream, Data: &ikCreateSignature},
			{ContentType: est.MimeTypeOctetStream, Data: &akPublic},
			{ContentType: est.MimeTypeOctetStream, Data: &report},
		},
		req.Header.Get(est.ContentTypeHeader),
	)
	if err != nil {
		writeHttpErrorf(w, "Failed to decode multipart: %v", err)
		return
	}

	// Verify the IK was certified by AK
	ikParams := attest.CertificationParameters{
		Public:            ikPublic,
		CreateData:        ikCreateData,
		CreateAttestation: ikCreateAttestation,
		CreateSignature:   ikCreateSignature,
	}
	err = provision.VerifyIk(ikParams, akPublic)
	if err != nil {
		writeHttpErrorf(w, "failed to verify IK: %v", err)
		return
	}

	// Verify that certified IK is actually the CSR public key
	err = provision.VerifyTpmCsr(ikPublic, csr)
	if err != nil {
		writeHttpErrorf(w, "failed to verify CSR: %v", err)
		return
	}

	// Verify attestation report if authentication method attestation is activated
	if s.authMethods.Has(internal.AuthAttestation) {
		log.Tracef("Verifying attestation report against %v metadata CAs", len(s.metadataCas))
		err = verifyAttestationReport(csr, s.metadataCas, report, s.publishAddr, s.publishFile, s.publishToken)
		if err != nil {
			writeHttpErrorf(w, "Failed to verify attestation report: %v", err)
			return
		}
	}

	cert, err := enrollCert(csr, s.estCaKey, s.estCaChain[0])
	if err != nil {
		writeHttpErrorf(w, "Failed to enroll certificate: %v", err)
		return
	}

	body, err := est.EncodePkcs7CertsOnly([]*x509.Certificate{cert})
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

func (s *Server) handleAttestEnroll(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received /attestenroll request from %v", req.RemoteAddr)

	if strings.Compare(req.Method, "POST") != 0 {
		writeHttpErrorf(w, "Only method POST implemented for tpmcertifyenroll request")
		return
	}

	if s.authMethods.Has(internal.AuthToken) {
		if err := verifyBootStrapToken(s.tokenPath, req); err != nil {
			writeHttpErrorf(w, "%v (Failed to verify bootstrap token: %v)", http.StatusUnauthorized, err)
			return
		}
	}

	var csr *x509.CertificateRequest
	var report []byte

	_, err := est.DecodeMultipart(
		req.Body,
		[]est.MimeMultipart{
			{ContentType: est.MimeTypePKCS10, Data: &csr},
			{ContentType: est.MimeTypeOctetStream, Data: &report},
		},
		req.Header.Get(est.ContentTypeHeader),
	)
	if err != nil {
		writeHttpErrorf(w, "Failed to decode multipart: %v", err)
		return
	}

	// Verify attestation report if authentication method attestation is activated
	if s.authMethods.Has(internal.AuthAttestation) {
		err = verifyAttestationReport(csr, s.metadataCas, report, s.publishAddr, s.publishFile, s.publishToken)
		if err != nil {
			writeHttpErrorf(w, "Failed to verify attestation report: %v", err)
			return
		}
	}

	cert, err := enrollCert(csr, s.estCaKey, s.estCaChain[0])
	if err != nil {
		writeHttpErrorf(w, "Failed to enroll certificate: %v", err)
		return
	}

	body, err := est.EncodePkcs7CertsOnly([]*x509.Certificate{cert})
	if err != nil {
		writeHttpErrorf(w, "Failed to encode PKCS7 certs-only: %v", err)
		return
	}
	encoded := est.EncodeBase64(body)

	log.Debugf("Enrolled cert %v", cert.Subject.CommonName)

	err = sendResponse(w, est.MimeTypePKCS7, est.EncodingTypeBase64, encoded)
	if err != nil {
		writeHttpErrorf(w, "Failed to send generated certificate: %v", err)
		return
	}
}

// enrollCert generates a new certificate signed by the CA
func enrollCert(csr *x509.CertificateRequest, key crypto.PrivateKey, parent *x509.Certificate,
) (*x509.Certificate, error) {

	tmpl, err := internal.CreateCert(csr)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert from CSR: %w", err)
	}

	certDer, err := x509.CreateCertificate(rand.Reader, tmpl, parent, csr.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create IK certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	return cert, nil
}
