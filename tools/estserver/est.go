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
	"encoding/asn1"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
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

	sendResponse(w, est.MimeTypePKCS7, internal.HttpEncodingTypeBase64, encoded)
}

func (s *Server) handleCsrattrs(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received /csrattrs request from %v", req.RemoteAddr)

	if strings.Compare(req.Method, "GET") != 0 {
		writeHttpErrorf(w, "Only method GET implemented for csrattrs request")
		return
	}

	// RFC 7030 4.5.2: 204 indicates that no CSR attributes are requested
	if !s.auth[est.EnrollEndpoint].Has(internal.AuthAttestation) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// CsrAttrs ::= SEQUENCE OF AttrOrOID, the attestation attribute OID requests evidence
	body, err := asn1.Marshal([]asn1.ObjectIdentifier{est.OidAttestation})
	if err != nil {
		writeHttpErrorf(w, "Failed to marshal CSR attributes: %v", err)
		return
	}

	sendResponse(w, est.MimeTypeCSRAttrs, internal.HttpEncodingTypeBase64, est.EncodeBase64(body))
}

func (s *Server) handleSimpleenroll(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received /simpleenroll request from %v", req.RemoteAddr)

	if strings.Compare(req.Method, "POST") != 0 {
		writeHttpErrorf(w, "Only method POST implemented for simpleenroll request")
		return
	}

	// Check content type pkcs10 CSR
	t, _, err := mime.ParseMediaType(req.Header.Get(internal.HttpContentTypeHeader))
	if err != nil {
		writeHttpErrorf(w, "failed to parse media type %s: %v",
			internal.HttpContentTypeHeader, err)
		return
	}
	if !strings.HasPrefix(t, est.MimeTypePKCS10) {
		writeHttpErrorf(w, "invalid %s %s, must begin with %s", internal.HttpContentTypeHeader,
			t, est.MimeTypePKCS10)
		return
	}

	csr, err := est.ParsePkcs10Csr(req.Body)
	if err != nil {
		writeHttpErrorf(w, "Failed to parse CSR: %v", err)
		return
	}

	att, err := est.ParseCsrAttestation(csr)
	if err != nil {
		writeHttpErrorf(w, "Failed to parse CSR attestation: %v", err)
		return
	}

	var attest attestFunc
	if att != nil && att.Report != nil {
		attest = func() (*ar.AttestationResult, error) {
			log.Tracef("Verifying attestation report against %v metadata CAs", len(s.rootCas))
			return s.verifyAttestationReport(csr, att.Report)
		}
	}
	attestResult, err := s.authorize(est.EnrollEndpoint, req, attest)
	if err != nil {
		writeUnauthorized(w, err)
		return
	}

	// TPM key evidence is verified regardless of the authentication methods
	if att != nil && att.TpmCertify != nil {
		if err := s.verifyTpmKey(csr, att, attestResult); err != nil {
			writeHttpErrorf(w, "Failed to verify TPM key evidence: %v", err)
			return
		}
	}

	cert, err := enrollCert(csr, s.estCaKey, s.estCaChain[0], s.namingPolicy, attestResult,
		s.certValidity, tlsProfile(s.certPolicies.FromResult(attestResult)))
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

	sendResponse(w, est.MimeTypePKCS7, internal.HttpEncodingTypeBase64, encoded)
}

// verifyTpmKey verifies that the CSR key resides in the same TPM as the AK, which is either
// certified by the EST CA or bound to the attestation result of the request. The AK chain is
// carried leaf first in the attestation bundle certificates
func (s *Server) verifyTpmKey(csr *x509.CertificateRequest, att *est.CsrAttestation,
	result *ar.AttestationResult,
) error {

	if len(att.Certs) == 0 {
		return fmt.Errorf("no AK certificate provided")
	}
	ak := att.Certs[0]

	err := provision.VerifyIk(*att.TpmCertify, ak.PublicKey)
	if err != nil {
		return err
	}

	err = provision.VerifyTpmCsr(att.TpmCertify.Public, csr)
	if err != nil {
		return fmt.Errorf("failed to verify CSR: %w", err)
	}

	// Only the EST CA issues AK certificates via credential activation
	_, chainErr := internal.VerifyCertChain(att.Certs, s.estCaChain,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageAny})
	if chainErr == nil && !internal.HasUnknownExtKeyUsage(ak, internal.OidAkCertificate) {
		chainErr = fmt.Errorf("AK certificate lacks extended key usage tcg-kp-AIKCertificate")
	}
	if chainErr == nil {
		log.Debugf("TPM key certified by AK %v issued by EST CA", ak.Subject.CommonName)
		return nil
	}

	// AKs not certified by the EST CA, e.g. self-signed vTPM AKs, require attestation
	if result == nil {
		return fmt.Errorf("AK not certified by EST CA and request not authenticated via "+
			"attestation: %w", chainErr)
	}
	if err := provision.VerifyAkBinding(result, ak.PublicKey); err != nil {
		return fmt.Errorf("AK not certified by EST CA (%v) and not bound to attestation "+
			"report: %w", chainErr, err)
	}
	log.Debugf("TPM key certified by AK %v bound to attestation report", ak.Subject.CommonName)

	return nil
}

func (s *Server) handleTpmActivateEnroll(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received /tpmactivateenroll request from %v", req.RemoteAddr)

	if strings.Compare(req.Method, "POST") != 0 {
		writeHttpErrorf(w, "Only method POST implemented for tpmactivateenroll request")
		return
	}

	if _, err := s.authorize(est.TpmActivateEnrollEndpoint, req, nil); err != nil {
		writeUnauthorized(w, err)
		return
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

	err := est.DecodeMultipart(
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
		req.Header.Get(internal.HttpContentTypeHeader),
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

	// The AK only signs attestation evidence and must not be usable for TLS
	cert, err := enrollCert(csr, s.estCaKey, s.estCaChain[0], s.namingPolicy, nil, s.certValidity,
		akProfile)
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

	sendResponse(w, contentType, "", payload.Bytes())
}

// certProfile states what an issued key may be used for (extended key usages) and how it was
// enrolled (certificate policies)
type certProfile struct {
	ekus        []x509.ExtKeyUsage
	unknownEkus []asn1.ObjectIdentifier
	policies    []x509.OID
}

// akProfile restricts AK certificates to signing attestation evidence
var akProfile = certProfile{unknownEkus: []asn1.ObjectIdentifier{internal.OidAkCertificate}}

// tlsProfile returns the profile of TLS certificates with the given certificate policies
func tlsProfile(policies []x509.OID) certProfile {
	return certProfile{ekus: internal.TlsExtKeyUsage, policies: policies}
}

// enrollCert generates a new certificate from a CSR signed by the CA. The naming policy determines
// the certificate fields. The attestation result can be nil for enrollment paths without
// attestation, a validity of zero uses the default
func enrollCert(csr *x509.CertificateRequest, key crypto.PrivateKey, parent *x509.Certificate,
	policy NamingPolicy, result *ar.AttestationResult, validity time.Duration, profile certProfile,
) (*x509.Certificate, error) {

	fields, err := policy.Assign(csr, validity, result)
	if err != nil {
		return nil, fmt.Errorf("naming policy rejected enrollment: %w", err)
	}
	fields.ExtKeyUsage = profile.ekus
	fields.UnknownExtKeyUsage = profile.unknownEkus
	fields.Policies = profile.policies

	tmpl, err := internal.PrepareCert(csr, fields)
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
