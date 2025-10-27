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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"mime"
	"net/http"
	"path/filepath"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision"
	"github.com/Fraunhofer-AISEC/cmc/provision/est"
	pub "github.com/Fraunhofer-AISEC/cmc/publish"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/Fraunhofer-AISEC/go-attestation/attest"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/pkcs7"

	_ "github.com/mattn/go-sqlite3"
)

type Server struct {
	server      *http.Server
	estCaKey    *ecdsa.PrivateKey
	estCaChain  []*x509.Certificate
	metadataCas []*x509.Certificate
	snpConf     *provision.SnpConfig
	tpmConf     provision.TpmConfig
	authMethods provision.AuthMethod
	tokenPath   string
	publishAddr string
	publishFile string
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
	if c.authMethods.Has(provision.AuthCertificate) {
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
		snpConf: &provision.SnpConfig{
			VcekCacheFolder: c.VcekCacheFolder,
			Vceks:           make(map[provision.VcekInfo][]byte),
		},
		authMethods: c.authMethods,
		tokenPath:   c.TokenPath,
		publishAddr: c.PublishAddr,
		publishFile: c.PublishFile,
	}

	cacertsEndpoint := est.EndpointPrefix + est.CacertsEndpoint
	simpleenrollEndpoint := est.EndpointPrefix + est.EnrollEndpoint
	tpmActivateEnrollEndpoint := est.EndpointPrefix + est.TpmActivateEnrollEndpoint
	tpmCertifyEnrollEndpoint := est.EndpointPrefix + est.TpmCertifyEnrollEndpoint
	ccEnrollEndpoint := est.EndpointPrefix + est.CcEnrollEndpoint
	snpVcekEndpoint := est.EndpointPrefix + est.SnpVcekEndpoint
	snpCaCertsEndpoint := est.EndpointPrefix + est.SnpCaCertsEndpoint

	http.HandleFunc(cacertsEndpoint, server.handleCacerts)
	http.HandleFunc(simpleenrollEndpoint, server.handleSimpleenroll)
	http.HandleFunc(tpmActivateEnrollEndpoint, server.handleTpmActivateEnroll)
	http.HandleFunc(tpmCertifyEnrollEndpoint, server.handleTpmCertifyEnroll)
	http.HandleFunc(ccEnrollEndpoint, server.handleCcEnroll)
	http.HandleFunc(snpVcekEndpoint, server.handleSnpVcek)
	http.HandleFunc(snpCaCertsEndpoint, server.handleSnpCa)

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

func (s *Server) handleCacerts(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received /cacerts %v request from %v", req.Method, req.RemoteAddr)

	if strings.Compare(req.Method, "GET") != 0 {
		writeHttpErrorf(w, "Method %v not implemented for cacerts request", req.Method)
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
		writeHttpErrorf(w, "Method %v not implemented for simpleenroll request", req.Method)
		return
	}

	if s.authMethods.Has(provision.AuthToken) {
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
		writeHttpErrorf(w, "Method %v not implemented for tpmactivateenroll request", req.Method)
		return
	}

	if s.authMethods.Has(provision.AuthToken) {
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
		TPMVersion: 2,
		EK:         ekPub,
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
		writeHttpErrorf(w, "Method %v not implemented for tpmcertifyenroll request", req.Method)
		return
	}

	if s.authMethods.Has(provision.AuthToken) {
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
	var metadata []byte

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
			{ContentType: est.MimeTypeOctetStream, Data: &metadata},
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
	}

	// Verify that certified IK is actually the CSR public key
	err = provision.VerifyTpmCsr(ikPublic, csr)
	if err != nil {
		writeHttpErrorf(w, "failed to verify IK: %v", err)
		return
	}

	// Verify attestation report if authentication method attestation is activated
	if s.authMethods.Has(provision.AuthAttestation) {
		log.Tracef("Verifying attestation report against %v metadata CAs", len(s.metadataCas))
		err = verifyAttestationReport(csr, s.metadataCas, report, metadata, s.publishAddr, s.publishFile)
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

func (s *Server) handleCcEnroll(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received /ccenroll request from %v", req.RemoteAddr)

	if strings.Compare(req.Method, "POST") != 0 {
		writeHttpErrorf(w, "Method %v not implemented for tpmcertifyenroll request", req.Method)
		return
	}

	if s.authMethods.Has(provision.AuthToken) {
		if err := verifyBootStrapToken(s.tokenPath, req); err != nil {
			writeHttpErrorf(w, "%v (Failed to verify bootstrap token: %v)", http.StatusUnauthorized, err)
			return
		}
	}

	var csr *x509.CertificateRequest
	var report []byte
	var metadata []byte

	_, err := est.DecodeMultipart(
		req.Body,
		[]est.MimeMultipart{
			{ContentType: est.MimeTypePKCS10, Data: &csr},
			{ContentType: est.MimeTypeOctetStream, Data: &report},
			{ContentType: est.MimeTypeOctetStream, Data: &metadata},
		},
		req.Header.Get(est.ContentTypeHeader),
	)
	if err != nil {
		writeHttpErrorf(w, "Failed to decode multipart: %v", err)
		return
	}

	// Verify attestation report if authentication method attestation is activated
	if s.authMethods.Has(provision.AuthAttestation) {
		err = verifyAttestationReport(csr, s.metadataCas, report, metadata, s.publishAddr, s.publishFile)
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

func (s *Server) handleSnpVcek(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received /snpvcek request from %v", req.RemoteAddr)

	if strings.Compare(req.Method, "POST") != 0 {
		writeHttpErrorf(w, "Method %v not implemented for snpenroll request", req.Method)
		return
	}

	if s.authMethods.Has(provision.AuthToken) {
		if err := verifyBootStrapToken(s.tokenPath, req); err != nil {
			writeHttpErrorf(w, "%v (Failed to verify bootstrap token: %v)", http.StatusUnauthorized, err)
			return
		}
	}

	var chipId []byte
	var tcb uint64

	_, err := est.DecodeMultipart(
		req.Body,
		[]est.MimeMultipart{
			{ContentType: est.MimeTypeOctetStream, Data: &chipId},
			{ContentType: est.MimeTypeOctetStream, Data: &tcb},
		},
		req.Header.Get(est.ContentTypeHeader),
	)
	if err != nil {
		writeHttpErrorf(w, "Failed to decode multipart: %v", err)
		return
	}

	vcek, err := s.snpConf.GetVcek(chipId, tcb)
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

	if s.authMethods.Has(provision.AuthToken) {
		if err := verifyBootStrapToken(s.tokenPath, req); err != nil {
			writeHttpErrorf(w, "%v (Failed to verify bootstrap token: %v)", http.StatusUnauthorized, err)
			return
		}
	}

	var akTypeRaw []byte

	_, err := est.DecodeMultipart(
		req.Body,
		[]est.MimeMultipart{
			{ContentType: est.MimeTypeOctetStream, Data: &akTypeRaw},
		},
		req.Header.Get(est.ContentTypeHeader),
	)
	if err != nil {
		writeHttpErrorf(w, "Failed to decode multipart: %v", err)
		return
	}

	akType := internal.AkType(akTypeRaw[0])

	ca, err := s.snpConf.GetSnpCa(akType)
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

// enrollCert generates a new certificate signed by the CA
func enrollCert(csr *x509.CertificateRequest, key *ecdsa.PrivateKey, parent *x509.Certificate,
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

func verifyAttestationReport(csr *x509.CertificateRequest, cas []*x509.Certificate,
	report, metadataFlattened []byte, publishAddr, publishFile string,
) error {

	if len(report) == 0 {
		return fmt.Errorf("failed to verify attestation report: no report was provided")
	}

	metadata, err := internal.UnflattenArray(metadataFlattened)
	if err != nil {
		return fmt.Errorf("failed to decode metadata: %w", err)
	}

	// Use Subject Key Identifier (SKI) as nonce
	pubKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse CSR public key: %w", err)
	}
	nonce := sha1.Sum(pubKey)

	log.Debugf("Verifying attestation report with SKI as nonce: %v",
		hex.EncodeToString(nonce[:]))

	// Call verify with pubkey instead of identity CAs for verification in provisioning mode, which
	// only checks the signature, but not the certificate chains (which are about to
	// be created)
	result := verifier.Verify(report, nonce[:], csr.PublicKey,
		nil, verifier.PolicyEngineSelect_None, false,
		cas, internal.ConvertToMap(metadata))
	switch result.Summary.Status {
	case ar.StatusFail:
		result.PrintErr()
		return fmt.Errorf("failed to verify attestation report")
	case ar.StatusWarn:
		result.PrintErr()
		log.Debugf("Attestation report verification passed with warnings")
	default:
		log.Debugf("Successfully verified attestation report")
	}

	go pub.PublishResult(publishAddr, publishFile, result)

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
