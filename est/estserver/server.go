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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	est "github.com/Fraunhofer-AISEC/cmc/est/common"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/google/go-attestation/attest"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/pkcs7"

	_ "github.com/mattn/go-sqlite3"
)

type Server struct {
	server      *http.Server
	estCaKey    *ecdsa.PrivateKey
	estCaChain  []*x509.Certificate
	metadataCas []*x509.Certificate
	tpmConf     tpmConfig
	snpConf     snpConfig
}

func NewServer(c *config) (*Server, error) {

	var tlsCaChain [][]byte
	for _, c := range c.tlsCaChain {
		tlsCaChain = append(tlsCaChain, c.Raw)
	}

	tlsCfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		// The client does not need to authenticate itself during the TLS handshake, as client
		// trust anchor authentication (e.g., TPM credential activation) is performed during
		// certificate enrollment.
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  nil,
		Certificates: []tls.Certificate{
			{
				Certificate: tlsCaChain,
				PrivateKey:  c.tlsKey,
				Leaf:        c.tlsCaChain[0],
			},
		},
	}

	addr := fmt.Sprintf(":%v", c.Port)

	s := &http.Server{
		Addr:      addr,
		Handler:   nil,
		TLSConfig: tlsCfg,
	}

	server := &Server{
		server:      s,
		estCaKey:    c.estCaKey,
		estCaChain:  c.estCaChain,
		metadataCas: c.metadataCas,
		tpmConf: tpmConfig{
			verifyEkCert: c.VerifyEkCert,
			dbPath:       c.TpmEkCertDb,
		},
		snpConf: snpConfig{
			vcekCacheFolder: c.VcekCacheFolder,
			vceks:           make(map[vcekInfo][]byte),
		},
	}

	cacertsEndpoint := est.EndpointPrefix + est.CacertsEndpoint
	simpleenrollEndpoint := est.EndpointPrefix + est.EnrollEndpoint
	tpmActivateEnrollEndpoint := est.EndpointPrefix + est.TpmActivateEnrollEndpoint
	tpmCertifyEnrollEndpoint := est.EndpointPrefix + est.TpmCertifyEnrollEndpoint
	attestEnrollEndpoint := est.EndpointPrefix + est.AttestEnrollEndpoint
	snpVcekEndpoint := est.EndpointPrefix + est.SnpVcekEndpoint
	snpCaCertsEndpoint := est.EndpointPrefix + est.SnpCaCertsEndpoint

	http.HandleFunc(cacertsEndpoint, server.handleCacerts)
	http.HandleFunc(simpleenrollEndpoint, server.handleSimpleenroll)
	http.HandleFunc(tpmActivateEnrollEndpoint, server.handleTpmActivateEnroll)
	http.HandleFunc(tpmCertifyEnrollEndpoint, server.handleTpmCertifyEnroll)
	http.HandleFunc(attestEnrollEndpoint, server.handleAttestEnroll)
	http.HandleFunc(snpVcekEndpoint, server.handleSnpVcek)
	http.HandleFunc(snpCaCertsEndpoint, server.handleSnpCa)

	err := httpHandleMetadata(c.HttpFolder)
	if err != nil {
		return nil, fmt.Errorf("failed to serve metadata: %w", err)
	}

	return server, nil
}

func (s *Server) Serve() {
	err := s.server.ListenAndServeTLS("", "")
	if err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			log.Infof("Server closed")
		} else {
			log.Errorf("Server failed: %v", err)
		}
	}
}

func (s *Server) handleCacerts(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received /cacerts %v request from %v", req.Method, req.RemoteAddr)

	if strings.Compare(req.Method, "GET") != 0 {
		writeHttpErrorf(w, "Method %v not implemented for cacerts request", req.Method)
		return
	}

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

	var tpmInfo string
	var ekCertUrl string
	var csr *x509.CertificateRequest
	var ekCertDer []byte
	var ekPubPkix []byte
	// TODO is there a TPM structure that summarizes this data?
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

	err = verifyEk(ekPubPkix, ekCertDer, tpmInfo, ekCertUrl, &s.tpmConf)
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
	err = verifyTpmCsr(akPublic, csr)
	if err != nil {
		writeHttpErrorf(w, "failed to verify AK: %v", err)
		return
	}

	cert, err := enrollCert(csr, s.estCaKey, s.estCaChain[0])
	if err != nil {
		writeHttpErrorf(w, "Failed to enroll certificate: %v", err)
		return
	}

	// TODO Discuss if this is secure
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

	var csr *x509.CertificateRequest
	// TODO is there a TPM structure that summarizes this data?
	var ikPublic []byte
	var ikCreateData []byte
	var ikCreateAttestation []byte
	var ikCreateSignature []byte
	var akPublic []byte

	_, err := est.DecodeMultipart(
		req.Body,
		[]est.MimeMultipart{
			{ContentType: est.MimeTypePKCS10, Data: &csr},
			{ContentType: est.MimeTypeOctetStream, Data: &ikPublic},
			{ContentType: est.MimeTypeOctetStream, Data: &ikCreateData},
			{ContentType: est.MimeTypeOctetStream, Data: &ikCreateAttestation},
			{ContentType: est.MimeTypeOctetStream, Data: &ikCreateSignature},
			{ContentType: est.MimeTypeOctetStream, Data: &akPublic},
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
	err = verifyIk(ikParams, akPublic)
	if err != nil {
		writeHttpErrorf(w, "failed to verify IK: %v", err)
	}

	// Verify that certified IK is actually the CSR public key
	err = verifyTpmCsr(ikPublic, csr)
	if err != nil {
		writeHttpErrorf(w, "failed to verify IK: %v", err)
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

func (s *Server) handleAttestEnroll(w http.ResponseWriter, req *http.Request) {

	log.Debugf("Received /attestenroll request from %v", req.RemoteAddr)

	if strings.Compare(req.Method, "POST") != 0 {
		writeHttpErrorf(w, "Method %v not implemented for tpmcertifyenroll request", req.Method)
		return
	}

	var csr *x509.CertificateRequest
	var report []byte
	var metadataFlattened []byte

	_, err := est.DecodeMultipart(
		req.Body,
		[]est.MimeMultipart{
			{ContentType: est.MimeTypePKCS10, Data: &csr},
			{ContentType: est.MimeTypeOctetStream, Data: &report},
			{ContentType: est.MimeTypeOctetStream, Data: &metadataFlattened},
		},
		req.Header.Get(est.ContentTypeHeader),
	)
	if err != nil {
		writeHttpErrorf(w, "Failed to decode multipart: %v", err)
		return
	}

	metadata, err := internal.UnflattenArray(metadataFlattened)
	if err != nil {
		writeHttpErrorf(w, "Failed to decode metadata: %v", err)
	}

	// Use Subject Key Identifier (SKI) as nonce
	pubKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		writeHttpErrorf(w, "failed to parse CSR public key: %v", err)
		return
	}
	nonce := sha1.Sum(pubKey)

	log.Debugf("Verifying attestation report with SKI as nonce: %v",
		hex.EncodeToString(nonce[:]))

	// Call verify with pubkey instead of identity CAs for verification in provisioning mode, which
	// only checks the signature, but not the certificate chains (which are about to
	// be created)
	result := verifier.Verify(report, nonce[:], nil, csr.PublicKey, s.metadataCas, nil,
		verifier.PolicyEngineSelect_None, internal.ConvertToMap(metadata))
	if !result.Success {
		result.PrintErr()
		writeHttpErrorf(w, "failed to verify attestation report")
		return
	}

	log.Debugf("Successfully verified attestation report")

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

	vcek, err := s.getVcek(chipId, tcb)
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

	akType := verifier.AkType(akTypeRaw[0])

	ca, err := s.getSnpCa(akType)
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

func httpHandleMetadata(folder string) error {
	// Retrieve the directories to be provided from config and create http
	// directory structure
	log.Debugf("Serving Directory: %v", folder)

	// Create directory, if it does not yet exist (might be populated later)
	if _, err := os.Stat(folder); err != nil {
		if err := os.MkdirAll(folder, 0755); err != nil {
			return fmt.Errorf("failed to create directory %q: %w", folder, err)
		}
	}

	dirs, err := os.ReadDir(folder)
	if err != nil {
		return fmt.Errorf("failed to open metaddata folders %q: %v", folder, err)
	}

	log.Tracef("Sub-paths:")
	for _, dir := range dirs {
		d := dir.Name()
		log.Tracef("\t%v", d)
		path := path.Join(folder, d)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			abs, _ := filepath.Abs(path)
			return fmt.Errorf("path %v does not exist", abs)
		}
		fs := http.FileServer(http.Dir(path))
		http.Handle("/"+d+"/", logRequest(http.StripPrefix("/"+d, fs)))
	}
	return nil
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

	// Check that CSR is self-signed
	err := csr.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("failed to verify CSR signature: %v", err)
	}

	// Parse public key and generate Subject Key Identifier (SKI)
	pubKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR public key: %w", err)
	}
	ski := sha1.Sum(pubKey)

	// Create random 128-bit serial number
	serial, err := rand.Int(rand.Reader, big.NewInt(1).Exp(big.NewInt(2), big.NewInt(128), nil))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number for certificate: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		RawSubject:            csr.RawSubject,
		SubjectKeyId:          ski[:],
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
	}

	certDer, err := x509.CreateCertificate(rand.Reader, &tmpl, parent, csr.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create IK certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	return cert, nil
}

func verifyTpmCsr(tpmPub []byte, csr *x509.CertificateRequest) error {
	pub, err := attest.ParseAKPublic(attest.TPMVersion20, tpmPub)
	if err != nil {
		return fmt.Errorf("parse TPM key failed: %w", err)
	}
	akPkix, err := x509.MarshalPKIXPublicKey(pub.Public)
	if err != nil {
		return fmt.Errorf("activate credential failed: %w", err)
	}
	csrPkix, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return fmt.Errorf("activate credential failed: %w", err)
	}
	if !bytes.Equal(akPkix, csrPkix) {
		return fmt.Errorf("provided TPM key does not match TPM csr key")
	}
	return nil
}

func writeHttpErrorf(w http.ResponseWriter, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Warn(msg)
	http.Error(w, msg, http.StatusBadRequest)
}
