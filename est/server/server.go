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

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	est "github.com/Fraunhofer-AISEC/cmc/est/common"
	"github.com/google/go-attestation/attest"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/pkcs7"

	_ "github.com/mattn/go-sqlite3"
)

type Server struct {
	server       *http.Server
	signingKey   *ecdsa.PrivateKey
	signingCerts []*x509.Certificate
	serializer   ar.Serializer
	tpmConf      tpmConfig
	snpConf      snpConfig
}

func NewServer(c *config, configPath string) (*Server, error) {

	signingPriv, err := loadPrivateKey(getFilePath(c.SigningKey, filepath.Dir(configPath)))
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	signingCerts, err := loadCertChain(c.SigningCerts, configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate chain: %w", err)
	}

	estPriv, err := loadPrivateKey(getFilePath(c.EstKey, filepath.Dir(configPath)))
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	estCerts, err := loadCertChain(c.EstCerts, configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate chain: %w", err)
	}

	serializer, err := getSerializer(c.Serialization)
	if err != nil {
		return nil, fmt.Errorf("failed to get serializer: %w", err)
	}

	var tlsCerts [][]byte
	for _, c := range estCerts {
		tlsCerts = append(tlsCerts, c.Raw)
	}

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(signingCerts[len(signingCerts)-1])

	tlsCfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		ClientAuth:       tls.VerifyClientCertIfGiven,
		Certificates: []tls.Certificate{
			{
				Certificate: tlsCerts,
				PrivateKey:  estPriv,
				Leaf:        estCerts[0],
			},
		},
		ClientCAs: clientCAs,
	}

	addr := fmt.Sprintf(":%v", c.Port)

	s := &http.Server{
		Addr:      addr,
		Handler:   nil,
		TLSConfig: tlsCfg,
	}

	server := &Server{
		server:       s,
		signingKey:   signingPriv,
		signingCerts: signingCerts,
		serializer:   serializer,
		tpmConf: tpmConfig{
			verifyEkCert: c.VerifyEkCert,
			dbPath:       getFilePath(c.TpmEkCertDb, filepath.Dir(configPath)),
		},
		snpConf: snpConfig{
			vcekOfflineCaching: c.VcekOfflineCaching,
			vcekCacheFolder:    getFilePath(c.VcekCacheFolder, filepath.Dir(configPath)),
			vceks:              make(map[vcekInfo][]byte),
		},
	}

	cacertsEndpoint := est.EndpointPrefix + est.CacertsEndpoint
	simpleenrollEndpoint := est.EndpointPrefix + est.EnrollEndpoint
	tpmActivateEnrollEndpoint := est.EndpointPrefix + est.TpmActivateEnrollEndpoint
	tpmCertifyEnrollEndpoint := est.EndpointPrefix + est.TpmCertifyEnrollEndpoint
	snpEnrollEndpoint := est.EndpointPrefix + est.SnpEnrollEndpoint

	http.HandleFunc(cacertsEndpoint, server.handleCacerts)
	http.HandleFunc(simpleenrollEndpoint, server.handleSimpleenroll)
	http.HandleFunc(tpmActivateEnrollEndpoint, server.handleTpmActivateEnroll)
	http.HandleFunc(tpmCertifyEnrollEndpoint, server.handleTpmCertifyEnroll)
	http.HandleFunc(snpEnrollEndpoint, server.handleSnpEnroll)

	err = httpHandleMetadata(c.HttpFolder, configPath)
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

	log.Tracef("Received 'cacerts' %v request from %v", req.Method, req.RemoteAddr)

	if strings.Compare(req.Method, "GET") != 0 {
		writeHttpErrorf(w, "Method %v not implemented for cacerts request", req.Method)
		return
	}

	body, err := est.EncodePkcs7CertsOnly(s.signingCerts)
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

	log.Tracef("Received 'simpleenroll' request from %v", req.RemoteAddr)

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

	cert, err := enrollCert(csr, s.signingKey, s.signingCerts[0])
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

	log.Tracef("Received 'tpmactivateenroll' request from %v", req.RemoteAddr)

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
		writeHttpErrorf(w, "failed to generate AK credentials: '%v'", err)
		return
	}

	// Verify that activated AK is actually the certificate's public key
	err = verifyTpmCsr(akPublic, csr)
	if err != nil {
		writeHttpErrorf(w, "failed to verify AK: %v", err)
		return
	}

	cert, err := enrollCert(csr, s.signingKey, s.signingCerts[0])
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

	log.Tracef("Received 'tpmcertifyenroll' request from %v", req.RemoteAddr)

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

	// Verify that certified IK is actually the CSR's public key
	err = verifyTpmCsr(ikPublic, csr)
	if err != nil {
		writeHttpErrorf(w, "failed to verify IK: %v", err)
		return
	}

	cert, err := enrollCert(csr, s.signingKey, s.signingCerts[0])
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

func (s *Server) handleSnpEnroll(w http.ResponseWriter, req *http.Request) {

	log.Tracef("Received 'snpenroll' request from %v", req.RemoteAddr)

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

func httpHandleMetadata(httpFolder, configPath string) error {
	// Retrieve the directories to be provided from config and create http
	// directory structure
	log.Info("Serving Directories: ")

	folder := getFilePath(httpFolder, filepath.Dir(configPath))

	dirs, err := os.ReadDir(folder)
	if err != nil {
		return fmt.Errorf("failed to open metaddata folders '%v': %v", folder, err)
	}

	for _, dir := range dirs {
		d := dir.Name()
		log.Info("\t", d)
		path := path.Join(folder, d)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			abs, _ := filepath.Abs(path)
			return fmt.Errorf("path %v does not exist", abs)
		}
		fs := http.FileServer(http.Dir(path))
		http.Handle("/"+d+"/", http.StripPrefix("/"+d, fs))
	}
	return nil
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
