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
	"crypto/rsa"
	"crypto/sha1"

	cryptoX509 "crypto/x509"
	"database/sql"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/snpdriver"
	"github.com/Fraunhofer-AISEC/cmc/swdriver"
	"github.com/Fraunhofer-AISEC/cmc/tpmdriver"

	"github.com/Fraunhofer-AISEC/go-attestation/attest"

	"github.com/google/certificate-transparency-go/asn1"
	x509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/google/go-tpm/tpm2"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
)

type config struct {
	Port               int    `json:"port"`
	DeviceSubCaKeyFile string `json:"deviceSubCaKey"`
	DeviceSubCaFile    string `json:"deviceSubCaCert"`
	CaFile             string `json:"caCert"`
	HTTPFolder         string `json:"httpFolder"`
	VerifyEkCert       bool   `json:"verifyEkCert"`
	TpmEkCertDb        string `json:"tpmEkCertDb"`
}

type datastore struct {
	Secret             map[[32]byte][]byte
	AkParams           map[[32]byte]attest.AttestationParameters
	TLSKeyParams       map[[32]byte]attest.CertificationParameters
	DeviceSubCaPriv    *ecdsa.PrivateKey
	DeviceSubCaCert    *x509.Certificate
	DeviceSubCaCertPem []byte
	CaCertPem          []byte
	VerifyEkCert       bool
	DbPath             string
}

const (
	manufacturerIntel     = "Intel"
	intelEKCertServiceURL = "https://ekop.intel.com/ekcertservice/"
	snpVcekUrlPrefix      = "https://kdsintf.amd.com/vcek/v1/Milan/"
	snpMilanUrl           = "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain"
	snpMaxRetries         = 3
)

var dataStore datastore

func printConfig(c *config, configFile string) {
	log.Infof("Using the configuration loaded from %v:", configFile)
	log.Info("\tPort                   : ", c.Port)
	log.Info("\tDevice Sub CA Key File : ", getFilePath(c.DeviceSubCaKeyFile, filepath.Dir(configFile)))
	log.Info("\tDevice Sub CA Cert File: ", getFilePath(c.DeviceSubCaFile, filepath.Dir(configFile)))
	log.Info("\tCA Cert File           : ", getFilePath(c.CaFile, filepath.Dir(configFile)))
	log.Info("\tFolders to be served   : ", getFilePath(c.HTTPFolder, filepath.Dir(configFile)))
	log.Info("\tVerify EK Cert         : ", c.VerifyEkCert)
	log.Info("\tTPM EK DB              : ", getFilePath(c.TpmEkCertDb, filepath.Dir(configFile)))
}

func readConfig(configFile string) (*config, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Error("Failed to read config file '", configFile, "'")
		return nil, err
	}
	config := new(config)
	err = json.Unmarshal(data, config)
	if err != nil {
		log.Error("Failed to parse config")
		return nil, err
	}
	return config, nil
}

func loadCaPriv(caPrivFile string) (*ecdsa.PrivateKey, error) {

	// Read private pem-encoded key and convert it to a private key
	privBytes, err := ioutil.ReadFile(caPrivFile)
	if err != nil {
		return nil, fmt.Errorf("error loading CA - Read private key returned '%w'", err)
	}

	privPem, _ := pem.Decode(privBytes)

	priv, err := x509.ParseECPrivateKey(privPem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error loading CA - ParsePKCS1PrivateKey returned '%w'", err)
	}

	return priv, nil
}

func loadCert(certFile string) (*x509.Certificate, []byte, error) {

	caCertPem, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("error loading certificate: Read file %v returned %w", certFile, err)
	}

	block, _ := pem.Decode(caCertPem)

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error loading certificate - Parse Certificate returned %w", err)
	}

	return caCert, caCertPem, nil
}

func parseCertParams(certParams []byte) (*ar.CertParams, error) {

	roots := cryptoX509.NewCertPool()
	ok := roots.AppendCertsFromPEM(dataStore.CaCertPem)
	if !ok {
		return nil, errors.New("failed to create cert pool")
	}
	opts := cryptoX509.VerifyOptions{
		KeyUsages: []cryptoX509.ExtKeyUsage{cryptoX509.ExtKeyUsageAny},
		Roots:     roots,
	}

	jwsData, err := jose.ParseSigned(string(certParams))
	if err != nil {
		return nil, fmt.Errorf("verifyJws: Data could not be parsed - %w", err)
	}

	certs, err := jwsData.Signatures[0].Protected.Certificates(opts)
	if err != nil {
		return nil, fmt.Errorf("certificate chain for Cert Params: %w", err)
	}

	payload, err := jwsData.Verify(certs[0][0].PublicKey)
	if err != nil {
		return nil, fmt.Errorf("signature of Cert Params: %w", err)
	}

	// Unmarshal the certificate parameters
	cp := new(ar.CertParams)
	if err := json.Unmarshal(payload, cp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cert params: %w", err)
	}

	return cp, nil
}

func getIntelEkCert(certificateURL string) (*x509.Certificate, error) {
	return nil, fmt.Errorf("retrieval of Intel EK Certificates not implemented yet")
}

// HandleAcRequest handles an Activate Credential Request (Step 1)
func HandleAcRequest(buf *bytes.Buffer) (*bytes.Buffer, error) {

	var acRequest tpmdriver.AcRequest
	// Registers specific type for value transferred as interface
	gob.Register(rsa.PublicKey{})
	d := gob.NewDecoder(buf)
	d.Decode(&acRequest)

	if acRequest.Ek.Public == nil {
		return nil, fmt.Errorf("ek public key from device not present")
	}

	var ekCert *x509.Certificate
	var err error
	if acRequest.Ek.Certificate == nil {
		if acRequest.Ek.CertificateURL == "" {
			return nil, fmt.Errorf("neither EK Certificate nor Certificate URL present")
		}
		// Intel TPMs do not provide their EK certificate but instead a certificate URL from where the certificate can be retrieved via its public key
		if acRequest.TpmInfo.Manufacturer.String() != manufacturerIntel {
			return nil, fmt.Errorf("ek certificate not present and Certificate URL not supported for manufacturer %v", acRequest.TpmInfo.Manufacturer)
		}
		ekCert, err = getIntelEkCert(acRequest.Ek.CertificateURL)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve Intel TPM EK certificate from Intel server: %w", err)
		}
	} else {
		ekCert = acRequest.Ek.Certificate
	}

	if dataStore.VerifyEkCert {
		err := verifyEkCert(dataStore.DbPath, ekCert, &acRequest.TpmInfo)
		if err != nil {
			return nil, fmt.Errorf("verify EK certificate chain: error = %w", err)
		}
		log.Debug("verification of EK certificate chain successful")
	} else {
		log.Warn("skipping EK certificate chain validation (turned off via config)")
	}

	var ekPub rsa.PublicKey
	ekPub, ok := acRequest.Ek.Public.(rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("rsa public key required for credential activation")
	}

	params := attest.ActivationParameters{
		TPMVersion: 2,
		EK:         &ekPub,
		AK:         acRequest.AkParams,
	}

	secret, encryptedCredentials, err := params.Generate()
	if err != nil {
		return nil, fmt.Errorf("error Generating Credentials - '%w'", err)
	}

	// Return encrypted credentials to client
	acResponse := tpmdriver.AcResponse{
		Ec: *encryptedCredentials,
	}

	var retBuf bytes.Buffer
	e := gob.NewEncoder(&retBuf)
	err = e.Encode(acResponse)
	if err != nil {
		return nil, fmt.Errorf("error Activating Credential - '%w'", err)
	}

	dataStore.Secret[acRequest.AkQualifiedName] = secret
	dataStore.AkParams[acRequest.AkQualifiedName] = acRequest.AkParams
	dataStore.TLSKeyParams[acRequest.AkQualifiedName] = acRequest.TLSKeyParams

	return &retBuf, nil
}

// HandleAkCertRequest handles an AK Cert Request (Step 2)
func HandleAkCertRequest(buf *bytes.Buffer) (*bytes.Buffer, error) {

	var akCertRequest tpmdriver.AkCertRequest
	decoder := gob.NewDecoder(buf)
	decoder.Decode(&akCertRequest)

	// Compare the client returned decrypted secret with the
	// server generated secret
	if bytes.Equal(akCertRequest.Secret, dataStore.Secret[akCertRequest.AkQualifiedName]) {
		log.Debug("Activate Credential Successful - Secrets match")
	} else {
		return nil, errors.New("activate credential failed - cecrets do no match")
	}

	// Parse certificate parameters
	akCertParams := ar.CertParams{}
	tlsCertParams := ar.CertParams{}
	for _, c := range akCertRequest.CertParams {
		cp, err := parseCertParams(c)
		if err != nil {
			return nil, fmt.Errorf("activate credential Failed - Failed to parse certificate parameters: %w", err)
		}
		if cp.Type == "AK Cert Params" {
			log.Debug("Added AK Certificate Parameters")
			akCertParams = *cp
		} else if cp.Type == "TLS Key Cert Params" {
			log.Debug("Added TLS Key Certificate Parameters")
			tlsCertParams = *cp
		} else {
			return nil, fmt.Errorf("unknown cert params type: %v", cp.Type)
		}
	}

	// Generate AK certificate
	akPub, err := attest.ParseAKPublic(attest.TPMVersion20, dataStore.AkParams[akCertRequest.AkQualifiedName].Public)
	if err != nil {
		return nil, fmt.Errorf("activate credential failed - ParseAKPublic returned %w", err)
	}

	encodedpub, err := x509.MarshalPKIXPublicKey(akPub.Public)
	if err != nil {
		return nil, fmt.Errorf("activate credential failed - marshal public key returned %w", err)
	}
	ski := sha1.Sum(encodedpub)

	// Create AK Certificate
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         akCertParams.Subject.CommonName,
			Country:            []string{akCertParams.Subject.Country},
			Province:           []string{akCertParams.Subject.Province},
			Locality:           []string{akCertParams.Subject.Locality},
			Organization:       []string{akCertParams.Subject.Organization},
			OrganizationalUnit: []string{akCertParams.Subject.OrganizationalUnit},
			StreetAddress:      []string{akCertParams.Subject.StreetAddress},
			PostalCode:         []string{akCertParams.Subject.PostalCode},
		},
		SubjectKeyId:          ski[:],
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, dataStore.DeviceSubCaCert, akPub.Public, dataStore.DeviceSubCaPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to create AK certificate: %w", err)
	}

	akPem := &bytes.Buffer{}
	pem.Encode(akPem, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	log.Trace("Generated new AK Certificate: ", akPem.String())

	// Verify that TLS Key is a TPM key signed by the AK
	pub, err := tpm2.DecodePublic(dataStore.AkParams[akCertRequest.AkQualifiedName].Public)
	if err != nil {
		return nil, fmt.Errorf("decode public failed: %w", err)
	}
	akPubVerify := &rsa.PublicKey{E: int(pub.RSAParameters.Exponent()), N: pub.RSAParameters.Modulus()}
	hash, err := pub.RSAParameters.Sign.Hash.Hash()
	if err != nil {
		return nil, fmt.Errorf("cannot access AK's hash function: %w", err)
	}
	opts := attest.VerifyOpts{
		Public: akPubVerify,
		Hash:   hash,
	}
	p := dataStore.TLSKeyParams[akCertRequest.AkQualifiedName]
	err = p.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to verify TLS Key with AK: %w", err)
	}
	log.Debug("Successfully verified TLS key with AK")

	tlsPub, err := attest.ParseAKPublic(attest.TPMVersion20, dataStore.TLSKeyParams[akCertRequest.AkQualifiedName].Public)
	if err != nil {
		return nil, fmt.Errorf("activate credential Failed - parse TLS key returned %w", err)
	}

	encodedpub, err = x509.MarshalPKIXPublicKey(tlsPub.Public)
	if err != nil {
		return nil, fmt.Errorf("activate credential failed - marshal public key returned %w", err)
	}
	ski = sha1.Sum(encodedpub)

	// Create TLS key certificate
	tmpl = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         tlsCertParams.Subject.CommonName,
			Country:            []string{tlsCertParams.Subject.Country},
			Province:           []string{tlsCertParams.Subject.Province},
			Locality:           []string{tlsCertParams.Subject.Locality},
			Organization:       []string{tlsCertParams.Subject.Organization},
			OrganizationalUnit: []string{tlsCertParams.Subject.OrganizationalUnit},
			StreetAddress:      []string{tlsCertParams.Subject.StreetAddress},
			PostalCode:         []string{tlsCertParams.Subject.PostalCode},
		},
		SubjectKeyId:          ski[:],
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              tlsCertParams.SANs,
	}

	der, err = x509.CreateCertificate(rand.Reader, &tmpl, dataStore.DeviceSubCaCert, tlsPub.Public, dataStore.DeviceSubCaPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	tlsKeyPem := &bytes.Buffer{}
	pem.Encode(tlsKeyPem, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	log.Trace("Generated new TLS Key Certificate: ", tlsKeyPem.String())

	akCertResponse := tpmdriver.AkCertResponse{
		AkQualifiedName: akCertRequest.AkQualifiedName,
		Certs: tpmdriver.Certs{
			Ak:          akPem.Bytes(),
			TLSCert:     tlsKeyPem.Bytes(),
			DeviceSubCa: dataStore.DeviceSubCaCertPem,
			Ca:          dataStore.CaCertPem,
		},
	}

	var retBuf bytes.Buffer
	e := gob.NewEncoder(&retBuf)
	err = e.Encode(akCertResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to encode: %w", err)
	}

	return &retBuf, nil
}

// HandleSwCertRequest handles a software CSR request
func HandleSwCertRequest(buf *bytes.Buffer) (*bytes.Buffer, error) {

	var req swdriver.SwCertRequest
	decoder := gob.NewDecoder(buf)
	decoder.Decode(&req)

	certParams, err := parseCertParams(req.CertParams)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate parameters: %w", err)
	}
	if certParams.Type != "TLS Key Cert Params" {
		return nil, fmt.Errorf("unknown cert params type: %v", certParams.Type)
	}

	pubKey, err := cryptoX509.ParsePKIXPublicKey(req.PubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ski := sha1.Sum(req.PubKey)

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         certParams.Subject.CommonName,
			Country:            []string{certParams.Subject.Country},
			Province:           []string{certParams.Subject.Province},
			Locality:           []string{certParams.Subject.Locality},
			Organization:       []string{certParams.Subject.Organization},
			OrganizationalUnit: []string{certParams.Subject.OrganizationalUnit},
			StreetAddress:      []string{certParams.Subject.StreetAddress},
			PostalCode:         []string{certParams.Subject.PostalCode},
		},
		SubjectKeyId:          ski[:],
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              certParams.SANs,
	}

	cert, err := x509.CreateCertificate(rand.Reader, &tmpl, dataStore.DeviceSubCaCert, pubKey, dataStore.DeviceSubCaPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	tmp := &bytes.Buffer{}
	pem.Encode(tmp, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	log.Trace("Generated new SW TLS Certificate: ", tmp.String())

	certResponse := swdriver.SwCertResponse{
		Certs: ar.CertChain{
			Leaf:          tmp.Bytes(),
			Intermediates: [][]byte{dataStore.DeviceSubCaCertPem},
			Ca:            dataStore.CaCertPem,
		},
	}

	var retBuf bytes.Buffer
	e := gob.NewEncoder(&retBuf)
	err = e.Encode(certResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cert - encode returned %w", err)
	}

	return &retBuf, nil
}

// HTTP handler for TPM Credential activation and Issuing of AK Certificates
func handleActivateCredential(writer http.ResponseWriter, req *http.Request) {

	log.Debug("Received ", req.Method)

	if strings.Compare(req.Method, "POST") == 0 {

		ctype := req.Header.Get("Content-Type")
		log.Debug("Content-Type: ", ctype)

		if strings.Compare(ctype, "tpm/attestparams") == 0 {
			log.Debug("Received tpm/attestParams")

			b, err := ioutil.ReadAll(req.Body)
			if err != nil {
				msg := fmt.Sprintf("Error Activating Credential - %v", err)
				log.Warn(msg)
				http.Error(writer, msg, http.StatusBadRequest)
				return
			}
			buf := bytes.NewBuffer(b)

			// Handle the Activate Credential Request: Create a secret and
			// encrypt it with the EK private key
			retBuf, err := HandleAcRequest(buf)
			if err != nil {
				msg := fmt.Sprintf("Error Activating Credential - %v", err)
				log.Warn(msg)
				http.Error(writer, msg, http.StatusBadRequest)
				return
			}

			// Send back response
			n, err := writer.Write(retBuf.Bytes())
			if err != nil {
				msg := fmt.Sprintf("Error Activating Credential - %v", err)
				log.Warn(msg)
				http.Error(writer, msg, http.StatusBadRequest)
				return
			}
			if n != len(retBuf.Bytes()) {
				msg := "Error Activating Credential - not all bytes sent"
				log.Warn(msg)
				http.Error(writer, msg, http.StatusBadRequest)
				return
			}

		} else if strings.Compare(ctype, "tpm/akcert") == 0 {

			// Retrieve secret from client
			b, err := ioutil.ReadAll(req.Body)
			if err != nil {
				msg := fmt.Sprintf("Error handling AK Cert Request: %v", err)
				log.Warn(msg)
				http.Error(writer, msg, http.StatusBadRequest)
				return
			}
			buf := bytes.NewBuffer(b)

			retBuf, err := HandleAkCertRequest(buf)
			if err != nil {
				msg := fmt.Sprintf("Error handling AK Cert Request: %v", err)
				log.Warn(msg)
				http.Error(writer, msg, http.StatusBadRequest)
				return
			}

			// Send back response
			n, err := writer.Write(retBuf.Bytes())
			if err != nil {
				msg := fmt.Sprintf("Error handling AK Cert Request: Write File returned %v", err)
				log.Warn(msg)
				http.Error(writer, msg, http.StatusBadRequest)
				return
			}
			if n != len(retBuf.Bytes()) {
				msg := fmt.Sprintf("Error handling AK Cert Request: File length mismatch - %v", err)
				log.Warn(msg)
				http.Error(writer, msg, http.StatusBadRequest)
				return
			}
		} else {
			msg := fmt.Sprintf("Unknown Content Type: %v", ctype)
			log.Warn(msg)
			http.Error(writer, msg, http.StatusBadRequest)
			return
		}
	} else {
		msg := fmt.Sprintf("Unsupported HTTP Method %v", req.Method)
		log.Warn(msg)
		http.Error(writer, msg, http.StatusBadRequest)
		return
	}
}

func handleSwSigning(writer http.ResponseWriter, req *http.Request) {

	log.Debug("Received ", req.Method)

	if strings.Compare(req.Method, "POST") == 0 {

		ctype := req.Header.Get("Content-Type")
		log.Debug("Content-Type: ", ctype)

		if strings.Compare(ctype, "signing/csr") == 0 {
			log.Debug("Received signing/csr")

			b, err := ioutil.ReadAll(req.Body)
			if err != nil {
				msg := fmt.Sprintf("Failed to handle sw-sign request: %v", err)
				log.Warn(msg)
				http.Error(writer, msg, http.StatusBadRequest)
				return
			}
			buf := bytes.NewBuffer(b)

			// Handle the certificate request
			retBuf, err := HandleSwCertRequest(buf)
			if err != nil {
				msg := fmt.Sprintf("Failed to handle sw-sign request: %v", err)
				log.Warn(msg)
				http.Error(writer, msg, http.StatusBadRequest)
				return
			}

			// Send back response
			n, err := writer.Write(retBuf.Bytes())
			if err != nil {
				msg := fmt.Sprintf("Failed to handle sw-sign request: %v", err)
				log.Warn(msg)
				http.Error(writer, msg, http.StatusBadRequest)
				return
			}
			if n != len(retBuf.Bytes()) {
				msg := "Failed to handle sw-sign request: not all bytes sent"
				log.Warn(msg)
				http.Error(writer, msg, http.StatusBadRequest)
				return
			}
		}
	} else {
		msg := fmt.Sprintf("Unsupported HTTP Method %v", req.Method)
		log.Warn(msg)
		http.Error(writer, msg, http.StatusBadRequest)
		return
	}
}

func verifyEkCert(dbpath string, ek *x509.Certificate, tpmInfo *attest.TPMInfo) error {
	// Load the TPM EK Certificate database for validating sent EK certificates
	db, err := sql.Open("sqlite3", dbpath)
	if err != nil {
		return err
	}
	defer db.Close()

	// Add TPM EK intermediate certs from database to certificate pool
	var intermediates []byte
	var intermediatesPool *x509.CertPool = nil
	err = db.QueryRow("SELECT Certs FROM trustanchors WHERE Manufacturer LIKE ? AND FwMajor=? AND CA=0", tpmInfo.Manufacturer.String(), tpmInfo.FirmwareVersionMajor).Scan(&intermediates)
	if err == sql.ErrNoRows {
		log.Debug("TPM EK cert chain does not contain intermediate certificates")
	} else if err != nil {
		return err
	} else {
		log.Trace("Found Intermediate Certs in DB: ", string(intermediates))

		intermediatesPool = x509.NewCertPool()
		ok := intermediatesPool.AppendCertsFromPEM(intermediates)
		if !ok {
			return errors.New("failed to append intermediate certificates from database")
		}
		log.Debugf("Added %v certificates to intermediates certificate pool", len(intermediatesPool.Subjects()))
	}

	// Add TPM EK CA cert from database to certificate pool
	var roots []byte
	err = db.QueryRow("SELECT Certs FROM trustanchors WHERE Manufacturer LIKE ? AND CA=1", tpmInfo.Manufacturer.String()).Scan(&roots)
	if err != nil {
		return fmt.Errorf("failed to retrieve CA certificate for TPM from %v (Major: %v, Minor: %v): %w", tpmInfo.Manufacturer.String(), tpmInfo.FirmwareVersionMajor, tpmInfo.FirmwareVersionMinor, err)
	}
	log.Trace("Found Root Certs in DB: ", string(roots))

	rootsPool := x509.NewCertPool()
	ok := rootsPool.AppendCertsFromPEM(roots)
	if !ok {
		return errors.New("failed to append root certificate from database")
	}
	log.Debugf("Added %v certificate to root certificate pool", len(rootsPool.Subjects()))

	// TODO the ST certificates contain the x509 v3 extension with OID 2.5.29.17
	// which is not handled by default. Check for other certs and decide how to handle
	u := ek.UnhandledCriticalExtensions
	if len(u) == 1 && len(u[0]) == 4 {
		if u[0][0] == 2 && u[0][1] == 5 && u[0][2] == 29 && u[0][3] == 17 {
			ek.UnhandledCriticalExtensions = make([]asn1.ObjectIdentifier, 0)
		}
	}

	chain, err := ek.Verify(x509.VerifyOptions{Roots: rootsPool, Intermediates: intermediatesPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return err
	}

	var expectedLen int
	if intermediatesPool == nil {
		expectedLen = len(rootsPool.Subjects()) + 1
	} else {
		expectedLen = len(intermediatesPool.Subjects()) + len(rootsPool.Subjects()) + 1
	}

	if len(chain[0]) != expectedLen {
		return fmt.Errorf("expected chain of length %v (got %v)", expectedLen, len(chain[0]))
	}

	log.Debugf("Successfully verified chain of %v elements", len(chain[0]))
	for i := range chain[0] {
		log.Tracef("\tCertificate CN='%v', Issuer CN='%v'", chain[0][i].Subject.CommonName, chain[0][i].Issuer.CommonName)
	}

	return nil
}

// Returns either the unmodified absolute path or the absolute path
// retrieved from a path relative to a base path
func getFilePath(p, base string) string {
	if path.IsAbs(p) {
		return p
	}
	ret, _ := filepath.Abs(filepath.Join(base, p))
	return ret
}

func handleVcekRetrieval(writer http.ResponseWriter, req *http.Request) {

	log.Debug("Received ", req.Method)

	if strings.Compare(req.Method, "POST") == 0 {

		ctype := req.Header.Get("Content-Type")
		log.Debug("Content-Type: ", ctype)

		if strings.Compare(ctype, "retrieval/vcek") == 0 {
			log.Debug("Received retrieval/vcek")

			b, err := ioutil.ReadAll(req.Body)
			if err != nil {
				msg := fmt.Sprintf("Failed to handle vcek request: %v", err)
				log.Warn(msg)
				http.Error(writer, msg, http.StatusBadRequest)
				return
			}
			buf := bytes.NewBuffer(b)

			// Handle the certificate request
			retBuf, err := handleVcekRequest(buf)
			if err != nil {
				msg := fmt.Sprintf("Failed to handle VCEK retrieval request: %v", err)
				log.Warn(msg)
				http.Error(writer, msg, http.StatusBadRequest)
				return
			}

			// Send back response
			n, err := writer.Write(retBuf.Bytes())
			if err != nil {
				msg := fmt.Sprintf("Failed to handle VCEK retrieval request: %v", err)
				log.Warn(msg)
				http.Error(writer, msg, http.StatusBadRequest)
				return
			}
			if n != len(retBuf.Bytes()) {
				msg := "Failed to handle VCEK retrieval request: not all bytes sent"
				log.Warn(msg)
				http.Error(writer, msg, http.StatusBadRequest)
				return
			}
		}
	} else {
		msg := fmt.Sprintf("Unsupported HTTP Method %v", req.Method)
		log.Warn(msg)
		http.Error(writer, msg, http.StatusBadRequest)
		return
	}
}

func handleVcekRequest(buf *bytes.Buffer) (*bytes.Buffer, error) {

	var req snpdriver.VcekRequest
	decoder := gob.NewDecoder(buf)
	decoder.Decode(&req)

	vcek, err := getVcek(req.ChipId, req.Tcb)
	if err != nil {
		return nil, fmt.Errorf("failed to get VCEK: %w", err)
	}

	resp := snpdriver.VcekResponse{
		Vcek: vcek,
	}

	var retBuf bytes.Buffer
	e := gob.NewEncoder(&retBuf)
	err = e.Encode(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cert - encode returned %w", err)
	}

	return &retBuf, nil
}

// Get Vcek takes the TCB and chip ID, calculates the VCEK URL and gets the certificate
// from the cache or downloads it from the AMD server if not present
func getVcek(chipId [64]byte, tcb uint64) ([]byte, error) {
	ChipId := hex.EncodeToString(chipId[:])
	tcbInfo := fmt.Sprintf("?blSPL=%v&teeSPL=%v&snpSPL=%v&ucodeSPL=%v",
		tcb&0xFF,
		(tcb>>8)&0xFF,
		(tcb>>48)&0xFF,
		(tcb>>56)&0xFF)

	url := snpVcekUrlPrefix + ChipId + tcbInfo
	log.Tracef("Requesting SNP VCEK certificate from %v", url)
	for i := 0; i < snpMaxRetries; i++ {
		vcek, statusCode, err := downloadCert(url)
		if err == nil {
			return encodeCertPem(vcek), nil
		}
		// If the status code is not 429 (too many requests), return
		if statusCode != 429 {
			return nil, fmt.Errorf("failed to get VCEK certificate: %w", err)
		}
		// The AMD KDS server accepts requests only every 10 seconds, try again
		log.Warnf("AMD server blocked VCEK request for ChipID %v TCB %x (HTTP 429 - Too many requests). Trying again in 11s",
			hex.EncodeToString(chipId[:]), tcb)
		time.Sleep(11 * time.Second)
	}

	return nil, fmt.Errorf("failed to get VCEK certificat after %v retries", snpMaxRetries)
}

func downloadCert(url string) (*x509.Certificate, int, error) {

	resp, err := http.Get(url)
	if err != nil {
		return nil, 0, fmt.Errorf("error HTTP GET: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, resp.StatusCode, fmt.Errorf("HTTP Response Status: %v (%v)", resp.StatusCode, resp.Status)
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read HTTP body: %w", err)
	}

	cert, err := x509.ParseCertificate(content)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to parse x509 Certificate: %w", err)
	}
	return cert, resp.StatusCode, nil
}

func encodeCertPem(cert *x509.Certificate) []byte {
	tmp := &bytes.Buffer{}
	pem.Encode(tmp, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return tmp.Bytes()
}

func main() {

	log.Info("CMC Provisioning Demo Server")

	log.SetLevel(log.TraceLevel)

	configFile := flag.String("config", "", "configuration file")
	flag.Parse()

	if *configFile == "" {
		log.Error("Config file not specified. Please specify a config file (--config <file>)")
		return
	}

	config, err := readConfig(*configFile)
	if err != nil {
		log.Error(err)
		return
	}
	printConfig(config, *configFile)

	dataStore.VerifyEkCert = config.VerifyEkCert

	if dataStore.VerifyEkCert {
		dataStore.DbPath = getFilePath(config.TpmEkCertDb, filepath.Dir(*configFile))
	} else {
		log.Warn("Verification of EK certificate chain turned off via Config. Use this for testing only")
	}

	// Load CA private key and certificate for signing the AKs
	priv, err := loadCaPriv(getFilePath(config.DeviceSubCaKeyFile, filepath.Dir(*configFile)))
	if err != nil {
		log.Error(err)
		return
	}
	dataStore.DeviceSubCaPriv = priv

	dscCert, dscPem, err := loadCert(getFilePath(config.DeviceSubCaFile, filepath.Dir(*configFile)))
	if err != nil {
		log.Error(err)
		return
	}
	dataStore.DeviceSubCaCert = dscCert
	dataStore.DeviceSubCaCertPem = dscPem

	_, caCertPem, err := loadCert(getFilePath(config.CaFile, filepath.Dir(*configFile)))
	if err != nil {
		log.Error(err)
		return
	}
	dataStore.CaCertPem = caCertPem

	dataStore.AkParams = make(map[[32]byte]attest.AttestationParameters)
	dataStore.Secret = make(map[[32]byte][]byte)
	dataStore.TLSKeyParams = make(map[[32]byte]attest.CertificationParameters)

	// Retrieve the directories to be provided from config and create http
	// directory structure
	log.Info("Serving Directories: ")

	httpFolder := getFilePath(config.HTTPFolder, filepath.Dir(*configFile))

	dirs, err := ioutil.ReadDir(httpFolder)
	if err != nil {
		log.Errorf("Failed to open metaddata folders '%v' - %v", httpFolder, err)
		return
	}

	for _, dir := range dirs {
		d := dir.Name()
		log.Info("\t", d)
		path := path.Join(httpFolder, d)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			abs, _ := filepath.Abs(path)
			log.Error("Path '", abs, "' does not exist. Abort..")
			return
		}
		fs := http.FileServer(http.Dir(path))
		http.Handle("/"+d+"/", http.StripPrefix("/"+d, fs))
	}

	// TPM Credential Activation and AK Cert Generation
	http.HandleFunc("/activate-credential/", handleActivateCredential)

	// Software Signing of CSRs
	http.HandleFunc("/sw-signing/", handleSwSigning)

	// VCEK retrieval
	http.HandleFunc("/vcek-retrieval/", handleVcekRetrieval)

	port := fmt.Sprintf(":%v", config.Port)
	err = http.ListenAndServe(port, nil)
	if err != nil {
		log.Error("HTTP Server failed: ", err)
	}
}
