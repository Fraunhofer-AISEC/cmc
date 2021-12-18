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

	ar "attestationreport"
	"tpmdriver"

	"github.com/Fraunhofer-AISEC/go-attestation/attest"

	"github.com/google/certificate-transparency-go/asn1"
	x509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/google/go-tpm/tpm2"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
)

type Config struct {
	Port               int    `json:"port"`
	DeviceSubCaKeyFile string `json:"deviceSubCaKey"`
	DeviceSubCaFile    string `json:"deviceSubCaCert"`
	CaFile             string `json:"caCert"`
	HttpFolder         string `json:"httpFolder"`
	VerifyEkCert       bool   `json:"verifyEkCert"`
	TpmEkCertDb        string `json:"tpmEkCertDb"`
}

type DataStore struct {
	Secret             map[[32]byte][]byte
	AkParams           map[[32]byte]attest.AttestationParameters
	TlsKeyParams       map[[32]byte]attest.CertificationParameters
	DeviceSubCaPriv    *ecdsa.PrivateKey
	DeviceSubCaCert    *x509.Certificate
	DeviceSubCaCertPem []byte
	CaCertPem          []byte
	VerifyEkCert       bool
	DbPath             string
}

var dataStore DataStore

func printConfig(c *Config, configFile string) {
	log.Infof("Using the configuration loaded from %v:", configFile)
	log.Info("\tPort                   : ", c.Port)
	log.Info("\tDevice Sub CA Key File : ", getFilePath(c.DeviceSubCaKeyFile, filepath.Dir(configFile)))
	log.Info("\tDevice Sub CA Cert File: ", getFilePath(c.DeviceSubCaFile, filepath.Dir(configFile)))
	log.Info("\tCA Cert File           : ", getFilePath(c.CaFile, filepath.Dir(configFile)))
	log.Info("\tFolders to be served   : ", getFilePath(c.HttpFolder, filepath.Dir(configFile)))
	log.Info("\tVerify EK Cert         : ", c.VerifyEkCert)
	log.Info("\tTPM EK DB              : ", getFilePath(c.TpmEkCertDb, filepath.Dir(configFile)))
}

func readConfig(configFile string) (*Config, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Error("Failed to read config file '", configFile, "'")
		return nil, err
	}
	config := new(Config)
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
		return nil, fmt.Errorf("Error loading CA - Read private key returned '%v'", err)
	}

	privPem, _ := pem.Decode(privBytes)

	priv, err := x509.ParseECPrivateKey(privPem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Error loading CA - ParsePKCS1PrivateKey returned '%v'", err)
	}

	return priv, nil
}

func loadCert(certFile string) (*x509.Certificate, []byte, error) {

	caCertPem, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("Error loading certificate: Read file %v returned %v", certFile, err)
	}

	block, _ := pem.Decode(caCertPem)

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Error loading certificate - Parse Certificate returned %v", err)
	}

	return caCert, caCertPem, nil
}

func parseCertParams(certParams [][]byte) (akCertParams, tlsCertParams *ar.CertParams, err error) {

	akCertParams = nil
	tlsCertParams = nil

	roots := cryptoX509.NewCertPool()
	ok := roots.AppendCertsFromPEM(dataStore.CaCertPem)
	akCertParams = nil
	tlsCertParams = nil
	if !ok {
		return nil, nil, errors.New("Failed to create cert pool")
	}
	opts := cryptoX509.VerifyOptions{
		KeyUsages: []cryptoX509.ExtKeyUsage{cryptoX509.ExtKeyUsageAny},
		Roots:     roots,
	}

	for _, data := range certParams {

		jwsData, err := jose.ParseSigned(string(data))
		if err != nil {
			return nil, nil, fmt.Errorf("verifyJws: Data could not be parsed - %v", err)
		}

		certs, err := jwsData.Signatures[0].Protected.Certificates(opts)
		if err != nil {
			return nil, nil, fmt.Errorf("Certificate chain for Cert Params: %v", err)
		}

		payload, err := jwsData.Verify(certs[0][0].PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("Signature of Cert Params: %v", err)
		}

		// Unmarshal the certificate parameters
		cp := new(ar.CertParams)
		if err := json.Unmarshal(payload, cp); err != nil {
			return nil, nil, fmt.Errorf("Failed to unmarshal cert params: %v ", err)
		}
		if cp.Type == "AK Cert Params" {
			log.Debug("Added AK Certificate Parameters")
			akCertParams = cp
		} else if cp.Type == "TLS Key Cert Params" {
			log.Debug("Added TLS Key Certificate Parameters")
			tlsCertParams = cp
		} else {
			return nil, nil, fmt.Errorf("Unknown Cert Params Type: %v", cp.Type)
		}
	}

	if akCertParams == nil {
		return nil, nil, fmt.Errorf("Did not find AK certificate parameters")
	}
	if tlsCertParams == nil {
		return nil, nil, fmt.Errorf("Did not find TLS key certificate parameters")
	}

	return akCertParams, tlsCertParams, nil
}

// Handle Activate Credential Request (Step 1)
func HandleAcRequest(buf *bytes.Buffer) (*bytes.Buffer, error) {

	var acRequest tpmdriver.AcRequest
	// Registers specific type for value transferred as interface
	gob.Register(rsa.PublicKey{})
	d := gob.NewDecoder(buf)
	d.Decode(&acRequest)

	if acRequest.Ek.Certificate == nil {
		return nil, fmt.Errorf("Certificate not present")
	}
	if acRequest.Ek.Public == nil {
		return nil, fmt.Errorf("EK Pub not present")
	}

	if dataStore.VerifyEkCert {
		err := VerifyEkCert(dataStore.DbPath, acRequest.Ek.Certificate, &acRequest.TpmInfo)
		if err != nil {
			return nil, fmt.Errorf("Verify EK certificate chain: error = %v", err)
		}
		log.Debug("Verification of EK certificate chain successful")
	} else {
		log.Warn("Skipping EK certificate chain validation (turned off via config)")
	}

	var ekPub rsa.PublicKey
	ekPub, ok := acRequest.Ek.Public.(rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("RSA Public Key required for credential activation")
	}

	params := attest.ActivationParameters{
		TPMVersion: 2,
		EK:         &ekPub,
		AK:         acRequest.AkParams,
	}

	secret, encryptedCredentials, err := params.Generate()
	if err != nil {
		return nil, fmt.Errorf("Error Generating Credentials - '%v'", err)
	}

	// Return encrypted credentials to client
	acResponse := tpmdriver.AcResponse{
		Ec: *encryptedCredentials,
	}

	var retBuf bytes.Buffer
	e := gob.NewEncoder(&retBuf)
	err = e.Encode(acResponse)
	if err != nil {
		return nil, fmt.Errorf("Error Activating Credential - '%v'", err)
	}

	dataStore.Secret[acRequest.AkQualifiedName] = secret
	dataStore.AkParams[acRequest.AkQualifiedName] = acRequest.AkParams
	dataStore.TlsKeyParams[acRequest.AkQualifiedName] = acRequest.TlsKeyParams

	return &retBuf, nil
}

// Handle AK Cert Request (Step 2)
func HandleAkCertRequest(buf *bytes.Buffer) (*bytes.Buffer, error) {

	var akCertRequest tpmdriver.AkCertRequest
	decoder := gob.NewDecoder(buf)
	decoder.Decode(&akCertRequest)

	// Compare the client returned decrypted secret with the
	// server generated secret
	if bytes.Compare(akCertRequest.Secret, dataStore.Secret[akCertRequest.AkQualifiedName]) == 0 {
		log.Debug(fmt.Sprintf("Activate Credential Successful - Secrets match"))
	} else {
		return nil, fmt.Errorf("Activate Credential Failed - Secrets do no match")
	}

	// Parse certificate parameters
	akCertParams, tlsCertParams, err := parseCertParams(akCertRequest.CertParams)
	if err != nil {
		return nil, fmt.Errorf("Activate Credential Failed - Failed to parse certificate parameters: %v", err)
	}

	// Generate AK certificate
	akPub, err := attest.ParseAKPublic(attest.TPMVersion20, dataStore.AkParams[akCertRequest.AkQualifiedName].Public)
	if err != nil {
		return nil, fmt.Errorf("Activate Credential Failed - ParseAKPublic returned %v", err)
	}

	encodedpub, err := x509.MarshalPKIXPublicKey(akPub.Public)
	if err != nil {
		return nil, fmt.Errorf("Activate Credential Failed - Marshal Public key returned %v", err)
	}
	ski := sha1.Sum(encodedpub)

	if akCertParams.Subject.OrganizationalUnit != "device" {
		return nil, fmt.Errorf("Activate Credential Failed - Invalid role ('OU' field) for AK certificate: Must be 'device'")
	}

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
		return nil, fmt.Errorf("Failed to create AK certificate: %v", err)
	}

	akPem := &bytes.Buffer{}
	pem.Encode(akPem, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	log.Trace("Generated new AK Certificate: ", akPem.String())

	// Verify that TLS Key is a TPM key signed by the AK
	pub, err := tpm2.DecodePublic(dataStore.AkParams[akCertRequest.AkQualifiedName].Public)
	if err != nil {
		return nil, fmt.Errorf("DecodePublic() failed: %v", err)
	}
	akPubVerify := &rsa.PublicKey{E: int(pub.RSAParameters.Exponent()), N: pub.RSAParameters.Modulus()}
	hash, err := pub.RSAParameters.Sign.Hash.Hash()
	if err != nil {
		return nil, fmt.Errorf("cannot access AK's hash function: %v", err)
	}
	opts := attest.VerifyOpts{
		Public: akPubVerify,
		Hash:   hash,
	}
	p := dataStore.TlsKeyParams[akCertRequest.AkQualifiedName]
	err = p.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("Failed to verify TLS Key with AK: %v", err)
	}
	log.Debug("Successfully verified TLS key with AK")

	tlsPub, err := attest.ParseAKPublic(attest.TPMVersion20, dataStore.TlsKeyParams[akCertRequest.AkQualifiedName].Public)
	if err != nil {
		return nil, fmt.Errorf("Activate Credential Failed - Parse TLS Key returned %v", err)
	}

	encodedpub, err = x509.MarshalPKIXPublicKey(tlsPub.Public)
	if err != nil {
		return nil, fmt.Errorf("Activate Credential Failed - Marshal Public key returned %v", err)
	}
	ski = sha1.Sum(encodedpub)

	if tlsCertParams.Subject.OrganizationalUnit != "device" {
		return nil, fmt.Errorf("Activate Credential Failed - Invalid role ('OU' field) for TLS certificate: Must be 'device'")
	}

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
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, // encipherment is RSA specific requirement
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              tlsCertParams.SANs,
	}

	der, err = x509.CreateCertificate(rand.Reader, &tmpl, dataStore.DeviceSubCaCert, tlsPub.Public, dataStore.DeviceSubCaPriv)
	if err != nil {
		return nil, fmt.Errorf("Failed to create AK certificate: %v", err)
	}

	tlsKeyPem := &bytes.Buffer{}
	pem.Encode(tlsKeyPem, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	log.Trace("Generated new TLS Key Certificate: ", tlsKeyPem.String())

	akCertResponse := tpmdriver.AkCertResponse{
		AkCert:          akPem.Bytes(),
		TlsCert:         tlsKeyPem.Bytes(),
		DeviceSubCaCert: dataStore.DeviceSubCaCertPem,
		CaCert:          dataStore.CaCertPem,
	}

	var retBuf bytes.Buffer
	e := gob.NewEncoder(&retBuf)
	err = e.Encode(akCertResponse)
	if err != nil {
		return nil, fmt.Errorf("Error Generating AK Cert - Encode returned %v", err)
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
				msg := fmt.Sprintf("Error Activating Credential - not all bytes sent")
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

func VerifyEkCert(dbpath string, ek *x509.Certificate, tpmInfo *attest.TPMInfo) error {
	// Load the TPM EK Certificate database for validating sent EK certificates
	db, err := sql.Open("sqlite3", dbpath)
	if err != nil {
		return err
	}
	defer db.Close()

	var intermediates []byte
	err = db.QueryRow("SELECT Certs FROM trustanchors WHERE Manufacturer LIKE ? AND FwMajor=?", tpmInfo.Manufacturer.String(), tpmInfo.FirmwareVersionMajor).Scan(&intermediates)
	if err != nil {
		return err
	}

	var roots []byte
	err = db.QueryRow("SELECT Certs FROM trustanchors WHERE Manufacturer LIKE ? AND CA=1", tpmInfo.Manufacturer.String()).Scan(&roots)
	if err != nil {
		return err
	}

	log.Trace("Found Intermediate Certs in DB: ", string(intermediates))
	log.Trace("Found Root Certs in DB: ", string(roots))

	intermediatesPool := x509.NewCertPool()
	ok := intermediatesPool.AppendCertsFromPEM(intermediates)
	if !ok {
		return fmt.Errorf("Failed to append intermediate certificates from database")
	}
	log.Debugf("Added %v certificates to intermediates certificate pool", len(intermediatesPool.Subjects()))

	rootsPool := x509.NewCertPool()
	ok = rootsPool.AppendCertsFromPEM(roots)
	if !ok {
		return fmt.Errorf("Failed to append root certificate from database")
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

	expectedLen := len(intermediatesPool.Subjects()) + len(rootsPool.Subjects()) + 1

	if len(chain[0]) != expectedLen {
		return fmt.Errorf("Error: Expected chain of length %v (got %v)", expectedLen, len(chain[0]))
	}

	log.Debugf("Sucessfully verified chain of %v elements", len(chain[0]))
	for i, _ := range chain[0] {
		log.Tracef("\tCertificate CN='%v', Issuer CN='%v'", chain[0][i].Subject.CommonName, chain[0][i].Issuer.CommonName)
	}

	return nil
}

// Returns either the unmodified absolute path or the absolute path
// retrieved from a path relative to a base path
func getFilePath(p, base string) string {
	if path.IsAbs(p) {
		return p
	} else {
		ret, _ := filepath.Abs(filepath.Join(base, p))
		return ret
	}
}

func main() {

	log.Info("Connector Provisioning Demo Server")

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
	dataStore.TlsKeyParams = make(map[[32]byte]attest.CertificationParameters)

	// Retrieve the directories to be provided from config and create http
	// directory structure
	log.Info(fmt.Sprintf("Serving Directories: "))

	httpFolder := getFilePath(config.HttpFolder, filepath.Dir(*configFile))

	connectorDirs, err := ioutil.ReadDir(httpFolder)
	if err != nil {
		log.Error(fmt.Sprintf("Failed to open connector data folders '%v' - %v", httpFolder, err))
		return
	}

	for _, dir := range connectorDirs {
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

	port := fmt.Sprintf(":%v", config.Port)
	err = http.ListenAndServe(port, nil)
	if err != nil {
		log.Error("HTTP Server failed: ", err)
	}
}
