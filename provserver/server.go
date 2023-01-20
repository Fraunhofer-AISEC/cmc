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
	"crypto/x509/pkix"
	"sync"

	"crypto/x509"
	"database/sql"
	"encoding/asn1"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/snpdriver"
	"github.com/Fraunhofer-AISEC/cmc/swdriver"
	"github.com/Fraunhofer-AISEC/cmc/tpmdriver"
	log "github.com/sirupsen/logrus"

	"github.com/Fraunhofer-AISEC/go-attestation/attest"

	"github.com/google/go-tpm/tpm2"
	_ "github.com/mattn/go-sqlite3"
)

type config struct {
	Port               int      `json:"port"`
	SigningKeyFile     string   `json:"signingKey"`
	CertChainFiles     []string `json:"certChain"`
	HTTPFolder         string   `json:"httpFolder"`
	VerifyEkCert       bool     `json:"verifyEkCert"`
	TpmEkCertDb        string   `json:"tpmEkCertDb,omitempty"`
	VcekOfflineCaching bool     `json:"vcekOfflineCaching,omitempty"`
	VcekCacheFolder    string   `json:"vcekCacheFolder,omitempty"`
	Serialization      string   `json:"serialization"`
}

type datastore struct {
	Secret             map[[32]byte][]byte
	AkParams           map[[32]byte]attest.AttestationParameters
	IkParams           map[[32]byte]attest.CertificationParameters
	SigningKey         *ecdsa.PrivateKey
	CertChain          []*x509.Certificate
	CertChainPem       [][]byte
	VerifyEkCert       bool
	DbPath             string
	VcekMutex          sync.Mutex
	VcekOfflineCaching bool
	VcekCacheFolder    string
	Vceks              map[snpdriver.VcekRequest][]byte
	Serializer         ar.Serializer
}

const (
	manufacturerIntel     = "Intel"
	intelEKCertServiceURL = "https://ekop.intel.com/ekcertservice/"
	snpVcekUrlPrefix      = "https://kdsintf.amd.com/vcek/v1/Milan/"
	snpMilanUrl           = "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain"
	snpMaxRetries         = 3
)

var (
	tpmProtocolVersion = 1
	swProtocolVersion  = 1
	snpProtocolVersion = 1
	dataStore          datastore
)

func printConfig(c *config, configFile string) {
	log.Infof("Using the configuration loaded from %v:", configFile)
	log.Infof("\tPort                : %v", c.Port)
	log.Infof("\tSigning Key File    : %v", getFilePath(c.SigningKeyFile, filepath.Dir(configFile)))
	log.Infof("\tCert Chain Files    :")
	for i, f := range c.CertChainFiles {
		log.Infof("\t\tCert %v: %v", i, f)
	}
	log.Infof("\tFolders to be served: %v", getFilePath(c.HTTPFolder, filepath.Dir(configFile)))
	log.Infof("\tVerify EK Cert      : %v", c.VerifyEkCert)
	log.Infof("\tTPM EK DB           : %v", getFilePath(c.TpmEkCertDb, filepath.Dir(configFile)))
	log.Infof("\tVCEK Offline Caching: %v", c.VcekOfflineCaching)
	log.Infof("\tVCEK Cache Folder   : %v", getFilePath(c.VcekCacheFolder, filepath.Dir(configFile)))
	log.Infof("\tSerialization       : %v", c.Serialization)
}

func readConfig(configFile string) (*config, error) {
	data, err := os.ReadFile(configFile)
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

func loadPrivateKey(caPrivFile string) (*ecdsa.PrivateKey, error) {

	// Read private pem-encoded key and convert it to a private key
	privBytes, err := os.ReadFile(caPrivFile)
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

func parseCertParams(certParams []byte) (*ar.CertParams, error) {

	if certParams == nil {
		return nil, errors.New("verification of certificate parameters failed: no data provided")
	}
	if len(dataStore.CertChain) == 0 {
		return nil, errors.New("verification of certificate parameters failed: internal cert chain not present")
	}

	log.Trace("Verifying certificate parameters..")

	ca := dataStore.CertChain[len(dataStore.CertChain)-1]

	_, payload, ok := dataStore.Serializer.VerifyToken(certParams, []*x509.Certificate{ca})
	if !ok {
		return nil, errors.New("verification of certificate parameter signatures failed")
	}

	// Unmarshal the certificate parameters
	cp := new(ar.CertParams)
	if err := dataStore.Serializer.Unmarshal(payload, cp); err != nil {
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

	if acRequest.Version != tpmProtocolVersion {
		return nil, fmt.Errorf("activate credential request protocol version of server (%d) does not match client (%d)",
			tpmProtocolVersion, acRequest.Version)
	}

	if acRequest.Ek.Public == nil {
		return nil, fmt.Errorf("ek public key from device not present")
	}

	// Retrieve the EK cert (varies between manufacturers)
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

	// Verify the EK certificate chain
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

	// Generate the credential activation challenge. This includes verifying, that the
	// AK is a restricted, fixedTPM, fixedParent key
	secret, encryptedCredentials, err := params.Generate()
	if err != nil {
		return nil, fmt.Errorf("error Generating Credentials - '%w'", err)
	}

	// Return encrypted credentials to client
	acResponse := tpmdriver.AcResponse{
		Version: tpmProtocolVersion,
		Ec:      *encryptedCredentials,
	}

	var retBuf bytes.Buffer
	e := gob.NewEncoder(&retBuf)
	err = e.Encode(acResponse)
	if err != nil {
		return nil, fmt.Errorf("error Activating Credential - '%w'", err)
	}

	dataStore.Secret[acRequest.AkQualifiedName] = secret
	dataStore.AkParams[acRequest.AkQualifiedName] = acRequest.AkParams
	dataStore.IkParams[acRequest.AkQualifiedName] = acRequest.IkParams

	return &retBuf, nil
}

// HandleAkCertRequest handles an AK Cert Request (Step 2)
func HandleAkCertRequest(buf *bytes.Buffer) (*bytes.Buffer, error) {

	if len(dataStore.CertChainPem) == 0 {
		return nil, errors.New("failed to create AkCertResponse: certificate chain not present")
	}
	if len(dataStore.CertChain) == 0 {
		return nil, errors.New("failed to create AkCertResponse: certificate chain not present")
	}

	var akCertRequest tpmdriver.AkCertRequest
	decoder := gob.NewDecoder(buf)
	decoder.Decode(&akCertRequest)

	if akCertRequest.Version != tpmProtocolVersion {
		return nil, fmt.Errorf("ak cert request protocol version of server (%d) does not match client (%d)",
			tpmProtocolVersion, akCertRequest.Version)
	}

	// Compare the client returned decrypted secret with the
	// server generated secret
	if bytes.Equal(akCertRequest.Secret, dataStore.Secret[akCertRequest.AkQualifiedName]) {
		log.Debug("Activate Credential Successful - Secrets match")
	} else {
		return nil, errors.New("activate credential failed - cecrets do no match")
	}

	// Parse certificate parameters
	akCertParams := ar.CertParams{}
	ikCertParams := ar.CertParams{}
	for _, c := range akCertRequest.CertParams {
		cp, err := parseCertParams(c)
		if err != nil {
			return nil, fmt.Errorf("activate credential Failed - Failed to parse certificate parameters: %w", err)
		}
		if cp.Type == "AK Cert Params" {
			log.Debug("Added AK Certificate Parameters")
			akCertParams = *cp
		} else if cp.Type == "TLS Key Cert Params" {
			log.Debug("Added IK Certificate Parameters")
			ikCertParams = *cp
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

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, dataStore.CertChain[0], akPub.Public, dataStore.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AK certificate: %w", err)
	}

	akPem := &bytes.Buffer{}
	pem.Encode(akPem, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	log.Trace("Generated new AK Certificate: ", akPem.String())

	// Verify that IK is a TPM key signed by the AK
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
	p := dataStore.IkParams[akCertRequest.AkQualifiedName]
	err = p.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to verify IK with AK: %w", err)
	}
	log.Debug("Successfully verified IK with AK")

	ikPub, err := attest.ParseAKPublic(attest.TPMVersion20, dataStore.IkParams[akCertRequest.AkQualifiedName].Public)
	if err != nil {
		return nil, fmt.Errorf("activate credential Failed - parse IK returned %w", err)
	}

	encodedpub, err = x509.MarshalPKIXPublicKey(ikPub.Public)
	if err != nil {
		return nil, fmt.Errorf("activate credential failed - marshal public key returned %w", err)
	}
	ski = sha1.Sum(encodedpub)

	// Create IK certificate
	tmpl = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         ikCertParams.Subject.CommonName,
			Country:            []string{ikCertParams.Subject.Country},
			Province:           []string{ikCertParams.Subject.Province},
			Locality:           []string{ikCertParams.Subject.Locality},
			Organization:       []string{ikCertParams.Subject.Organization},
			OrganizationalUnit: []string{ikCertParams.Subject.OrganizationalUnit},
			StreetAddress:      []string{ikCertParams.Subject.StreetAddress},
			PostalCode:         []string{ikCertParams.Subject.PostalCode},
		},
		SubjectKeyId:          ski[:],
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              ikCertParams.SANs,
	}

	der, err = x509.CreateCertificate(rand.Reader, &tmpl, dataStore.CertChain[0], ikPub.Public, dataStore.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create IK certificate: %w", err)
	}

	ikPem := &bytes.Buffer{}
	pem.Encode(ikPem, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	log.Trace("Generated new IK Certificate: ", ikPem.String())

	intermediates := make([][]byte, 0)
	intermediates = append(intermediates, dataStore.CertChainPem[:len(dataStore.CertChainPem)-1]...)

	akCertResponse := tpmdriver.AkCertResponse{
		Version:         tpmProtocolVersion,
		AkQualifiedName: akCertRequest.AkQualifiedName,
		AkCertChain: ar.CertChain{
			Leaf:          akPem.Bytes(),
			Intermediates: intermediates,
			Ca:            dataStore.CertChainPem[len(dataStore.CertChainPem)-1],
		},
		IkCertChain: ar.CertChain{
			Leaf:          ikPem.Bytes(),
			Intermediates: intermediates,
			Ca:            dataStore.CertChainPem[len(dataStore.CertChainPem)-1],
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

	if len(dataStore.CertChainPem) == 0 {
		return nil, errors.New("failed to create AkCertResponse: certificate chain not present")
	}
	if len(dataStore.CertChain) == 0 {
		return nil, errors.New("failed to create AkCertResponse: certificate chain not present")
	}

	log.Trace("Decoding request")

	var req swdriver.SwCertRequest
	decoder := gob.NewDecoder(buf)
	decoder.Decode(&req)

	if req.Version != swProtocolVersion {
		return nil, fmt.Errorf("sw request protocol version of server (%d) does not match client (%d)",
			tpmProtocolVersion, req.Version)
	}

	log.Trace("Parsing certificate parameters")

	certParams, err := parseCertParams(req.CertParams)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate parameters: %w", err)
	}
	if certParams.Type != "TLS Key Cert Params" {
		return nil, fmt.Errorf("unknown cert params type: %v", certParams.Type)
	}

	pubKey, err := x509.ParsePKIXPublicKey(req.PubKey)
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

	cert, err := x509.CreateCertificate(rand.Reader, &tmpl, dataStore.CertChain[0], pubKey, dataStore.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create IK certificate: %w", err)
	}

	tmp := &bytes.Buffer{}
	pem.Encode(tmp, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	log.Trace("Generated new SW IK Certificate: ", tmp.String())

	intermediates := make([][]byte, 0)
	intermediates = append(intermediates, dataStore.CertChainPem[:len(dataStore.CertChainPem)-1]...)

	certResponse := swdriver.SwCertResponse{
		Version: swProtocolVersion,
		Certs: ar.CertChain{
			Leaf:          tmp.Bytes(),
			Intermediates: intermediates,
			Ca:            dataStore.CertChainPem[len(dataStore.CertChainPem)-1],
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

			b, err := io.ReadAll(req.Body)
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
			b, err := io.ReadAll(req.Body)
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

			log.Trace("Reading http body")
			b, err := io.ReadAll(req.Body)
			if err != nil {
				msg := fmt.Sprintf("Failed to handle sw-sign request: %v", err)
				log.Warn(msg)
				http.Error(writer, msg, http.StatusBadRequest)
				return
			}
			buf := bytes.NewBuffer(b)

			// Handle the certificate request
			log.Trace("Handling certificate request")
			retBuf, err := HandleSwCertRequest(buf)
			if err != nil {
				msg := fmt.Sprintf("Failed to handle sw-sign request: %v", err)
				log.Warn(msg)
				http.Error(writer, msg, http.StatusBadRequest)
				return
			}

			// Send back response
			log.Trace("Sending back certificate request")
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
		log.Debug("Added certificates to intermediates certificate pool")
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
	log.Debug("Added certificates to root certificate pool")

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

			b, err := io.ReadAll(req.Body)
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

	if req.Version != snpProtocolVersion {
		return nil, fmt.Errorf("snp request protocol version of server (%d) does not match client (%d)",
			tpmProtocolVersion, req.Version)
	}

	vcek, err := getVcek(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get VCEK: %w", err)
	}

	resp := snpdriver.VcekResponse{
		Version: snpProtocolVersion,
		Vcek:    encodeCertPem(vcek),
	}

	var retBuf bytes.Buffer
	e := gob.NewEncoder(&retBuf)
	err = e.Encode(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cert - encode returned %w", err)
	}

	return &retBuf, nil
}

func lockDatastore() {
	log.Trace("Trying to get lock")
	dataStore.VcekMutex.Lock()
	log.Trace("Got lock")
}

func unlockDatastore() {
	log.Trace("Releasing Lock")
	dataStore.VcekMutex.Unlock()
	log.Trace("Released Lock")
}

// tryGetCachedVcek returns cached VCEKs in DER format if available
func tryGetCachedVcek(req snpdriver.VcekRequest) ([]byte, bool) {
	if dataStore.VcekOfflineCaching {
		filePath := path.Join(dataStore.VcekCacheFolder,
			fmt.Sprintf("%v_%x.der", hex.EncodeToString(req.ChipId[:]), req.Tcb))
		f, err := os.ReadFile(filePath)
		if err != nil {
			log.Tracef("VCEK not present at %v, will be downloaded", filePath)
			return nil, false
		}
		log.Tracef("Using offlince cached VCEK %v", filePath)
		return f, true
	} else {
		if der, ok := dataStore.Vceks[req]; ok {
			log.Trace("Using cached VCEK")
			return der, true
		}
		log.Trace("Could not find VCEK in cache")
	}
	return nil, false
}

// cacheVcek caches VCEKs in DER format
func cacheVcek(vcek []byte, req snpdriver.VcekRequest) error {
	if dataStore.VcekOfflineCaching {
		filePath := path.Join(dataStore.VcekCacheFolder,
			fmt.Sprintf("%v_%x.der", hex.EncodeToString(req.ChipId[:]), req.Tcb))
		err := os.WriteFile(filePath, vcek, 0644)
		if err != nil {
			return fmt.Errorf("failed to write file %v: %w", filePath, err)
		}
		log.Tracef("Cached VCEK at %v", filePath)
		return nil
	} else {
		dataStore.Vceks[req] = vcek
		log.Trace("Cached VCEK")
		return nil
	}
}

// Get Vcek takes the TCB and chip ID, calculates the VCEK URL and gets the certificate
// in DER format from the cache or downloads it from the AMD server if not present
func getVcek(req snpdriver.VcekRequest) ([]byte, error) {

	// Allow only one download and caching of the VCEK certificate in parallel
	// as the AMD KDF server allows only one request in 10s
	lockDatastore()
	defer unlockDatastore()

	der, ok := tryGetCachedVcek(req)
	if ok {
		return der, nil
	}

	ChipId := hex.EncodeToString(req.ChipId[:])
	tcbInfo := fmt.Sprintf("?blSPL=%v&teeSPL=%v&snpSPL=%v&ucodeSPL=%v",
		req.Tcb&0xFF,
		(req.Tcb>>8)&0xFF,
		(req.Tcb>>48)&0xFF,
		(req.Tcb>>56)&0xFF)

	url := snpVcekUrlPrefix + ChipId + tcbInfo
	for i := 0; i < snpMaxRetries; i++ {
		log.Tracef("Requesting SNP VCEK certificate from: %v", url)
		vcek, statusCode, err := downloadCert(url)
		if err == nil {
			log.Tracef("Successfully downloaded VCEK certificate")
			if err := cacheVcek(vcek.Raw, req); err != nil {
				log.Warnf("Failed to cache VCEK: %v", err)
			}
			return vcek.Raw, nil
		}
		// If the status code is not 429 (too many requests), return
		if statusCode != 429 {
			return nil, fmt.Errorf("failed to get VCEK certificate: %w", err)
		}
		// The AMD KDS server accepts requests only every 10 seconds, try again
		log.Warnf("AMD server blocked VCEK request for ChipID %v TCB %x (HTTP 429 - Too many requests). Trying again in 11s",
			hex.EncodeToString(req.ChipId[:]), req.Tcb)
		time.Sleep(time.Duration(11) * time.Second)
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

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read HTTP body: %w", err)
	}

	cert, err := x509.ParseCertificate(content)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to parse x509 Certificate: %w", err)
	}
	return cert, resp.StatusCode, nil
}

func encodeCertPem(der []byte) []byte {
	tmp := &bytes.Buffer{}
	pem.Encode(tmp, &pem.Block{Type: "CERTIFICATE", Bytes: der})
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

	// Read the configuration file
	config, err := readConfig(*configFile)
	if err != nil {
		log.Error(err)
		return
	}
	printConfig(config, *configFile)

	// Configure if EK certificate chains should be validated
	dataStore.VerifyEkCert = config.VerifyEkCert
	if dataStore.VerifyEkCert {
		dataStore.DbPath = getFilePath(config.TpmEkCertDb, filepath.Dir(*configFile))
	} else {
		log.Warn("Verification of EK certificate chain turned off via Config. Use this for testing only")
	}

	// Configure serializer
	if strings.EqualFold(config.Serialization, "JSON") {
		log.Info("Using JSON/JWS as serialization interface")
		dataStore.Serializer = ar.JsonSerializer{}
	} else if strings.EqualFold(config.Serialization, "CBOR") {
		log.Info("Using CBOR/COSE as serialization interface")
		dataStore.Serializer = ar.CborSerializer{}
	} else {
		log.Errorf("Serializer %v not supported (only 'json' and 'cbor')", config.Serialization)
		return
	}

	// Load CA private key and certificate for signing the AKs
	priv, err := loadPrivateKey(getFilePath(config.SigningKeyFile, filepath.Dir(*configFile)))
	if err != nil {
		log.Error(err)
		return
	}
	dataStore.SigningKey = priv

	if len(config.CertChainFiles) == 0 {
		log.Error("Config error: no certificate chain specified")
		return
	}

	// Load certificate chain
	for _, f := range config.CertChainFiles[:len(config.CertChainFiles)] {
		pem, err := os.ReadFile(getFilePath(f, filepath.Dir(*configFile)))
		if err != nil {
			log.Errorf("Error loading certificate: Read file %v returned %v", f, err)
			return
		}
		dataStore.CertChainPem = append(dataStore.CertChainPem, pem)
		cert, err := internal.LoadCert(pem)
		if err != nil {
			log.Errorf("failed to load certificate: %v", err)
			return
		}
		dataStore.CertChain = append(dataStore.CertChain, cert)
	}

	// Sanity Check
	if len(dataStore.CertChain) == 0 {
		log.Error("configuration error: x509 certificate chain not present")
		return
	}
	if len(dataStore.CertChainPem) == 0 {
		log.Error("configuration error: pem certificate chain not present")
		return
	}

	dataStore.VcekCacheFolder = getFilePath(config.VcekCacheFolder, filepath.Dir(*configFile))
	dataStore.VcekOfflineCaching = config.VcekOfflineCaching

	dataStore.AkParams = make(map[[32]byte]attest.AttestationParameters)
	dataStore.Secret = make(map[[32]byte][]byte)
	dataStore.IkParams = make(map[[32]byte]attest.CertificationParameters)
	dataStore.Vceks = make(map[snpdriver.VcekRequest][]byte)

	// Retrieve the directories to be provided from config and create http
	// directory structure
	log.Info("Serving Directories: ")

	httpFolder := getFilePath(config.HTTPFolder, filepath.Dir(*configFile))

	dirs, err := os.ReadDir(httpFolder)
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
