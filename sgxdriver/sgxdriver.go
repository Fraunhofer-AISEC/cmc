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

package sgxdriver

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	est "github.com/Fraunhofer-AISEC/cmc/est/estclient"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/edgelesssys/ego/enclave"
	"github.com/sirupsen/logrus"

	_ "github.com/mattn/go-sqlite3"
)

var log = logrus.WithField("service", "sgxdriver")

var (
	tcbInfoUrl             = "https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc=%s"
	pckCertUrl             = "https://api.trustedservices.intel.com/sgx/certification/v4/pckcert?encrypted_ppid=%s&cpusvn=%s&pceid=%s&pcesvn=%s"
	ROOT_CA_CERT_NAME      = "Intel_SGX_Root_CA"
	INTERMEDIATE_CERT_NAME = "Intel_SGX_PCK_Processor_CA"
	PCK_CERT_NAME          = "Intel_SGX_PCK_Certificate"
	TCB_SIGNING_CERT_NAME  = "Intel_SGX_TCB_Signing"
)

// Sgx is a structure required for implementing the Measure method
// of the attestation report Measurer interface
type Sgx struct {
	akChain []*x509.Certificate
	ikChain []*x509.Certificate
	ikPriv  crypto.PrivateKey
}

// Name returns the name of the driver
func (s *Sgx) Name() string {
	return "SGX driver"
}

// Init initializes the SGX driver with the specifified configuration
func (sgx *Sgx) Init(c *ar.DriverConfig) error {

	// Initial checks
	if sgx == nil {
		return errors.New("internal error: SNP object is nil")
	}

	// Create storage folder for storage of internal data if not existing
	if c.StoragePath != "" {
		if _, err := os.Stat(c.StoragePath); err != nil {
			if err := os.MkdirAll(c.StoragePath, 0755); err != nil {
				return fmt.Errorf("failed to create directory for internal data '%v': %w",
					c.StoragePath, err)
			}
		}
	}

	// Create new private key for signing
	ikPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	sgx.ikPriv = ikPriv

	// Create CSRs and fetch IK and AK certificates
	sgx.akChain, sgx.ikChain, err = provisionSgx(ikPriv, c, c.ServerAddr)
	if err != nil {
		return fmt.Errorf("failed to provision sgx driver: %w", err)
	}

	return nil
}

// Measure implements the attestation reports generic Measure interface to be called
// as a plugin during attestation report generation
func (sgx *Sgx) Measure(nonce []byte) (ar.Measurement, error) {

	log.Trace("Collecting SGX measurements")

	if sgx == nil {
		return ar.Measurement{}, errors.New("internal error: SGX object is nil")
	}

	data, err := enclave.GetRemoteReport(nonce)
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to get SGX Measurement: %w", err)
	}

	measurement := ar.Measurement{
		Type:     "SGX Measurement",
		Evidence: data[16:],
		Certs:    internal.WriteCertsDer(sgx.akChain),
	}

	return measurement, nil
}

// Lock implements the locking method for the attestation report signer interface
func (sgx *Sgx) Lock() error {
	// No locking mechanism required for software key
	return nil
}

// Lock implements the unlocking method for the attestation report signer interface
func (sgx *Sgx) Unlock() error {
	// No unlocking mechanism required for software key
	return nil
}

// GetKeyHandles returns private and public key handles as a generic crypto interface
func (sgx *Sgx) GetKeyHandles(sel ar.KeySelection) (crypto.PrivateKey, crypto.PublicKey, error) {
	if sgx == nil {
		return nil, nil, errors.New("internal error: SW object is nil")
	}

	if sel == ar.AK {
		if len(sgx.akChain) == 0 {
			return nil, nil, fmt.Errorf("internal error: SGX AK certificate not present")
		}
		// Only return the public key, as the SGX signing key is not directly accessible
		return nil, sgx.akChain[0].PublicKey, nil
	} else if sel == ar.IK {
		return sgx.ikPriv, &sgx.ikPriv.(*ecdsa.PrivateKey).PublicKey, nil
	}
	return nil, nil, fmt.Errorf("internal error: unknown key selection %v", sel)
}

// GetCertChain returns the certificate chain for the specified key
func (sgx *Sgx) GetCertChain(sel ar.KeySelection) ([]*x509.Certificate, error) {
	if sgx == nil {
		return nil, errors.New("internal error: SW object is nil")
	}

	if sel == ar.AK {
		log.Tracef("Returning %v AK certificates", len(sgx.akChain))
		return sgx.akChain, nil
	} else if sel == ar.IK {
		log.Tracef("Returning %v IK certificates", len(sgx.ikChain))
		return sgx.ikChain, nil

	}
	return nil, fmt.Errorf("internal error: unknown key selection %v", sel)
}

func provisionSgx(ik crypto.PrivateKey, c *ar.DriverConfig, addr string,
) ([]*x509.Certificate, []*x509.Certificate, error) {

	// Get CA certificates and enroll newly created CSR
	// TODO provision EST server certificate with a different mechanism,
	// otherwise this step has to happen in a secure environment. Allow
	// different CAs for metadata and the EST server authentication
	log.Warn("Creating new EST client without server authentication")
	client := est.NewClient(nil)

	log.Info("Retrieving CA certs")
	caCerts, err := client.CaCerts(addr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve certs: %w", err)
	}
	log.Debug("Received certs:")
	for _, c := range caCerts {
		log.Debugf("\t%v", c.Subject.CommonName)
	}
	if len(caCerts) == 0 {
		return nil, nil, fmt.Errorf("no certs provided")
	}

	log.Warn("Setting retrieved cert for future authentication")
	err = client.SetCAs([]*x509.Certificate{caCerts[len(caCerts)-1]})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to set EST CA: %w", err)
	}

	// Perform IK EST enrollment
	ikCsr, err := ar.CreateCsr(ik, c.DeviceConfig.Sgx.IkCsr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSRs: %w", err)
	}

	log.Infof("Performing simple IK enroll for CN=%v", ikCsr.Subject.CommonName)
	ikCert, err := client.SimpleEnroll(addr, ikCsr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to enroll cert: %w", err)
	}
	ikChain := append([]*x509.Certificate{ikCert}, caCerts...)

	// Fetch SGX AK certificate chain
	akChain, err := getSgxCertChain(c)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get SGX cert chain: %w", err)
	}

	return akChain, ikChain, nil
}

func readCertFromFile(filePath string) (*x509.Certificate, error) {
	// Read Certificate
	cert_raw, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	// Parse Certificate
	ikCert, err := x509.ParseCertificate(cert_raw)
	if err != nil {
		return nil, err
	}
	return ikCert, nil
}

func isCertValid(cert *x509.Certificate) bool {
	currentTime := time.Now()
	return currentTime.After(cert.NotAfter) || currentTime.Before(cert.NotBefore)
}

// retrieve PCK Certificate Chain + TCB Signing Cert with caching mechanism
func getSgxCertChain(c *ar.DriverConfig) ([]*x509.Certificate, error) {
	if c.StoragePath == "" {
		log.Traceln("No cache storage available, downloading cert chain")
		return downloadSgxCertChain(&c.DeviceConfig)
	}

	fileNames := []string{PCK_CERT_NAME, INTERMEDIATE_CERT_NAME, ROOT_CA_CERT_NAME, TCB_SIGNING_CERT_NAME}
	certificates := []*x509.Certificate{}

	// Use cache or download if not present
	for _, fileName := range fileNames {
		filePath := fmt.Sprintf("%s/%s.pem", c.StoragePath, fileName)
		_, err := os.Stat(filePath)

		if err != nil {
			certs, err := downloadAndCacheCertChain(c)
			if err != nil {
				return nil, fmt.Errorf("error downloading and caching Sgx Certificate Chain: %v", err)
			}
			certificates = append(certificates, certs...)
			return certificates, nil
		}

		cert, err := readCertFromFile(filePath)
		if err != nil || !isCertValid(cert) {
			certs, err := downloadAndCacheCertChain(c)
			if err != nil {
				return nil, fmt.Errorf("error downloading and caching Sgx Certificate Chain: %v", err)
			}
			certificates = append(certificates, certs...)
			break
		}
		certificates = append(certificates, cert)
	}

	return certificates, nil
}

func downloadAndCacheCertChain(c *ar.DriverConfig) ([]*x509.Certificate, error) {
	certs, err := downloadSgxCertChain(&c.DeviceConfig)
	if err != nil {
		return nil, err
	}

	// Store certificates in cache
	for _, cert := range certs {
		fileName := fmt.Sprintf("%s/%s.pem", c.StoragePath, strings.ReplaceAll(cert.Subject.CommonName, " ", "_"))
		err = os.WriteFile(fileName, cert.Raw, 0644)
		if err != nil {
			return nil, err
		}
	}
	return certs, nil
}

// download PCK Certificate Chain + TCB Signing Cert from Intel API
func downloadSgxCertChain(config *ar.DeviceConfig) ([]*x509.Certificate, error) {

	certificates := []*x509.Certificate{}
	encrypted_ppid := hex.EncodeToString(config.SgxValues.EncryptedPPID)
	cpusvn := hex.EncodeToString(config.SgxValues.Cpusvn)
	pceid := hex.EncodeToString(config.SgxValues.Pceid)
	pcesvn := hex.EncodeToString(config.SgxValues.Pcesvn)
	pckCertUrl = fmt.Sprintf(pckCertUrl, encrypted_ppid, cpusvn, pceid, pcesvn)

	// 1. GET PCK Certificate and Certificte Chain
	req, err := http.NewRequest("GET", pckCertUrl, nil)
	if err != nil {
		return certificates, fmt.Errorf("error creating request: %v", err)
	}

	// Perform untrusted GET request (ego has no access to root certificates in enclave)
	// Should be ok, since root ca certificate fingerpint is checked by verifier
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	resp, err := client.Do(req)
	if err != nil {
		return certificates, fmt.Errorf("error performing request: %v", err)
	}

	// Extract PCK-Certificate-Chain from the header
	sgxPckIssuerChain := resp.Header.Get("SGX-PCK-Certificate-Issuer-Chain")

	decoded, err := url.QueryUnescape(sgxPckIssuerChain)
	if err != nil {
		return certificates, fmt.Errorf("error decoding URL-encoded string: %v", err)
	}

	// Split the PEM certificates
	certs := strings.SplitAfter(decoded, "-----END CERTIFICATE-----\n")
	for _, certPEM := range certs {
		if certPEM != "" {

			// Decode the PEM block
			block, _ := pem.Decode([]byte(certPEM))
			if block == nil {
				return certificates, fmt.Errorf("error decoding PCK cert chain")
			}

			// Parse the certificate
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return certificates, fmt.Errorf("error parsing certificate: %v", err)
			}

			certificates = append(certificates, cert)
		}
	}

	// Read the PCK certificate
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return certificates, fmt.Errorf("error reading response body: %v", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode([]byte(body))
	if block == nil {
		return certificates, fmt.Errorf("error decoding PCK cert")
	}

	// Parse the certificate
	pckCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return certificates, fmt.Errorf("error parsing certificate: %v", err)

	}
	certificates = append(certificates, pckCert)
	resp.Body.Close()

	// Extract FMSPC from PCK certificate SGX Extensions
	sgxExtensions, err := verifier.ParseSGXExtensions(pckCert.Extensions[verifier.SGX_EXTENSION_INDEX].Value[4:])
	if err != nil {
		return certificates, err
	}
	tcbInfoUrl = fmt.Sprintf(tcbInfoUrl, hex.EncodeToString(sgxExtensions.Fmspc.Value))

	// 2. GET TCB Signing Certificate
	req, err = http.NewRequest("GET", tcbInfoUrl, nil)
	if err != nil {
		return certificates, fmt.Errorf("error creating request: %v", err)
	}

	// Perform the request
	resp, err = client.Do(req)
	if err != nil {
		return certificates, fmt.Errorf("error performing request: %v", err)
	}

	// Extract and print TCB-Info-Issuer-Chain from the header
	tcbInfoIssuerChain := resp.Header.Get("TCB-Info-Issuer-Chain")

	decoded, err = url.QueryUnescape(tcbInfoIssuerChain)
	if err != nil {
		return certificates, fmt.Errorf("error decoding URL-encoded string: %v", err)
	}

	// Split the PEM certificates
	certs = strings.SplitAfter(decoded, "-----END CERTIFICATE-----\n")
	tcbSigningCert := certs[0]
	if tcbSigningCert != "" {
		// Decode the PEM block
		block, _ := pem.Decode([]byte(tcbSigningCert))
		if block == nil {
			return certificates, fmt.Errorf("error decoding TCB Signing Cert")
		}

		// Parse the certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return certificates, fmt.Errorf("error parsing certificate: %v", err)
		}

		certificates = append(certificates, cert)
	}

	resp.Body.Close()

	return certificates, nil
}
