// Copyright (c) 2024 Fraunhofer AISEC
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

//go:build amd64 && (!nodefaults || sgx)

package sgxdriver

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/edgelesssys/ego/enclave"
	"github.com/google/go-tdx-guest/pcs"
	"github.com/sirupsen/logrus"

	_ "github.com/mattn/go-sqlite3"
)

var log = logrus.WithField("service", "sgxdriver")

const (
	sgxChainFile     = "sgx_ak_chain.pem"
	signingChainFile = "sgx_ik_chain.pem"
	sgxPrivFile      = "sgx_ik_private.key"
)

// Sgx is a structure required for implementing the Measure method
// of the attestation report Measurer interface
type Sgx struct {
	*ar.DriverConfig
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
	var err error

	// Initial checks
	if sgx == nil {
		return errors.New("internal error: SGX object is nil")
	}
	switch c.Serializer.(type) {
	case ar.JsonSerializer:
	case ar.CborSerializer:
	default:
		return fmt.Errorf("serializer not initialized in driver config")
	}

	sgx.DriverConfig = c

	// Create storage folder for storage of internal data if not existing
	if c.StoragePath != "" {
		if _, err := os.Stat(c.StoragePath); err != nil {
			if err := os.MkdirAll(c.StoragePath, 0755); err != nil {
				return fmt.Errorf("failed to create directory for internal data '%v': %w",
					c.StoragePath, err)
			}
		}
	}

	if provisioningRequired(c.StoragePath) {

		// Create CSRs and fetch IK and AK certificates
		log.Info("Performing SGX provisioning")
		err = sgx.provision()
		if err != nil {
			return fmt.Errorf("failed to provision sgx driver: %w", err)
		}

		if c.StoragePath != "" {
			err = sgx.saveCredentials()
			if err != nil {
				return fmt.Errorf("failed to save SGX credentials: %w", err)
			}
		}
	} else {
		err = sgx.loadCredentials()
		if err != nil {
			return fmt.Errorf("failed to load SGX credentials: %w", err)
		}
	}

	return nil
}

// Measure implements the attestation reports generic Measure interface to be called
// as a plugin during attestation report generation
func (sgx *Sgx) Measure(nonce []byte) ([]ar.Measurement, error) {

	log.Debug("Collecting SGX measurements")

	if sgx == nil {
		return nil, errors.New("internal error: SGX object is nil")
	}

	data, err := getMeasurement(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get SGX Measurement: %w", err)
	}

	quote, err := verifier.DecodeSgxReport(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SGX quote: %w", err)
	}

	// Extract quote PCK certificate chain. Currently only support for QECertDataType 5
	var quoteCerts verifier.SgxCertificates
	if quote.QuoteSignatureData.QECertDataType != 5 {
		return nil, fmt.Errorf("quoting enclave cert data type not supported: %v",
			quote.QuoteSignatureData.QECertDataType)
	}
	quoteCerts, err = verifier.ParseCertificates(quote.QuoteSignatureData.QECertData, true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate chain from QECertData: %w", err)
	}
	log.Tracef("PCK Leaf Certificate: %v",
		string(internal.WriteCertPem(quoteCerts.PCKCert)))

	// Get FMSPC
	exts, err := pcs.PckCertificateExtensions(quoteCerts.PCKCert)
	if err != nil {
		return nil, fmt.Errorf("failed to get PCK certificate extensions: %w", err)
	}
	log.Tracef("PCK FMSPC: %v", exts.FMSPC)

	// Fetch collateral
	collateral, err := verifier.FetchCollateral(exts.FMSPC, quoteCerts.PCKCert, verifier.SGX_QUOTE_TYPE)
	if err != nil {
		return nil, fmt.Errorf("failed to get SGX collateral: %w", err)
	}

	measurement := ar.Measurement{
		Type:     "SGX Measurement",
		Evidence: data,
		Certs:    internal.WriteCertsDer(sgx.akChain),
		Artifacts: []ar.Artifact{
			{
				Type: "SGX Collateral",
				Events: []ar.MeasureEvent{
					{
						IntelCollateral: collateral,
					},
				},
			},
		},
	}

	return []ar.Measurement{measurement}, nil
}

func getMeasurement(nonce []byte) ([]byte, error) {
	data, err := enclave.GetRemoteReport(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get SGX Measurement: %w", err)
	}
	return data[16:], nil
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
		log.Debugf("Returning %v AK certificates", len(sgx.akChain))
		return sgx.akChain, nil
	} else if sel == ar.IK {
		log.Debugf("Returning %v IK certificates", len(sgx.ikChain))
		return sgx.ikChain, nil

	}
	return nil, fmt.Errorf("internal error: unknown key selection %v", sel)
}

func (sgx *Sgx) UpdateCerts() error {
	var err error

	// Initial checks
	if sgx == nil {
		return errors.New("internal error: sgx object is nil")
	}

	log.Info("Updating sgx certificates")

	err = sgx.provision()
	if err != nil {
		return fmt.Errorf("failed to provision sgx driver: %w", err)
	}

	if sgx.StoragePath != "" {
		err = sgx.saveCredentials()
		if err != nil {
			return fmt.Errorf("failed to save sgx credentials: %w", err)
		}
	}

	return nil
}

func (sgx *Sgx) UpdateMetadata(metadata map[string][]byte) error {

	// Initial checks
	if sgx == nil {
		return errors.New("internal error: sgx object is nil")
	}

	log.Info("Updating sgx driver metadata")

	sgx.Metadata = metadata

	return nil
}

func (sgx *Sgx) provision() error {
	var err error

	// Create new IK private key
	sgx.ikPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	log.Debug("Retrieving CA certs")
	caCerts, err := sgx.Provisioner.CaCerts()
	if err != nil {
		return fmt.Errorf("failed to retrieve certs: %w", err)
	}

	// Fetch SGX certificate chain for SGX Attestation Key
	sgx.akChain, err = fetchAk()
	if err != nil {
		return fmt.Errorf("failed to get SGX cert chain: %w", err)
	}

	// Create IK CSR and fetch new certificate including its chain from EST server
	ikCert, err := sgx.provisionIk(sgx.ikPriv)
	if err != nil {
		return fmt.Errorf("failed to get signing cert chain: %w", err)
	}

	sgx.ikChain = append([]*x509.Certificate{ikCert}, caCerts...)

	return nil
}

func (sgx *Sgx) provisionIk(priv crypto.PrivateKey) (*x509.Certificate, error) {

	// Retrieve and check FQDN (After the initial provisioning, we do not allow changing the FQDN)
	fqdn, err := internal.Fqdn()
	if err != nil {
		return nil, fmt.Errorf("failed to get FQDN: %v", err)
	}
	if len(sgx.ikChain) > 0 && sgx.ikChain[0].Subject.CommonName != fqdn {
		return nil, fmt.Errorf("retrieved FQDN (%q) does not match IK CN (%v). Changing the FQDN is not allowed",
			fqdn, sgx.ikChain[0].Subject.CommonName)
	}

	// Create IK CSR for authentication
	csr, err := internal.CreateCsr(priv, fqdn, []string{fqdn}, []string{})
	if err != nil {
		return nil, fmt.Errorf("failed to create CSRs: %w", err)
	}

	// Request IK certificate from EST server
	cert, err := sgx.DriverConfig.Provisioner.SimpleEnroll(csr)
	if err != nil {
		return nil, fmt.Errorf("failed to enroll IK cert: %w", err)
	}

	return cert, nil
}

func fetchAk() ([]*x509.Certificate, error) {

	nonce := make([]byte, 64)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce: %w", err)
	}

	// Fetch initial attestation report which contains AK cert chain
	data, err := getMeasurement(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get SGX Measurement: %w", err)
	}

	// Decode attestation report
	quote, err := verifier.DecodeSgxReport(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SGX quote: %v", err)
	}

	// Check nonce
	if !bytes.Equal(quote.ISVEnclaveReport.ReportData[:], nonce) {
		return nil, errors.New("freshness check failed for SGX quote")
	}

	// Extract quote PCK certificate chain. Currently only support for QECertDataType 5
	var quoteCerts verifier.SgxCertificates
	if quote.QuoteSignatureData.QECertDataType != 5 {
		return nil, fmt.Errorf("quoting enclave cert data type not supported: %v",
			quote.QuoteSignatureData.QECertDataType)
	}
	quoteCerts, err = verifier.ParseCertificates(quote.QuoteSignatureData.QECertData, true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate chain from QECertData: %w", err)
	}

	// Return AK cert chain
	return []*x509.Certificate{
		quoteCerts.PCKCert,
		quoteCerts.IntermediateCert,
		quoteCerts.RootCACert,
	}, nil
}

func provisioningRequired(p string) bool {
	// Stateless operation always requires provisioning
	if p == "" {
		log.Info("SGX Provisioning REQUIRED")
		return true
	}

	// If any of the required files is not present, we need to provision
	if _, err := os.Stat(path.Join(p, sgxChainFile)); err != nil {
		log.Info("SGX Provisioning REQUIRED")
		return true
	}
	if _, err := os.Stat(path.Join(p, signingChainFile)); err != nil {
		log.Info("SGX Provisioning REQUIRED")
		return true
	}
	if _, err := os.Stat(path.Join(p, sgxPrivFile)); err != nil {
		log.Info("SGX Provisioning REQUIRED")
		return true
	}

	log.Info("SGX Provisioning NOT REQUIRED")

	return false
}

func (sgx *Sgx) loadCredentials() error {
	data, err := os.ReadFile(path.Join(sgx.StoragePath, sgxChainFile))
	if err != nil {
		return fmt.Errorf("failed to read AK chain from %v: %w", sgx.StoragePath, err)
	}
	sgx.akChain, err = internal.ParseCertsPem(data)
	if err != nil {
		return fmt.Errorf("failed to parse AK certs: %w", err)
	}
	log.Debugf("Parsed stored AK chain of length %v", len(sgx.akChain))

	data, err = os.ReadFile(path.Join(sgx.StoragePath, signingChainFile))
	if err != nil {
		return fmt.Errorf("failed to read IK chain from %v: %w", sgx.StoragePath, err)
	}
	sgx.ikChain, err = internal.ParseCertsPem(data)
	if err != nil {
		return fmt.Errorf("failed to parse IK certs: %w", err)
	}
	log.Debugf("Parsed stored IK chain of length %v", len(sgx.ikChain))

	data, err = os.ReadFile(path.Join(sgx.StoragePath, sgxPrivFile))
	if err != nil {
		return fmt.Errorf("failed to read SGX private key from %v: %w", sgx.StoragePath, err)
	}
	sgx.ikPriv, err = x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return fmt.Errorf("failed to parse SGX private key: %w", err)
	}

	return nil
}

func (sgx *Sgx) saveCredentials() error {
	akchainPem := make([]byte, 0)
	for _, cert := range sgx.akChain {
		c := internal.WriteCertPem(cert)
		akchainPem = append(akchainPem, c...)
	}
	if err := os.WriteFile(path.Join(sgx.StoragePath, sgxChainFile), akchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(sgx.StoragePath, sgxChainFile), err)
	}

	ikchainPem := make([]byte, 0)
	for _, cert := range sgx.ikChain {
		c := internal.WriteCertPem(cert)
		ikchainPem = append(ikchainPem, c...)
	}
	if err := os.WriteFile(path.Join(sgx.StoragePath, signingChainFile), ikchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(sgx.StoragePath, signingChainFile), err)
	}

	key, err := x509.MarshalPKCS8PrivateKey(sgx.ikPriv)
	if err != nil {
		return fmt.Errorf("failed marshal private key: %w", err)
	}
	if err := os.WriteFile(path.Join(sgx.StoragePath, sgxPrivFile), key, 0600); err != nil {
		return fmt.Errorf("failed to write %v: %w", path.Join(sgx.StoragePath, sgxPrivFile), err)
	}

	return nil
}
