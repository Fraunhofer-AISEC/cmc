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
		return errors.New("internal error: SNP object is nil")
	}
	switch c.Serializer.(type) {
	case ar.JsonSerializer:
	case ar.CborSerializer:
	default:
		return fmt.Errorf("serializer not initialized in driver config")
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

	if provisioningRequired(c.StoragePath) {

		// Create CSRs and fetch IK and AK certificates
		log.Info("Performing SGX provisioning")
		err = sgx.provision(c)
		if err != nil {
			return fmt.Errorf("failed to provision sgx driver: %w", err)
		}

		if c.StoragePath != "" {
			err = saveCredentials(c.StoragePath, sgx)
			if err != nil {
				return fmt.Errorf("failed to save SGX credentials: %w", err)
			}
		}
	} else {
		sgx.akChain, sgx.ikChain, sgx.ikPriv, err = loadCredentials(c.StoragePath)
		if err != nil {
			return fmt.Errorf("failed to load SGX credentials: %w", err)
		}
	}

	return nil
}

// Measure implements the attestation reports generic Measure interface to be called
// as a plugin during attestation report generation
func (sgx *Sgx) Measure(nonce []byte) (ar.Measurement, error) {

	log.Debug("Collecting SGX measurements")

	if sgx == nil {
		return ar.Measurement{}, errors.New("internal error: SGX object is nil")
	}

	data, err := getMeasurement(nonce)
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to get SGX Measurement: %w", err)
	}

	quote, err := verifier.DecodeSgxReport(data)
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to decode SGX quote: %w", err)
	}

	// Extract quote PCK certificate chain. Currently only support for QECertDataType 5
	var quoteCerts verifier.SgxCertificates
	if quote.QuoteSignatureData.QECertDataType != 5 {
		return ar.Measurement{}, fmt.Errorf("quoting enclave cert data type not supported: %v",
			quote.QuoteSignatureData.QECertDataType)
	}
	quoteCerts, err = verifier.ParseCertificates(quote.QuoteSignatureData.QECertData, true)
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to parse certificate chain from QECertData: %w", err)
	}
	log.Tracef("PCK Leaf Certificate: %v",
		string(internal.WriteCertPem(quoteCerts.PCKCert)))

	// Get FMSPC
	exts, err := pcs.PckCertificateExtensions(quoteCerts.PCKCert)
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to get PCK certificate extensions: %w", err)
	}
	log.Tracef("PCK FMSPC: %v", exts.FMSPC)

	// Fetch collateral
	collateral, err := verifier.FetchCollateral(exts.FMSPC, quoteCerts.PCKCert, verifier.SGX_QUOTE_TYPE)
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to get SGX collateral: %w", err)
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

	return measurement, nil
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

func (sgx *Sgx) provision(c *ar.DriverConfig) error {
	var err error

	// Create new IK private key
	sgx.ikPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	log.Debug("Retrieving CA certs")
	caCerts, err := c.Provisioner.CaCerts()
	if err != nil {
		return fmt.Errorf("failed to retrieve certs: %w", err)
	}

	// Fetch SGX certificate chain for SGX Attestation Key
	sgx.akChain, err = fetchAk()
	if err != nil {
		return fmt.Errorf("failed to get SGX cert chain: %w", err)
	}

	// Create IK CSR and fetch new certificate including its chain from EST server
	ikCert, err := provisionIk(sgx.ikPriv, c)
	if err != nil {
		return fmt.Errorf("failed to get signing cert chain: %w", err)
	}

	sgx.ikChain = append([]*x509.Certificate{ikCert}, caCerts...)

	return nil
}

func provisionIk(priv crypto.PrivateKey, c *ar.DriverConfig,
) (*x509.Certificate, error) {

	// Create IK CSR for authentication
	csr, err := ar.CreateCsr(priv, c.DeviceConfig.Sgx.IkCsr)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSRs: %w", err)
	}

	// Request IK certificate from EST server
	cert, err := c.Provisioner.SimpleEnroll(csr)
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

func loadCredentials(p string) ([]*x509.Certificate, []*x509.Certificate,
	crypto.PrivateKey, error,
) {
	data, err := os.ReadFile(path.Join(p, sgxChainFile))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read AK chain from %v: %w", p, err)
	}
	akchain, err := internal.ParseCertsPem(data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse AK certs: %w", err)
	}
	log.Debugf("Parsed stored AK chain of length %v", len(akchain))

	data, err = os.ReadFile(path.Join(p, signingChainFile))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read IK chain from %v: %w", p, err)
	}
	ikchain, err := internal.ParseCertsPem(data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse IK certs: %w", err)
	}
	log.Debugf("Parsed stored IK chain of length %v", len(akchain))

	data, err = os.ReadFile(path.Join(p, sgxPrivFile))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read SGX private key from %v: %w", p, err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse SGX private key: %w", err)
	}

	return akchain, ikchain, priv, nil
}

func saveCredentials(p string, sgx *Sgx) error {
	akchainPem := make([]byte, 0)
	for _, cert := range sgx.akChain {
		c := internal.WriteCertPem(cert)
		akchainPem = append(akchainPem, c...)
	}
	if err := os.WriteFile(path.Join(p, sgxChainFile), akchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(p, sgxChainFile), err)
	}

	ikchainPem := make([]byte, 0)
	for _, cert := range sgx.ikChain {
		c := internal.WriteCertPem(cert)
		ikchainPem = append(ikchainPem, c...)
	}
	if err := os.WriteFile(path.Join(p, signingChainFile), ikchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(p, signingChainFile), err)
	}

	key, err := x509.MarshalPKCS8PrivateKey(sgx.ikPriv)
	if err != nil {
		return fmt.Errorf("failed marshal private key: %w", err)
	}
	if err := os.WriteFile(path.Join(p, sgxPrivFile), key, 0600); err != nil {
		return fmt.Errorf("failed to write %v: %w", path.Join(p, sgxPrivFile), err)
	}

	return nil
}
