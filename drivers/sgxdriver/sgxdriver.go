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
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/edgelesssys/ego/enclave"
	"github.com/google/go-tdx-guest/pcs"
	"github.com/sirupsen/logrus"

	_ "github.com/mattn/go-sqlite3"
)

var log = logrus.WithField("service", "sgxdriver")

const (
	sgxChainFile = "sgx_ak_chain.pem"
)

// Sgx is a structure required for implementing the Measure method
// of the attestation report Measurer interface
type Sgx struct {
	*drivers.DriverConfig
	akChain  []*x509.Certificate
	fmspc    string
	endorser drivers.TdxEndorser
}

// Name returns the name of the driver
func (s *Sgx) Name() string {
	return "SGX driver"
}

// Init initializes the SGX driver with the specifified configuration
func (sgx *Sgx) Init(c *drivers.DriverConfig) error {
	var err error

	// Initial checks
	if sgx == nil {
		return errors.New("internal error: SGX object is nil")
	}
	if c.Endorsers == nil {
		return fmt.Errorf("missing endorser provider")
	}

	endorser, ok := c.Endorsers.Tdx()
	if !ok {
		return fmt.Errorf("sgx endorser not configured")
	}
	sgx.endorser = endorser

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

		// Create CSRs and fetch AK certificate
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

func (sgx *Sgx) GetEvidence(nonce []byte) ([]ar.Evidence, error) {

	log.Debug("Collecting SGX evidence")

	if sgx == nil {
		return nil, errors.New("internal error: SGX object is nil")
	}

	data, err := GetQuote(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get SGX Measurement: %w", err)
	}

	evidence := ar.Evidence{
		Type: ar.TYPE_EVIDENCE_SGX,
		Data: data,
	}

	return []ar.Evidence{evidence}, nil
}

func (sgx *Sgx) GetCollateral() ([]ar.Collateral, error) {

	// Fetch collateral
	sgxCollateral, err := sgx.endorser.FetchCollateral(sgx.fmspc, sgx.akChain[0], ar.SGX_QUOTE_TYPE)
	if err != nil {
		return nil, fmt.Errorf("failed to get SGX collateral: %w", err)
	}

	collateral := ar.Collateral{
		Type:  ar.TYPE_EVIDENCE_SGX,
		Certs: internal.WriteCertsDer(sgx.akChain),
		Artifacts: []ar.Artifact{
			{
				Type: ar.TYPE_SGX_COLLATERAL,
				Events: []ar.Component{
					{
						IntelCollateral: sgxCollateral,
					},
				},
			},
		},
	}

	return []ar.Collateral{collateral}, nil
}

func GetQuote(nonce []byte) ([]byte, error) {
	data, err := enclave.GetRemoteReport(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get SGX Measurement: %w", err)
	}
	return data[16:], nil
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

func (sgx *Sgx) provision() error {
	var err error

	// Fetch SGX certificate chain for SGX Attestation Key
	sgx.akChain, err = fetchAk()
	if err != nil {
		return fmt.Errorf("failed to get SGX cert chain: %w", err)
	}

	// Store FMSPC
	exts, err := pcs.PckCertificateExtensions(sgx.akChain[0])
	if err != nil {
		return fmt.Errorf("failed to get PCK certificate extensions: %w", err)
	}
	sgx.fmspc = exts.FMSPC
	log.Tracef("PCK FMSPC: %v", exts.FMSPC)

	return nil
}

func fetchAk() ([]*x509.Certificate, error) {

	nonce := make([]byte, 64)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce: %w", err)
	}

	// Fetch initial attestation report which contains AK cert chain
	data, err := GetQuote(nonce)
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

	return nil
}
