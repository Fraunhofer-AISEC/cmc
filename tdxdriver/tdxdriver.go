// Copyright (c) 2025 Fraunhofer AISEC
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

package tdxdriver

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	est "github.com/Fraunhofer-AISEC/cmc/est/estclient"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/report"
	"github.com/google/go-tdx-guest/pcs"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "tdxdriver")

const (
	tdxChainFile     = "tdx_ak_chain.pem"
	signingChainFile = "tdx_ik_chain.pem"
	tdxPrivFile      = "tdx_ik_private.key"
)

// Tdx is a structure required for implementing the Measure method
// of the attestation report Measurer interface
type Tdx struct {
	akChain []*x509.Certificate
	ikChain []*x509.Certificate
	ikPriv  crypto.PrivateKey
}

// Name returns the name of the driver
func (s *Tdx) Name() string {
	return "TDX driver"
}

// Init initializes the TDX driver with the specifified configuration
func (tdx *Tdx) Init(c *ar.DriverConfig) error {
	var err error

	// Initial checks
	if tdx == nil {
		return errors.New("internal error: TDX object is nil")
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
		log.Info("Performing TDX provisioning")
		// Create new private key for signing
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate private key: %w", err)
		}
		tdx.ikPriv = priv

		tdx.akChain, tdx.ikChain, err = provisionTdx(priv, c.DeviceConfig,
			c.ServerAddr, c.EstTlsCas, c.UseSystemRootCas)
		if err != nil {
			return fmt.Errorf("failed to provision tdx driver: %w", err)
		}

		if c.StoragePath != "" {
			err = saveCredentials(c.StoragePath, tdx)
			if err != nil {
				return fmt.Errorf("failed to save TDX credentials: %w", err)
			}
		}
	} else {
		tdx.akChain, tdx.ikChain, tdx.ikPriv, err = loadCredentials(c.StoragePath)
		if err != nil {
			return fmt.Errorf("failed to load TDX credentials: %w", err)
		}
	}

	return nil
}

// Measure implements the attestation reports generic Measure interface to be called
// as a plugin during attestation report generation
func (tdx *Tdx) Measure(nonce []byte) (ar.Measurement, error) {

	log.Debug("Collecting TDX measurements")

	if tdx == nil {
		return ar.Measurement{}, errors.New("internal error: TDX object is nil")
	}

	data, err := getMeasurement(nonce)
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to get TDX Measurement: %w", err)
	}

	// Decode attestation report to get FMSPC (required to fetch collateral)
	quote, err := verifier.DecodeTdxReportV4(data)
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to decode TDX quote: %w", err)
	}
	log.Tracef("PCK Leaf Certificate: %v",
		string(internal.WriteCertPem(quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert)))

	// Get FMSPC
	exts, err := pcs.PckCertificateExtensions(
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert)
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to get PCK certificate extensions: %w", err)
	}
	log.Tracef("PCK FMSPC: %v", exts.FMSPC)

	// Fetch collateral
	collateral, err := verifier.FetchCollateral(exts.FMSPC,
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert, verifier.TDX_QUOTE_TYPE)
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to get TDX collateral: %w", err)
	}

	// Create measurement
	measurement := ar.Measurement{
		Type:     "TDX Measurement",
		Evidence: data,
		Certs:    internal.WriteCertsDer(tdx.akChain),
		Artifacts: []ar.Artifact{
			{
				Type: "TDX Collateral",
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

// Lock implements the locking method for the attestation report signer interface
func (tdx *Tdx) Lock() error {
	// No locking mechanism required for software key
	return nil
}

// Lock implements the unlocking method for the attestation report signer interface
func (tdx *Tdx) Unlock() error {
	// No unlocking mechanism required for software key
	return nil
}

// GetKeyHandles returns private and public key handles as a generic crypto interface
func (tdx *Tdx) GetKeyHandles(sel ar.KeySelection) (crypto.PrivateKey, crypto.PublicKey, error) {
	if tdx == nil {
		return nil, nil, errors.New("internal error: TDX object is nil")
	}

	if sel == ar.AK {
		if len(tdx.akChain) == 0 {
			return nil, nil, fmt.Errorf("internal error: TDX AK certificate not present")
		}
		// Only return the public key, as the VCEK / VLEK is not directly accessible
		return nil, tdx.akChain[0].PublicKey, nil
	} else if sel == ar.IK {
		return tdx.ikPriv, &tdx.ikPriv.(*ecdsa.PrivateKey).PublicKey, nil
	}
	return nil, nil, fmt.Errorf("internal error: unknown key selection %v", sel)
}

// GetCertChain returns the certificate chain for the specified key
func (tdx *Tdx) GetCertChain(sel ar.KeySelection) ([]*x509.Certificate, error) {
	if tdx == nil {
		return nil, errors.New("internal error: SW object is nil")
	}

	if sel == ar.AK {
		log.Debugf("Returning %v AK certificates", len(tdx.akChain))
		return tdx.akChain, nil
	} else if sel == ar.IK {
		log.Debugf("Returning %v IK certificates", len(tdx.ikChain))
		return tdx.ikChain, nil
	}
	return nil, fmt.Errorf("internal error: unknown key selection %v", sel)
}

func getMeasurement(nonce []byte) ([]byte, error) {

	// Maximum TD quote REPORTDATA length
	if len(nonce) > 64 {
		return nil, errors.New("user Data must be at most 64 bytes")
	}

	// Must be 64 bytes long, fill with zeros
	if len(nonce) < 64 {
		tmpNonce := make([]byte, 64)
		copy(tmpNonce, nonce)
		nonce = tmpNonce
	}

	log.Debugf("Fetching TDX attestation report via configfs with nonce: %v", hex.EncodeToString(nonce))

	// Generate Quote
	req := &report.Request{
		InBlob:     nonce,
		GetAuxBlob: false,
	}
	resp, err := linuxtsm.GetReport(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get TDX quote via configfs: %w", err)
	}

	return resp.OutBlob, nil
}

func provisionTdx(priv crypto.PrivateKey, devConf ar.DeviceConfig, addr string,
	estTlsCas []*x509.Certificate, useSystemRootCas bool,
) ([]*x509.Certificate, []*x509.Certificate, error) {

	// Create IK CSR and fetch new certificate including its chain from EST server
	ikchain, err := provisionIk(priv, devConf, addr, estTlsCas, useSystemRootCas)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signing cert chain: %w", err)
	}

	// Fetch TDX certificate chain for TDX Attestation Key
	akchain, err := fetchAk()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get TDX cert chain: %w", err)
	}

	return akchain, ikchain, nil
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
		return nil, fmt.Errorf("failed to get TDX Measurement: %w", err)
	}

	// Decode attestation report
	quote, err := verifier.DecodeTdxReportV4(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TDX quote: %v", err)
	}

	// Check nonce
	if !bytes.Equal(quote.QuoteBody.ReportData[:], nonce) {
		return nil, errors.New("freshness check failed for TDX quote")
	}

	// Return AK cert chain
	return []*x509.Certificate{
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert,
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.IntermediateCert,
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.RootCACert,
	}, nil
}

func provisionIk(priv crypto.PrivateKey, devConf ar.DeviceConfig, addr string,
	estTlsCas []*x509.Certificate, useSystemRootCas bool,
) ([]*x509.Certificate, error) {

	client, err := est.NewClient(estTlsCas, useSystemRootCas)
	if err != nil {
		return nil, fmt.Errorf("failed to create EST client: %w", err)
	}

	log.Debug("Retrieving CA certs")
	caCerts, err := client.CaCerts(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve certs: %w", err)
	}
	log.Debug("Received certs:")
	for _, c := range caCerts {
		log.Debugf("\t%v", c.Subject.CommonName)
	}
	if len(caCerts) == 0 {
		return nil, fmt.Errorf("no certs provided")
	}

	// Create IK CSR for authentication
	csr, err := ar.CreateCsr(priv, devConf.Tdx.IkCsr)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSRs: %w", err)
	}

	// Request IK certificate from EST server
	cert, err := client.SimpleEnroll(addr, csr)
	if err != nil {
		return nil, fmt.Errorf("failed to enroll IK cert: %w", err)
	}

	return append([]*x509.Certificate{cert}, caCerts...), nil
}

func provisioningRequired(p string) bool {
	// Stateless operation always requires provisioning
	if p == "" {
		log.Info("TDX Provisioning REQUIRED")
		return true
	}

	// If any of the required files is not present, we need to provision
	if _, err := os.Stat(path.Join(p, tdxChainFile)); err != nil {
		log.Info("TDX Provisioning REQUIRED")
		return true
	}
	if _, err := os.Stat(path.Join(p, signingChainFile)); err != nil {
		log.Info("TDX Provisioning REQUIRED")
		return true
	}
	if _, err := os.Stat(path.Join(p, tdxPrivFile)); err != nil {
		log.Info("TDX Provisioning REQUIRED")
		return true
	}

	log.Info("TDX Provisioning NOT REQUIRED")

	return false
}

func loadCredentials(p string) ([]*x509.Certificate, []*x509.Certificate,
	crypto.PrivateKey, error,
) {
	data, err := os.ReadFile(path.Join(p, tdxChainFile))
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

	data, err = os.ReadFile(path.Join(p, tdxPrivFile))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read TDX private key from %v: %w", p, err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse TDX private key: %w", err)
	}

	return akchain, ikchain, priv, nil
}

func saveCredentials(p string, tdx *Tdx) error {
	akchainPem := make([]byte, 0)
	for _, cert := range tdx.akChain {
		c := internal.WriteCertPem(cert)
		akchainPem = append(akchainPem, c...)
	}
	if err := os.WriteFile(path.Join(p, tdxChainFile), akchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(p, tdxChainFile), err)
	}

	ikchainPem := make([]byte, 0)
	for _, cert := range tdx.ikChain {
		c := internal.WriteCertPem(cert)
		ikchainPem = append(ikchainPem, c...)
	}
	if err := os.WriteFile(path.Join(p, signingChainFile), ikchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(p, signingChainFile), err)
	}

	key, err := x509.MarshalPKCS8PrivateKey(tdx.ikPriv)
	if err != nil {
		return fmt.Errorf("failed marshal private key: %w", err)
	}
	if err := os.WriteFile(path.Join(p, tdxPrivFile), key, 0600); err != nil {
		return fmt.Errorf("failed to write %v: %w", path.Join(p, tdxPrivFile), err)
	}

	return nil
}
