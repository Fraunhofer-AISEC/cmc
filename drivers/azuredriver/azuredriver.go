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

package azuredriver

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/prover"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/sirupsen/logrus"
)

const (
	akChainFile = "azure_ak_chain.pem"
	ikChainFile = "azure_ik_chain.pem"
	ikFile      = "azure_ik_private.key"
)

var log = logrus.WithField("service", "azuredriver")

type Azure struct {
	*ar.DriverConfig

	// Confidential Computing Parameters
	ccAkChain []*x509.Certificate

	// vTPM Parameters
	pcrs   []int
	ctrLog bool

	ikChain []*x509.Certificate
	ikPriv  crypto.PrivateKey
}

func (azure *Azure) Name() string {
	return "Azure Driver"
}

func (azure *Azure) Init(c *ar.DriverConfig) error {

	// Initial checks
	if azure == nil {
		return errors.New("internal error: Azure object is nil")
	}
	switch c.Serializer.(type) {
	case ar.JsonSerializer:
	case ar.CborSerializer:
	default:
		return fmt.Errorf("serializer not initialized in driver config")
	}

	azure.DriverConfig = c
	azure.pcrs = getQuotePcrs(c.ExcludePcrs)
	azure.ctrLog = c.Ctr && strings.EqualFold(c.CtrDriver, "tpm")

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
		log.Info("Performing Azure provisioning")

		err := azure.provision()
		if err != nil {
			return fmt.Errorf("failed to provision azure driver: %w", err)
		}

		if c.StoragePath != "" {
			err = azure.saveCredentials()
			if err != nil {
				return fmt.Errorf("failed to save Azure credentials: %w", err)
			}
		}
	} else {
		err := azure.loadCredentials()
		if err != nil {
			return fmt.Errorf("failed to load Azure credentials: %w", err)
		}
	}

	return nil
}

func (azure *Azure) Measure(nonce []byte) ([]ar.Measurement, error) {

	log.Debug("Collecting azure measurements")

	if azure == nil {
		return nil, errors.New("internal error: azure object is nil")
	}

	ccMeasurement, err := GetCcMeasurement(nonce, azure.ccAkChain)
	if err != nil {
		return nil, fmt.Errorf("failed to get azure measurement: %w", err)
	}

	vtpmMeasurement, err := azure.GetVtpmMeasurement(azure.pcrs, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get vTPM measurement: %w", err)
	}

	return []ar.Measurement{ccMeasurement, vtpmMeasurement}, nil
}

func (azure *Azure) Lock() error {
	return nil
}

func (azure *Azure) Unlock() error {
	return nil
}

func (azure *Azure) GetKeyHandles(sel ar.KeySelection) (crypto.PrivateKey, crypto.PublicKey, error) {
	if azure == nil {
		return nil, nil, errors.New("internal error: azure object is nil")
	}

	if sel == ar.AK {
		// Return the CC AK chain, as it is required to establish trust. The TPM AK certificate
		// is retrieved from the NVIndex if needed
		if len(azure.ccAkChain) == 0 {
			return nil, nil, fmt.Errorf("internal error: AK certificate not present")
		}
		// Only return the public key, as the VCEK / VLEK is not directly accessible
		return nil, azure.ccAkChain[0].PublicKey, nil
	} else if sel == ar.IK {
		return azure.ikPriv, &azure.ikPriv.(*ecdsa.PrivateKey).PublicKey, nil
	}
	return nil, nil, fmt.Errorf("internal error: unknown key selection %v", sel)
}

func (azure *Azure) GetCertChain(keyType ar.KeySelection) ([]*x509.Certificate, error) {
	if azure == nil {
		return nil, errors.New("internal error: azure object is nil")
	}

	switch keyType {
	case ar.AK:
		// Return the CC AK chain, as it is required to establish trust. The TPM AK certificate
		// is retrieved from the NVIndex if needed
		internal.TraceCertsShort("Returning CC AK cert", azure.ccAkChain)
		return azure.ccAkChain, nil
	case ar.IK:
		internal.TraceCertsShort("Returning IK cert", azure.ikChain)
		return azure.ikChain, nil
	default:
		return nil, fmt.Errorf("internal error: unknown key selection %v", keyType)
	}
}

func (azure *Azure) UpdateCerts() error {
	var err error

	// Initial checks
	if azure == nil {
		return errors.New("internal error: azure object is nil")
	}

	log.Info("Updating azure certificates")

	err = azure.provision()
	if err != nil {
		return fmt.Errorf("failed to provision azure driver: %w", err)
	}

	if azure.StoragePath != "" {
		err = azure.saveCredentials()
		if err != nil {
			return fmt.Errorf("failed to save azure credentials: %w", err)
		}
	}

	return nil
}

func (azure *Azure) UpdateMetadata(metadata map[string][]byte) error {

	// Initial checks
	if azure == nil {
		return errors.New("internal error: azure object is nil")
	}

	log.Info("Updating azure driver metadata")

	azure.Metadata = metadata

	return nil
}

func provisioningRequired(p string) bool {
	// Stateless operation always requires provisioning
	if p == "" {
		log.Info("Aure Provisioning REQUIRED")
		return true
	}

	// If any of the required files is not present, we need to provision
	if _, err := os.Stat(path.Join(p, akChainFile)); err != nil {
		log.Info("Azure Provisioning REQUIRED")
		return true
	}
	if _, err := os.Stat(path.Join(p, ikChainFile)); err != nil {
		log.Info("Azure Provisioning REQUIRED")
		return true
	}
	if _, err := os.Stat(path.Join(p, ikFile)); err != nil {
		log.Info("Azure Provisioning REQUIRED")
		return true
	}

	log.Info("Azure Provisioning NOT REQUIRED")

	return false
}

func (azure *Azure) provision() error {
	var err error

	// Create new private key for signing
	azure.ikPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	log.Debug("Retrieving CA certs")
	caCerts, err := azure.DriverConfig.Provisioner.CaCerts()
	if err != nil {
		return fmt.Errorf("failed to retrieve certs: %w", err)
	}
	for _, c := range caCerts {
		internal.TraceCertShort("Provisioned CA cert", c)
	}

	// Fetch CC certificate chain for Attestation Key
	azure.ccAkChain, err = azure.fetchAk(azure.DriverConfig)
	if err != nil {
		return fmt.Errorf("failed to get azure cert chain: %w", err)
	}
	internal.TraceCertsShort("Provisioned AK cert", azure.ccAkChain)

	// Create IK CSR and fetch new certificate including its chain from EST server
	ikCert, err := azure.provisionIk(azure.ikPriv)
	if err != nil {
		return fmt.Errorf("failed to get signing cert chain: %w", err)
	}

	azure.ikChain = append([]*x509.Certificate{ikCert}, caCerts...)

	internal.TraceCertsShort("Provisioned IK cert", azure.ikChain)

	return nil
}

func (azure *Azure) fetchAk(c *ar.DriverConfig) ([]*x509.Certificate, error) {

	// Fetch initial attestation report which contains AK cert chain
	measurement, err := GetCcMeasurement(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get azure Measurement: %w", err)
	}

	switch measurement.Type {
	case "Azure SNP Measurement":
		return fetchSnpAk(c, measurement.Evidence)
	case "Azure TDX Measurement":
		return fetchTdxAk(measurement.Evidence)
	}

	return nil, fmt.Errorf("unknown report type %v", measurement.Type)
}

func fetchSnpAk(c *ar.DriverConfig, data []byte) ([]*x509.Certificate, error) {

	s, err := verifier.DecodeSnpReport(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SNP report: %w", err)
	}

	akType, err := internal.GetAkType(s.KeySelection)
	if err != nil {
		return nil, fmt.Errorf("could not determine SNP attestation report attestation key")
	}

	log.Debugf("Fetched Chip ID from attestation report: %x", s.ChipId[:])

	codeName := verifier.GetSnpCodeName(s.CpuFamilyId, s.CpuModelId)

	log.Debugf("Fetched EPYC code name from attestation report: %q", codeName)

	var akCert *x509.Certificate
	switch akType {
	case internal.VCEK:
		// VCEK is used, simply request EST enrollment for SNP chip ID and TCB
		log.Debug("Enrolling VCEK via EST")
		akCert, err = c.Provisioner.GetSnpVcek(codeName, s.ChipId, s.CurrentTcb)
		if err != nil {
			return nil, fmt.Errorf("failed to enroll SNP: %w", err)
		}
	case internal.VLEK:
		return nil, fmt.Errorf("VLEK is currently not supported for Azure")
	default:
		return nil, fmt.Errorf("internal error: signing cert not initialized")
	}

	// Fetch intermediate CAs and CA depending on signing key (VLEK / VCEK)
	log.Debugf("Fetching SNP CA for %v from %v", akType.String(), c.ServerAddr)
	ca, err := c.Provisioner.GetSnpCa(codeName, akType)
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP CA from EST server: %w", err)
	}

	return append([]*x509.Certificate{akCert}, ca...), nil
}

func fetchTdxAk(data []byte) ([]*x509.Certificate, error) {
	// Decode attestation report
	quote, err := verifier.DecodeTdxReportV4(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TDX quote: %v", err)
	}

	// Return AK cert chain
	return []*x509.Certificate{
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.PCKCert,
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.IntermediateCert,
		quote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain.RootCACert,
	}, nil
}

func (azure *Azure) provisionIk(priv crypto.PrivateKey) (*x509.Certificate, error) {

	// Retrieve and check FQDN (After the initial provisioning, we do not allow changing the FQDN)
	fqdn, err := internal.Fqdn()
	if err != nil {
		return nil, fmt.Errorf("failed to get FQDN: %v", err)
	}
	if len(azure.ikChain) > 0 && azure.ikChain[0].Subject.CommonName != fqdn {
		return nil, fmt.Errorf("retrieved FQDN (%q) does not match IK CN (%v). Changing the FQDN is not allowed",
			fqdn, azure.ikChain[0].Subject.CommonName)
	}

	// Create IK CSR for authentication
	csr, err := internal.CreateCsr(priv, fqdn, []string{fqdn}, []string{})
	if err != nil {
		return nil, fmt.Errorf("failed to create CSRs: %w", err)
	}

	// Use Subject Key Identifier (SKI) as nonce for attestation report
	pubKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR public key: %v", err)
	}
	nonce := sha1.Sum(pubKey)
	log.Tracef("Created nonce from IK public: %x", nonce)

	// Fetch attestation report as part of client authentication
	report, metadata, err := prover.Generate(nonce[:], nil, azure.DriverConfig.Metadata,
		[]ar.Driver{azure}, azure.DriverConfig.Serializer)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation report: %w", err)
	}
	r, err := azure.DriverConfig.Serializer.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal the Attestation Report: %v", err)
	}
	signedReport, err := prover.Sign(r, azure, azure.DriverConfig.Serializer, ar.IK)
	if err != nil {
		return nil, fmt.Errorf("failed to sign attestation report: %w", err)
	}

	// Request IK certificate from EST server
	cert, err := azure.DriverConfig.Provisioner.CcEnroll(csr, signedReport, internal.ConvertToArray(metadata))
	if err != nil {
		return nil, fmt.Errorf("failed to enroll IK cert: %w", err)
	}

	return cert, nil
}

func (azure *Azure) loadCredentials() error {
	data, err := os.ReadFile(path.Join(azure.StoragePath, akChainFile))
	if err != nil {
		return fmt.Errorf("failed to read AK chain from %v: %w", azure.StoragePath, err)
	}
	azure.ccAkChain, err = internal.ParseCertsPem(data)
	if err != nil {
		return fmt.Errorf("failed to parse AK certs: %w", err)
	}
	log.Debugf("Parsed stored AK chain of length %v", len(azure.ccAkChain))

	data, err = os.ReadFile(path.Join(azure.StoragePath, ikChainFile))
	if err != nil {
		return fmt.Errorf("failed to read IK chain from %v: %w", azure.StoragePath, err)
	}
	azure.ikChain, err = internal.ParseCertsPem(data)
	if err != nil {
		return fmt.Errorf("failed to parse IK certs: %w", err)
	}
	log.Debugf("Parsed stored IK chain of length %v", len(azure.ikChain))

	data, err = os.ReadFile(path.Join(azure.StoragePath, ikFile))
	if err != nil {
		return fmt.Errorf("failed to read IK private key from %v: %w", azure.StoragePath, err)
	}
	azure.ikPriv, err = x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return fmt.Errorf("failed to parse IK private key: %w", err)
	}

	return nil
}

func (azure *Azure) saveCredentials() error {
	akchainPem := make([]byte, 0)
	for _, cert := range azure.ccAkChain {
		c := internal.WriteCertPem(cert)
		akchainPem = append(akchainPem, c...)
	}
	if err := os.WriteFile(path.Join(azure.StoragePath, akChainFile), akchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(azure.StoragePath, akChainFile), err)
	}

	ikchainPem := make([]byte, 0)
	for _, cert := range azure.ikChain {
		c := internal.WriteCertPem(cert)
		ikchainPem = append(ikchainPem, c...)
	}
	if err := os.WriteFile(path.Join(azure.StoragePath, ikChainFile), ikchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(azure.StoragePath, ikChainFile), err)
	}

	key, err := x509.MarshalPKCS8PrivateKey(azure.ikPriv)
	if err != nil {
		return fmt.Errorf("failed marshal private key: %w", err)
	}
	if err := os.WriteFile(path.Join(azure.StoragePath, ikFile), key, 0600); err != nil {
		return fmt.Errorf("failed to write %v: %w", path.Join(azure.StoragePath, ikFile), err)
	}

	return nil
}

func getQuotePcrs(excludedPcrs []int) []int {

	// Use all SRTM PCRs by default
	pcrs := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 23}

	pcrs = internal.FilterInts(pcrs, excludedPcrs)

	return pcrs
}
