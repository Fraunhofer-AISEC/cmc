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
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/google/go-tdx-guest/pcs"
	"github.com/sirupsen/logrus"
)

const (
	akChainFile = "azure_ak_chain.pem"
)

var log = logrus.WithField("service", "azuredriver")

type Azure struct {
	*drivers.DriverConfig

	// Confidential Computing Parameters
	ccAkChain []*x509.Certificate
	fmspc     string
	vmType    string

	// vTPM Parameters
	pcrs   []int
	ctrLog bool
}

func (azure *Azure) Name() string {
	return "Azure Driver"
}

func (azure *Azure) Init(c *drivers.DriverConfig) error {

	// Initial checks
	if azure == nil {
		return errors.New("internal error: Azure object is nil")
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

func (azure *Azure) GetEvidence(nonce []byte) ([]ar.Evidence, error) {

	log.Debug("Collecting azure measurements")

	if azure == nil {
		return nil, errors.New("internal error: azure object is nil")
	}

	ccEvidence, err := GetCcEvidence(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get azure evidence: %w", err)
	}

	vtpmEvidence, err := azure.GetVtpmEvidence(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get vTPM measurement: %w", err)
	}

	return []ar.Evidence{*ccEvidence, *vtpmEvidence}, nil
}

func (azure *Azure) GetCollateral() ([]ar.Collateral, error) {

	ccCollateral, err := azure.GetCcCollateral()
	if err != nil {
		return nil, fmt.Errorf("failed to get CC collateral: %w", err)
	}

	vtpmCollateral, err := azure.GetVtpmCollateral()
	if err != nil {
		return nil, fmt.Errorf("failed to get vTPM collateral: %w", err)
	}

	return []ar.Collateral{*ccCollateral, *vtpmCollateral}, nil
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

	log.Info("Azure Provisioning NOT REQUIRED")

	return false
}

func (azure *Azure) provision() error {
	var err error

	// Fetch CC certificate chain for Attestation Key
	azure.ccAkChain, err = azure.fetchAk(azure.DriverConfig)
	if err != nil {
		return fmt.Errorf("failed to get azure cert chain: %w", err)
	}
	internal.TraceCertsShort("Provisioned AK cert", azure.ccAkChain)

	// Store FMSPC TODO ONLY WORKS WITH TDX
	exts, err := pcs.PckCertificateExtensions(azure.ccAkChain[0])
	if err != nil {
		return fmt.Errorf("failed to get PCK certificate extensions: %w", err)
	}
	azure.fmspc = exts.FMSPC
	log.Tracef("PCK FMSPC: %v", exts.FMSPC)

	return nil
}

func (azure *Azure) fetchAk(c *drivers.DriverConfig) ([]*x509.Certificate, error) {

	// Fetch initial attestation report which contains AK cert chain
	evidence, err := GetCcEvidence(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get azure Measurement: %w", err)
	}

	azure.vmType = evidence.Type

	switch evidence.Type {
	case ar.TYPE_EVIDENCE_AZURE_SNP:
		return fetchSnpAk(c, evidence.Data)
	case ar.TYPE_EVIDENCE_AZURE_TDX:
		return fetchTdxAk(evidence.Data)
	}

	return nil, fmt.Errorf("unknown report type %v", evidence.Type)
}

func fetchSnpAk(c *drivers.DriverConfig, data []byte) ([]*x509.Certificate, error) {

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
		akCert, err = c.Endorser.GetSnpVcek(codeName, s.ChipId, s.CurrentTcb)
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
	ca, err := c.Endorser.GetSnpCa(codeName, akType)
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

	return nil
}

func getQuotePcrs(excludedPcrs []int) []int {

	// Use all SRTM PCRs by default
	pcrs := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 23}

	pcrs = internal.FilterInts(pcrs, excludedPcrs)

	return pcrs
}
