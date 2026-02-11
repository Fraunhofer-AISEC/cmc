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

//go:build amd64 && (!nodefaults || tdx)

package tdxdriver

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"

	"golang.org/x/exp/maps"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/report"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
	"github.com/google/go-tdx-guest/pcs"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "tdxdriver")

const (
	akChainFile = "tdx_ak_chain.pem"

	DEFAULT_CCEL_ACPI_TABLE = "/sys/firmware/acpi/tables/data/CCEL"
)

// Tdx is a structure required for implementing the Measure method
// of the attestation report Measurer interface
type Tdx struct {
	*drivers.DriverConfig
	akChain []*x509.Certificate
	fmspc   string
}

// Name returns the name of the driver
func (s *Tdx) Name() string {
	return "TDX driver"
}

// Init initializes the TDX driver with the specifified configuration
func (tdx *Tdx) Init(c *drivers.DriverConfig) error {
	var err error

	// Initial checks
	if tdx == nil {
		return errors.New("internal error: TDX object is nil")
	}

	tdx.DriverConfig = c

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

		err = tdx.provision()
		if err != nil {
			return fmt.Errorf("failed to provision tdx driver: %w", err)
		}

		if c.StoragePath != "" {
			err = tdx.saveCredentials()
			if err != nil {
				return fmt.Errorf("failed to save TDX credentials: %w", err)
			}
		}
	} else {
		err = tdx.loadCredentials()
		if err != nil {
			return fmt.Errorf("failed to load TDX credentials: %w", err)
		}
	}

	return nil
}

func (tdx *Tdx) GetEvidence(nonce []byte) ([]ar.Evidence, error) {

	log.Debug("Collecting TDX evidence")

	if tdx == nil {
		return nil, errors.New("internal error: TDX object is nil")
	}

	data, err := GetReport(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get TDX Measurement: %w", err)
	}

	evidence := ar.Evidence{
		Type: ar.TYPE_EVIDENCE_TDX,
		Data: data,
	}

	return []ar.Evidence{evidence}, nil
}

func (tdx *Tdx) GetCollateral() ([]ar.Collateral, error) {

	// Fetch tdx collateral
	tdxCollateral, err := verifier.FetchCollateral(tdx.fmspc, tdx.akChain[0], verifier.TDX_QUOTE_TYPE)
	if err != nil {
		return nil, fmt.Errorf("failed to get TDX collateral: %w", err)
	}

	collateral := ar.Collateral{
		Type:  ar.TYPE_EVIDENCE_TDX,
		Certs: internal.WriteCertsDer(tdx.akChain),
		Artifacts: []ar.Artifact{
			{
				Type: ar.TYPE_TDX_COLLATERAL,
				Events: []ar.MeasureEvent{
					{
						IntelCollateral: tdxCollateral,
					},
				},
			},
		},
	}

	// For a more detailed measurement, try to read the CC event log from the CCEL ACPI table
	// and add the values to the measurement artifacts
	if tdx.MeasurementLogs {
		log.Debug("Collecting TDX CCEL measurement log")
		ccel, err := GetCcel(DEFAULT_CCEL_ACPI_TABLE)
		if err != nil {
			log.Warnf("Failed to get CCEL: %v", err)
		}
		collateral.Artifacts = append(collateral.Artifacts, ccel...)
	}

	return []ar.Collateral{collateral}, nil
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

func GetReport(nonce []byte) ([]byte, error) {

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

func (tdx *Tdx) UpdateCerts() error {
	var err error

	// Initial checks
	if tdx == nil {
		return errors.New("internal error: TDX object is nil")
	}

	log.Info("Updating TDX certificates")

	err = tdx.provision()
	if err != nil {
		return fmt.Errorf("failed to provision tdx driver: %w", err)
	}

	if tdx.StoragePath != "" {
		err = tdx.saveCredentials()
		if err != nil {
			return fmt.Errorf("failed to save TDX credentials: %w", err)
		}
	}

	return nil
}

func (tdx *Tdx) provision() error {
	var err error

	// Fetch TDX certificate chain for TDX Attestation Key
	tdx.akChain, err = fetchAk()
	if err != nil {
		return fmt.Errorf("failed to get TDX cert chain: %w", err)
	}

	// Store FMSPC
	exts, err := pcs.PckCertificateExtensions(tdx.akChain[0])
	if err != nil {
		return fmt.Errorf("failed to get PCK certificate extensions: %w", err)
	}
	tdx.fmspc = exts.FMSPC
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
	data, err := GetReport(nonce)
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

func provisioningRequired(p string) bool {
	// Stateless operation always requires provisioning
	if p == "" {
		log.Info("TDX Provisioning REQUIRED")
		return true
	}

	// If any of the required files is not present, we need to provision
	if _, err := os.Stat(path.Join(p, akChainFile)); err != nil {
		log.Info("TDX Provisioning REQUIRED")
		return true
	}

	log.Info("TDX Provisioning NOT REQUIRED")

	return false
}

func (tdx *Tdx) loadCredentials() error {
	data, err := os.ReadFile(path.Join(tdx.StoragePath, akChainFile))
	if err != nil {
		return fmt.Errorf("failed to read AK chain from %v: %w", tdx.StoragePath, err)
	}
	tdx.akChain, err = internal.ParseCertsPem(data)
	if err != nil {
		return fmt.Errorf("failed to parse AK certs: %w", err)
	}
	log.Debugf("Parsed stored AK chain of length %v", len(tdx.akChain))

	return nil
}

func (tdx *Tdx) saveCredentials() error {
	akchainPem := make([]byte, 0)
	for _, cert := range tdx.akChain {
		c := internal.WriteCertPem(cert)
		akchainPem = append(akchainPem, c...)
	}
	if err := os.WriteFile(path.Join(tdx.StoragePath, akChainFile), akchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(tdx.StoragePath, akChainFile), err)
	}

	return nil
}

func GetCcel(path string) ([]ar.Artifact, error) {

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}

	log.Tracef("Parsing CCEL eventlog: %v", path)

	eventlog, err := tcg.ParseEventLog(data, tcg.ParseOpts{AllowPadding: true})
	if err != nil {
		return nil, fmt.Errorf("failed to parse CC eventlog: %w", err)
	}

	log.Tracef("Adding %v events to CCEL artifacts", len(eventlog.Events(register.HashSHA384)))
	artifactsMap := map[int]ar.Artifact{}
	for _, event := range eventlog.Events(register.HashSHA384) {

		index := int(event.MRIndex())
		if _, ok := artifactsMap[index]; !ok {
			log.Tracef("Adding new artifact for index %v", index)
			artifactsMap[index] = ar.Artifact{
				Type:   ar.TYPE_CC_EVENTLOG,
				Index:  index,
				Events: []ar.MeasureEvent{},
			}
		}

		measureEvent := ar.MeasureEvent{
			Sha384:      event.Digest,
			EventName:   event.Type.String(),
			Description: internal.FormatRtmrData(event.Data),
		}

		log.Tracef("Adding %v %v: %v", internal.IndexToMr(index), measureEvent.EventName,
			hex.EncodeToString(measureEvent.Sha384))

		artifact := artifactsMap[index]
		artifact.Events = append(artifact.Events, measureEvent)
		artifactsMap[index] = artifact
	}

	artifacts := maps.Values(artifactsMap)

	// Sort artifacts by index
	sort.Slice(artifacts, func(i, j int) bool {
		return artifacts[i].Index < artifacts[j].Index
	})

	log.Tracef("Returning %v artifacts", len(artifacts))

	return artifacts, nil
}
