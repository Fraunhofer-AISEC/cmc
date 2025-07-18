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
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"

	"golang.org/x/exp/maps"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/prover"
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
	ikChainFile = "tdx_ik_chain.pem"
	ikFile      = "tdx_ik_private.key"

	DEFAULT_CCEL_ACPI_TABLE = "/sys/firmware/acpi/tables/data/CCEL"
)

// Tdx is a structure required for implementing the Measure method
// of the attestation report Measurer interface
type Tdx struct {
	akChain        []*x509.Certificate
	ikChain        []*x509.Certificate
	ikPriv         crypto.PrivateKey
	measurementLog bool
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

		err = tdx.provision(c)
		if err != nil {
			return fmt.Errorf("failed to provision tdx driver: %w", err)
		}

		if c.StoragePath != "" {
			err = tdx.saveCredentials(c.StoragePath)
			if err != nil {
				return fmt.Errorf("failed to save TDX credentials: %w", err)
			}
		}
	} else {
		err = tdx.loadCredentials(c.StoragePath)
		if err != nil {
			return fmt.Errorf("failed to load TDX credentials: %w", err)
		}
	}

	tdx.measurementLog = c.MeasurementLog

	return nil
}

// Measure implements the attestation reports generic Measure interface to be called
// as a plugin during attestation report generation
func (tdx *Tdx) Measure(nonce []byte) (ar.Measurement, error) {

	log.Debug("Collecting TDX measurements")

	if tdx == nil {
		return ar.Measurement{}, errors.New("internal error: TDX object is nil")
	}

	data, err := GetMeasurement(nonce)
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

	// For a more detailed measurement, try to read the CC event log from the CCEL ACPI table
	// and add the values to the measurement artifacts
	if tdx.measurementLog {
		log.Debug("Collecting TDX CCEL measurement log")
		ccel, err := GetCcel(DEFAULT_CCEL_ACPI_TABLE)
		if err != nil {
			log.Warnf("Failed to get CCEL: %v", err)
		}
		measurement.Artifacts = append(measurement.Artifacts, ccel...)
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

func GetMeasurement(nonce []byte) ([]byte, error) {

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

func (tdx *Tdx) provision(c *ar.DriverConfig) error {
	var err error

	// Create new private key for signing
	tdx.ikPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	log.Debug("Retrieving CA certs")
	caCerts, err := c.Provisioner.CaCerts()
	if err != nil {
		return fmt.Errorf("failed to retrieve certs: %w", err)
	}

	// Fetch TDX certificate chain for TDX Attestation Key
	tdx.akChain, err = fetchAk()
	if err != nil {
		return fmt.Errorf("failed to get TDX cert chain: %w", err)
	}

	// Create IK CSR and fetch new certificate including its chain from EST server
	ikCert, err := tdx.provisionIk(tdx.ikPriv, c)
	if err != nil {
		return fmt.Errorf("failed to get signing cert chain: %w", err)
	}

	tdx.ikChain = append([]*x509.Certificate{ikCert}, caCerts...)

	return nil
}

func fetchAk() ([]*x509.Certificate, error) {

	nonce := make([]byte, 64)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce: %w", err)
	}

	// Fetch initial attestation report which contains AK cert chain
	data, err := GetMeasurement(nonce)
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

func (tdx *Tdx) provisionIk(priv crypto.PrivateKey, c *ar.DriverConfig) (*x509.Certificate, error) {

	// Create IK CSR for authentication
	csr, err := ar.CreateCsr(priv, c.DeviceConfig.Tdx.IkCsr)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSRs: %w", err)
	}

	// Use Subject Key Identifier (SKI) as nonce for attestation report
	pubKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR public key: %v", err)
	}
	nonce := sha1.Sum(pubKey)

	// Fetch attestation report as part of client authentication
	report, metadata, err := prover.Generate(nonce[:], nil, c.Metadata, []ar.Driver{tdx}, c.Serializer)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation report: %w", err)
	}
	r, err := c.Serializer.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal the Attestation Report: %v", err)
	}
	signedReport, err := prover.Sign(r, tdx, c.Serializer, ar.IK)
	if err != nil {
		return nil, fmt.Errorf("failed to sign attestation report: %w", err)
	}

	// Request IK certificate from EST server
	cert, err := c.Provisioner.CcEnroll(csr, signedReport, internal.ConvertToArray(metadata))
	if err != nil {
		return nil, fmt.Errorf("failed to enroll IK cert: %w", err)
	}

	return cert, nil
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
	if _, err := os.Stat(path.Join(p, ikChainFile)); err != nil {
		log.Info("TDX Provisioning REQUIRED")
		return true
	}
	if _, err := os.Stat(path.Join(p, ikFile)); err != nil {
		log.Info("TDX Provisioning REQUIRED")
		return true
	}

	log.Info("TDX Provisioning NOT REQUIRED")

	return false
}

func (tdx *Tdx) loadCredentials(p string) error {
	data, err := os.ReadFile(path.Join(p, akChainFile))
	if err != nil {
		return fmt.Errorf("failed to read AK chain from %v: %w", p, err)
	}
	tdx.akChain, err = internal.ParseCertsPem(data)
	if err != nil {
		return fmt.Errorf("failed to parse AK certs: %w", err)
	}
	log.Debugf("Parsed stored AK chain of length %v", len(tdx.akChain))

	data, err = os.ReadFile(path.Join(p, ikChainFile))
	if err != nil {
		return fmt.Errorf("failed to read IK chain from %v: %w", p, err)
	}
	tdx.ikChain, err = internal.ParseCertsPem(data)
	if err != nil {
		return fmt.Errorf("failed to parse IK certs: %w", err)
	}
	log.Debugf("Parsed stored IK chain of length %v", len(tdx.ikChain))

	data, err = os.ReadFile(path.Join(p, ikFile))
	if err != nil {
		return fmt.Errorf("failed to read TDX IK private key from %v: %w", p, err)
	}
	tdx.ikPriv, err = x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return fmt.Errorf("failed to parse TDX IK private key: %w", err)
	}

	return nil
}

func (tdx *Tdx) saveCredentials(p string) error {
	akchainPem := make([]byte, 0)
	for _, cert := range tdx.akChain {
		c := internal.WriteCertPem(cert)
		akchainPem = append(akchainPem, c...)
	}
	if err := os.WriteFile(path.Join(p, akChainFile), akchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(p, akChainFile), err)
	}

	ikchainPem := make([]byte, 0)
	for _, cert := range tdx.ikChain {
		c := internal.WriteCertPem(cert)
		ikchainPem = append(ikchainPem, c...)
	}
	if err := os.WriteFile(path.Join(p, ikChainFile), ikchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(p, ikChainFile), err)
	}

	key, err := x509.MarshalPKCS8PrivateKey(tdx.ikPriv)
	if err != nil {
		return fmt.Errorf("failed marshal private key: %w", err)
	}
	if err := os.WriteFile(path.Join(p, ikFile), key, 0600); err != nil {
		return fmt.Errorf("failed to write %v: %w", path.Join(p, ikFile), err)
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
				Type:   ar.ARTIFACT_TYPE_CC_EVENTLOG,
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
