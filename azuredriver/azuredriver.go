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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/go-jose/go-jose/v4"
	"github.com/sirupsen/logrus"

	"github.com/google/go-tdx-guest/pcs"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type ReportType int

const (
	UNKNOWN ReportType = 0
	SNP     ReportType = 2
	TDX     ReportType = 4
)

type Azure struct {
	akChain []*x509.Certificate
	ikChain []*x509.Certificate
	ikPriv  crypto.PrivateKey
}

type AzureReport struct {
	Header        Header        // The Azure custom report header
	ReportPayload [1184]byte    // The SNP attestation report or TDX TDREPORT
	RuntimeData   RuntimeData   // Runtime data includes claims endorsed by hw report
	RuntimeClaims RuntimeClaims // Runtime claims in JSON format
}

type Header struct {
	Signature   [4]byte  // Expected: 0x414c4348 (HCLA)
	Version     uint32   // Expected: 2
	PayloadSize uint32   // Expected: 1184 (AMD SEV-SNP), 1024 (Intel TDX).
	RequestType uint32   // Expected: 2
	Status      [4]byte  // Reserved
	Reserved    [12]byte // Reserved
}

type RuntimeData struct {
	DataSize   uint32 // Size of runtime data
	Version    uint32 // Format version. Expected: 1
	ReportType uint32 // Expected: 2 (AMD SEV-SNP), 4 (Intel TDX)
	HashType   uint32 // Runtime data hash. Expected: 1 (SHA-256), 2 (SHA-384), 3 (SHA-512)
	ClaimSize  uint32 // The size of the runtime claims
}

type RuntimeClaims struct {
	Keys     []jose.JSONWebKey `json:"keys"`             // Array JWK keys. Expected kid: HCLAkPub (vTPM AK public), HCLEkPub (vTPM EK public)
	VmConfig VmConfig          `json:"vm-configuration"` // Azure confidential VM configuration.
	UserData string            `json:"user-data"`        // Hardware report user data (nonce)
}

type VmConfig struct {
	RootCertThumbPrint string `json:"root-cert-thumbprint"`
	ConsoleEnabled     bool   `json:"console-enabled"`
	SecureBoot         bool   `json:"secure-boot"`
	TpmEnabled         bool   `json:"tpm-enabled"`
	TpmPersisted       bool   `json:"tpm-persisted"`
	VmUniqueId         string `json:"vmUniqueId"`
}

const (
	akChainFile = "azure_ak_chain.pem"
	ikChainFile = "azure_ik_chain.pem"
	ikFile      = "azure_ik_private.key"
)

const (
	imdsEndpoint = "http://169.254.169.254/acc"
	quotePath    = "/tdquote"

	nvIndexTdReport = tpmutil.Handle(0x01400001) // NV index to read
	tpmDevicePath   = "/dev/tpm0"                // TODO reuse tpmdriver code to distinguish between tpmrm0 and tpm0
)

var log = logrus.WithField("service", "azuredriver")

func (azure *Azure) Name() string {
	return "Azure Driver"
}

func (azure *Azure) Init(c *ar.DriverConfig) error {

	var err error

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

		err = azure.provision(c)
		if err != nil {
			return fmt.Errorf("failed to provision azure driver: %w", err)
		}

		if c.StoragePath != "" {
			err = azure.saveCredentials(c.StoragePath)
			if err != nil {
				return fmt.Errorf("failed to save Azure credentials: %w", err)
			}
		}
	} else {
		err = azure.loadCredentials(c.StoragePath)
		if err != nil {
			return fmt.Errorf("failed to load Azure credentials: %w", err)
		}
	}

	return nil
}

func (azure *Azure) Measure(nonce []byte) (ar.Measurement, error) {

	log.Debug("Collecting azure measurements")

	if azure == nil {
		return ar.Measurement{}, errors.New("internal error: TDX object is nil")
	}

	// TODO JWKS
	data, reportType, _, err := GetEvidence()
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to get TDX Measurement: %w", err)
	}

	switch reportType {
	case SNP:
		return azure.createSnpMeasurement(data)
	case TDX:
		return azure.createTdxMeasurement(data)
	}

	return ar.Measurement{}, fmt.Errorf("failed to measure. Unknown report type %v", reportType)
}

func (azure *Azure) createSnpMeasurement(data []byte) (ar.Measurement, error) {
	measurement := ar.Measurement{
		Type:     "SNP Measurement",
		Evidence: data,
		Certs:    internal.WriteCertsDer(azure.akChain),
	}
	return measurement, nil
}

func (azure *Azure) createTdxMeasurement(data []byte) (ar.Measurement, error) {

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
		Certs:    internal.WriteCertsDer(azure.akChain),
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

func (azure *Azure) Lock() error {
	return nil
}

func (azure *Azure) Unlock() error {
	return nil
}

func (azure *Azure) GetKeyHandles(sel ar.KeySelection) (crypto.PrivateKey, crypto.PublicKey, error) {
	if azure == nil {
		return nil, nil, errors.New("internal error: TDX object is nil")
	}

	if sel == ar.AK {
		if len(azure.akChain) == 0 {
			return nil, nil, fmt.Errorf("internal error: TDX AK certificate not present")
		}
		// Only return the public key, as the VCEK / VLEK is not directly accessible
		return nil, azure.akChain[0].PublicKey, nil
	} else if sel == ar.IK {
		return azure.ikPriv, &azure.ikPriv.(*ecdsa.PrivateKey).PublicKey, nil
	}
	return nil, nil, fmt.Errorf("internal error: unknown key selection %v", sel)
}

func (azure *Azure) GetCertChain(keyType ar.KeySelection) ([]*x509.Certificate, error) {
	return nil, nil
}

func GetEvidence() ([]byte, ReportType, []jose.JSONWebKey, error) {

	log.Debugf("Retrieving hardware report (SNP report or TDX quote)...")

	report, reportType, jwks, err := GetAzureHwReport()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get TD report: %v\n", err)
		os.Exit(1)
	}

	switch reportType {
	case SNP:
		return report, SNP, jwks, nil
	case TDX:
		quote, err := GetTdxQuote(report)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("failed to get TDX quote: %w", err)
		}
		return quote, TDX, jwks, nil
	}

	return nil, 0, nil, fmt.Errorf("unknown report type %v. Expected %v or %v", reportType, SNP, TDX)
}

func GetTdxQuote(report []byte) ([]byte, error) {

	encodedReport := base64.RawURLEncoding.EncodeToString(report)
	imdsRequest := fmt.Sprintf(`{"report":"%s"}`, encodedReport)

	quoteResponse, err := FetchTdxQuote(imdsRequest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get quote from IMDS: %v\n", err)
		os.Exit(1)
	}

	log.Debugf("Unmarshalling azure formatted TDX quote..")

	var parsed struct {
		Quote       string `json:"quote"`
		RuntimeData struct {
			Data string `json:"data"`
		} `json:"runtimeData"`
	}
	if err := json.Unmarshal(quoteResponse, &parsed); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse quote JSON: %v\n", err)
		os.Exit(1)
	}

	if parsed.Quote == "" {
		fmt.Fprintf(os.Stderr, "Received empty quote from IMDS\n")
		os.Exit(1)
	}

	quoteBytes, err := base64.RawURLEncoding.DecodeString(parsed.Quote)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode base64url quote: %v\n", err)
		os.Exit(1)
	}

	log.Debugf("Successfully retrieved quote")

	return quoteBytes, nil
}

func GetAzureReport() ([]byte, error) {

	log.Debugf("Fetching azure report from vTPM NVIndex %x...", nvIndexTdReport)

	// Open TPM device
	rwc, err := os.OpenFile(tpmDevicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to open TPM device %s: %w", tpmDevicePath, err)
	}
	defer rwc.Close()

	// Read NV index contents
	data, err := tpm2.NVReadEx(rwc, nvIndexTdReport, tpm2.HandleOwner, "", 0)
	if err != nil {
		return nil, fmt.Errorf("NVRead failed: %w", err)
	}

	log.Debugf("Successfully fetched azure report")

	return data, nil
}

func GetAzureHwReport() ([]byte, ReportType, []jose.JSONWebKey, error) {

	data, err := GetAzureReport()
	if err != nil {
		return nil, UNKNOWN, nil, err
	}

	log.Debugf("Length of azure report: %v", len(data))

	buf := bytes.NewBuffer(data)

	// Parse header
	var header Header
	err = binary.Read(buf, binary.LittleEndian, &header)
	if err != nil {
		return nil, UNKNOWN, nil, fmt.Errorf("failed to decode Azure report header: %w", err)
	}

	log.Debug("Parsed header")
	log.Debugf("\tHeader signature       : %v", string(header.Signature[:]))
	log.Debugf("\tHeader version         : %v", header.Version)
	log.Debugf("\tHeader payload size    : %v", header.PayloadSize)
	log.Debugf("\tHeader request type    : %v", header.RequestType)

	if string(header.Signature[:]) != "HCLA" {
		return nil, UNKNOWN, nil, fmt.Errorf("unexpected header signature %q. Expected %q", string(header.Signature[:]), "HCLA")
	}
	if header.Version != 1 && header.Version != 2 {
		return nil, UNKNOWN, nil, fmt.Errorf("unsupported header version %v. Expected %v, %v", header.Version, 1, 2)
	}
	if header.RequestType != 2 {
		return nil, UNKNOWN, nil, fmt.Errorf("unsupported header request type %v. Expected %v", header.RequestType, 2)
	}

	// Parse payload
	var payload [1184]byte
	err = binary.Read(buf, binary.LittleEndian, &payload)
	if err != nil {
		return nil, UNKNOWN, nil, fmt.Errorf("failed to decode Azure report payload: %w", err)
	}

	// Parse runtime data
	var rtdata RuntimeData
	err = binary.Read(buf, binary.LittleEndian, &rtdata)
	if err != nil {
		return nil, UNKNOWN, nil, fmt.Errorf("failed to decode Azure report payload: %w", err)
	}

	log.Debug("Parsed runtime data")
	log.Debugf("\tRuntimeData data size  : %v", rtdata.DataSize)
	log.Debugf("\tRuntimeData version    : %v", rtdata.Version)
	log.Debugf("\tRuntimeData report type: %v", rtdata.ReportType)
	log.Debugf("\tRuntimeData hash type  : %v", rtdata.HashType)
	log.Debugf("\tRuntimeData claim size : %v", rtdata.ClaimSize)

	if rtdata.Version != 1 {
		return nil, UNKNOWN, nil, fmt.Errorf("unsupported runtime data version %v. Expected %v", rtdata.Version, 1)
	}

	reportLen := 0
	reportType := UNKNOWN
	switch rtdata.ReportType {
	case 2:
		log.Debug("Detected AMD SEV-SNP report")
		reportLen = 1184
		reportType = SNP
	case 4:
		log.Debug("Detected Intel TDX report")
		reportLen = 1024
		reportType = TDX
	default:
		return nil, UNKNOWN, nil, fmt.Errorf("unsupported runtime data report type %v. Expected %v (SNP) or %v (TDX)", rtdata.ReportType, 2, 4)
	}

	// Parse runtime claims
	rawClaims := buf.Bytes()[:rtdata.ClaimSize]
	log.Debugf("Parsing claims size %v", len(rawClaims))
	var claims RuntimeClaims
	err = json.Unmarshal(rawClaims, &claims)
	if err != nil {
		return nil, UNKNOWN, nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	log.Debug("Parsed runtime claims")
	log.Debugf("\tRoot cert thumbprint   : %q", claims.VmConfig.RootCertThumbPrint)
	log.Debugf("\tConsole enabled        : %v", claims.VmConfig.ConsoleEnabled)
	log.Debugf("\tSecure boot enabled    : %v", claims.VmConfig.SecureBoot)
	log.Debugf("\tTPM enabled            : %v", claims.VmConfig.TpmEnabled)
	log.Debugf("\tTPM persisted          : %v", claims.VmConfig.TpmPersisted)
	log.Debugf("\tVM unique ID           : %q", claims.VmConfig.VmUniqueId)
	log.Debugf("\tUser data              : %q", claims.UserData)
	for _, key := range claims.Keys {
		log.Debugf("\tJWK KeyID              : %v", key.KeyID)
	}

	return payload[:reportLen], reportType, claims.Keys, nil
}

func FetchTdxQuote(jsonRequest string) ([]byte, error) {

	url := imdsEndpoint + quotePath

	log.Debugf("Fetching quote from IMDS %v...", url)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(jsonRequest)))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request to IMDS failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IMDS returned non-OK status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read IMDS response body: %w", err)
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("IMDS response was empty")
	}

	log.Debug("Successfully fetched quote")

	return body, nil
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

func (azure *Azure) provision(c *ar.DriverConfig) error {
	var err error

	// Create new private key for signing
	azure.ikPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	log.Debug("Retrieving CA certs")
	caCerts, err := c.Provisioner.CaCerts()
	if err != nil {
		return fmt.Errorf("failed to retrieve certs: %w", err)
	}

	// Fetch TDX certificate chain for TDX Attestation Key
	azure.akChain, err = fetchAk(c)
	if err != nil {
		return fmt.Errorf("failed to get TDX cert chain: %w", err)
	}

	// Create IK CSR and fetch new certificate including its chain from EST server
	ikCert, err := azure.provisionIk(azure.ikPriv, c)
	if err != nil {
		return fmt.Errorf("failed to get signing cert chain: %w", err)
	}

	azure.ikChain = append([]*x509.Certificate{ikCert}, caCerts...)

	return nil
}

func fetchAk(c *ar.DriverConfig) ([]*x509.Certificate, error) {

	// Fetch initial attestation report which contains AK cert chain
	data, reportType, _, err := GetEvidence()
	if err != nil {
		return nil, fmt.Errorf("failed to get TDX Measurement: %w", err)
	}

	switch reportType {
	case SNP:
		return fetchSnpAk(c, data)
	case TDX:
		return fetchTdxAk(data)
	}

	return nil, fmt.Errorf("unknown report type %v. Expected %v or %v", reportType, SNP, TDX)
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

	var akCert *x509.Certificate
	if akType == internal.VCEK {
		// VCEK is used, simply request EST enrollment for SNP chip ID and TCB
		log.Debug("Enrolling VCEK via EST")
		akCert, err = c.Provisioner.GetSnpVcek(s.ChipId, s.CurrentTcb)
		if err != nil {
			return nil, fmt.Errorf("failed to enroll SNP: %w", err)
		}
	} else if akType == internal.VLEK {
		return nil, fmt.Errorf("VLEK is currently not supported for Azure")
	} else {
		return nil, fmt.Errorf("internal error: signing cert not initialized")
	}

	// Fetch intermediate CAs and CA depending on signing key (VLEK / VCEK)
	log.Debugf("Fetching SNP CA for %v from %v", akType.String(), c.ServerAddr)
	ca, err := c.Provisioner.GetSnpCa(akType)
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

func (azure *Azure) provisionIk(priv crypto.PrivateKey, c *ar.DriverConfig) (*x509.Certificate, error) {

	// Create IK CSR for authentication
	csr, err := ar.CreateCsr(priv, c.DeviceConfig.Tdx.IkCsr)
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

func (azure *Azure) loadCredentials(p string) error {
	data, err := os.ReadFile(path.Join(p, akChainFile))
	if err != nil {
		return fmt.Errorf("failed to read AK chain from %v: %w", p, err)
	}
	azure.akChain, err = internal.ParseCertsPem(data)
	if err != nil {
		return fmt.Errorf("failed to parse AK certs: %w", err)
	}
	log.Debugf("Parsed stored AK chain of length %v", len(azure.akChain))

	data, err = os.ReadFile(path.Join(p, ikChainFile))
	if err != nil {
		return fmt.Errorf("failed to read IK chain from %v: %w", p, err)
	}
	azure.ikChain, err = internal.ParseCertsPem(data)
	if err != nil {
		return fmt.Errorf("failed to parse IK certs: %w", err)
	}
	log.Debugf("Parsed stored IK chain of length %v", len(azure.ikChain))

	data, err = os.ReadFile(path.Join(p, ikFile))
	if err != nil {
		return fmt.Errorf("failed to read TDX IK private key from %v: %w", p, err)
	}
	azure.ikPriv, err = x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return fmt.Errorf("failed to parse TDX IK private key: %w", err)
	}

	return nil
}

func (azure *Azure) saveCredentials(p string) error {
	akchainPem := make([]byte, 0)
	for _, cert := range azure.akChain {
		c := internal.WriteCertPem(cert)
		akchainPem = append(akchainPem, c...)
	}
	if err := os.WriteFile(path.Join(p, akChainFile), akchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(p, akChainFile), err)
	}

	ikchainPem := make([]byte, 0)
	for _, cert := range azure.ikChain {
		c := internal.WriteCertPem(cert)
		ikchainPem = append(ikchainPem, c...)
	}
	if err := os.WriteFile(path.Join(p, ikChainFile), ikchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(p, ikChainFile), err)
	}

	key, err := x509.MarshalPKCS8PrivateKey(azure.ikPriv)
	if err != nil {
		return fmt.Errorf("failed marshal private key: %w", err)
	}
	if err := os.WriteFile(path.Join(p, ikFile), key, 0600); err != nil {
		return fmt.Errorf("failed to write %v: %w", path.Join(p, ikFile), err)
	}

	return nil
}
