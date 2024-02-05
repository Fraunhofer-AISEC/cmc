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

package attestationreport

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/fxamacker/cbor/v2"
	"github.com/sirupsen/logrus"

	"time"
)

var log = logrus.WithField("service", "ar")

// Driver is an interface representing a driver for a hardware trust anchor,
// capable of providing attestation evidence and signing data. This can be
// e.g. a Trusted Platform Module (TPM), AMD SEV-SNP, or the ARM PSA
// Initial Attestation Service (IAS). The driver must be capable of
// performing measurements, i.e. retrieving attestation evidence such as
// a TPM Quote or an SNP attestation report and providing handles to
// signing keys and their certificate chains
type Driver interface {
	Init(c *DriverConfig) error                                   // Initializes the driver
	Measure(nonce []byte) (Measurement, error)                    // Retrieves measurements
	Lock() error                                                  // For sync, if required
	Unlock() error                                                // For sync, if required
	GetSigningKeys() (crypto.PrivateKey, crypto.PublicKey, error) // Get Signing key handles
	GetCertChain() ([]*x509.Certificate, error)                   // Get cert chain for signing key
}

// DriverConfig contains all configuration values required for the different drivers
type DriverConfig struct {
	StoragePath    string
	ServerAddr     string
	KeyConfig      string
	Metadata       [][]byte
	UseIma         bool
	ImaPcr         int32
	Serializer     Serializer
	MeasurementLog bool
}

// Serializer is a generic interface providing methods for data serialization and
// de-serialization. This enables to generate and verify attestation reports in
// different formats, such as JSON/JWS or CBOR/COSE
type Serializer interface {
	GetPayload(raw []byte) ([]byte, error)
	Marshal(v any) ([]byte, error)
	Unmarshal(data []byte, v any) error
	Sign(report []byte, signer Driver) ([]byte, error)
	VerifyToken(data []byte, roots []*x509.Certificate) (TokenResult, []byte, bool)
}

type PolicyEngineSelect uint32

const (
	PolicyEngineSelect_None    PolicyEngineSelect = 0
	PolicyEngineSelect_JS      PolicyEngineSelect = 1
	PolicyEngineSelect_DukTape PolicyEngineSelect = 2
)

var policyEngines = map[PolicyEngineSelect]PolicyValidator{}

type PolicyValidator interface {
	Validate(policies []byte, result VerificationResult) bool
}

// MetaInfo is a helper struct for generic info
// present in every metadata object
type MetaInfo struct {
	Type    string `json:"type" cbor:"0,keyasint"`
	Name    string `json:"name" cbor:"1,keyasint"`
	Version string `json:"version" cbor:"2,keyasint"`
}

// Validity is a helper struct for 'Validity'
type Validity struct {
	NotBefore string `json:"notBefore" cbor:"0,keyasint"`
	NotAfter  string `json:"notAfter" cbor:"1,keyasint"`
}

// HashChainElem represents the attestation report
// element of type 'Hash Chain' embedded in 'TPM Measurement'
type HashChainElem struct {
	Type      string      `json:"type" cbor:"0,keyasint"`
	Pcr       int32       `json:"pcr,omitempty" cbor:"1,keyasint,omitempty"`
	Sha256    []HexByte   `json:"sha256" cbor:"2,keyasint"`
	Summary   bool        `json:"summary,omitempty" cbor:"3,keyasint,omitempty"` // Indicates if element represents final PCR value or single artifact
	EventName []string    `json:"eventname,omitempty" cbor:"4,keyasint,omitempty"`
	EventData []EventData `json:"eventdata,omitempty" cbor:"5,keyasint,omitempty"`
}

// TpmMeasurement represents the attestation report
// elements of type 'TPM Measurement', 'SNP Measurement', 'TDX Measurement',
// 'SGX Measurement', 'IAS Measurement' or 'SW Measurement'
type Measurement struct {
	Type        string           `json:"type" cbor:"0,keyasint"`
	Evidence    []byte           `json:"evidence" cbor:"1,keyasint"`
	Certs       [][]byte         `json:"certs" cbor:"3,keyasint"`
	Signature   []byte           `json:"signature,omitempty" cbor:"2,keyasint,omitempty"`
	HashChain   []*HashChainElem `json:"hashChain,omitempty" cbor:"4,keyasint,omitempty"`
	Sha256      HexByte          `json:"sha256,omitempty" cbor:"5,keyasint,omitempty"`
	Description string           `json:"description,omitempty" cbor:"6,keyasint,omitempty"`
}

type SnpPolicy struct {
	Type         string `json:"type" cbor:"0,keyasint"`
	SingleSocket bool   `json:"singleSocket" cbor:"1,keyasint"`
	Debug        bool   `json:"debug" cbor:"2,keyasint"`
	Migration    bool   `json:"migration" cbor:"3,keyasint"`
	Smt          bool   `json:"smt" cbor:"4,keyasint"`
	AbiMajor     uint8  `json:"abiMajor" cbor:"5,keyasint"`
	AbiMinor     uint8  `json:"abiMinor" cbor:"6,keyasint"`
}

type SnpFw struct {
	Build uint8 `json:"build" cbor:"0,keyasint"`
	Major uint8 `json:"major" cbor:"1,keyasint"`
	Minor uint8 `json:"minor" cbor:"2,keyasint"`
}

type SnpTcb struct {
	Bl    uint8 `json:"bl" cbor:"0,keyasint"`
	Tee   uint8 `json:"tee" cbor:"1,keyasint"`
	Snp   uint8 `json:"snp" cbor:"2,keyasint"`
	Ucode uint8 `json:"ucode" cbor:"3,keyasint"`
}

type SnpDetails struct {
	Version       uint32    `json:"version" cbor:"0,keyasint"`
	CaFingerprint string    `json:"caFingerprint" cbor:"1,keyasint"`
	Policy        SnpPolicy `json:"policy" cbor:"2,keyasint"`
	Fw            SnpFw     `json:"fw" cbor:"3,keyasint"`
	Tcb           SnpTcb    `json:"tcb" cbor:"4,keyasint"`
}

type IntelCollateral struct {
	TeeType        uint32          `json:"teeType" cbor:"0,keyasint"`
	TcbInfo        json.RawMessage `json:"tcbInfo" cbor:"1,keyasint"`
	TcbInfoSize    uint32          `json:"tcbInfoSize" cbor:"2,keyasint"`
	QeIdentity     json.RawMessage `json:"qeIdentity" cbor:"3,keyasint"`
	QeIdentitySize uint32          `json:"qeIdentitySize" cbor:"4,keyasint"`
}

// RtMrHashChainElem represents the attestation report
// element of type 'HashChain' embedded in 'TDXDetails'
type RtMrHashChainElem struct {
	Type    string    `json:"type" cbor:"0,keyasint"`
	Name    string    `json:"name" cbor:"1,keyasint"`
	Hashes  []HexByte `json:"Hashes" cbor:"2,keyasint"`
	Summary bool      `json:"summary" cbor:"3,keyasint"` // Indicates if element represents final RMTR value or single artifact
}

type TDXDetails struct {
	Version       uint16          `json:"version" cbor:"0,keyasint"`
	Collateral    IntelCollateral `json:"collateral" cbor:"1,keyasint"`
	CaFingerprint string          `json:"caFingerprint" cbor:"2,keyasint"` // Intel Root CA Certificate Fingerprint
	TdId          TDId            `json:"tdId" cbor:"3,keyasint"`
	TdMeas        TDMeasurements  `json:"tdMeasurements" cbor:"4,keyasint"`
	Xfam          [8]byte         `json:"xfam" cbor:"5,keyasint"`
	TdAttributes  TDAttributes    `json:"tdAttributes" cbor:"6,keyasint"`
}

type SGXDetails struct {
	Version       uint16          `json:"version" cbor:"0,keyasint"`
	Collateral    IntelCollateral `json:"collateral" cbor:"1,keyasint"`
	CaFingerprint string          `json:"caFingerprint" cbor:"2,keyasint"` // Intel Root CA Certificate Fingerprint
	IsvProdId     uint16          `json:"isvProdId" cbor:"3,keyasint"`
	MrSigner      string          `json:"mrSigner" cbor:"4,keyasint"`
	IsvSvn        uint16          `json:"isvSvn" cbor:"5,keyasint"`
	Attributes    SGXAttributes   `json:"attributes" cbor:"6,keyasint"`
}

// SGX attributes according to
// https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_Developer_Reference_Linux_2.22_Open_Source.pdf (page 414)
type SGXAttributes struct {
	Initted      bool `json:"initted" cbor:"0,keyasint"`
	Debug        bool `json:"debug" cbor:"1,keyasint"`
	Mode64Bit    bool `json:"mode64Bit" cbor:"2,keyasint"`
	ProvisionKey bool `json:"provisionKey" cbor:"3,keyasint"`
	EInitToken   bool `json:"eInitToken" cbor:"4,keyasint"`
	Kss          bool `json:"kss" cbor:"5,keyasint"`
	Legacy       bool `json:"legacy" cbor:"6,keyasint"`
	Avx          bool `json:"avx" cbor:"7,keyasint"`
}

// Structure of the security relevant attributes for a TD
// (Bits 0 - 31 of attributes array in quote)
// according to https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf (page 40)
type TDAttributes struct {
	Debug         bool `json:"debug" cbor:"0,keyasint"`
	SeptVEDisable bool `json:"septVEDisable" cbor:"1,keyasint"`
	Pks           bool `json:"pks" cbor:"2,keyasint"`
	Kl            bool `json:"kl" cbor:"3,keyasint"`
}

type TDMeasurements struct {
	RtMr0  RtMrHashChainElem `json:"rtMr0" cbor:"0,keyasint"`  // Firmware measurement
	RtMr1  RtMrHashChainElem `json:"rtMr1" cbor:"1,keyasint"`  // BIOS measurement
	RtMr2  RtMrHashChainElem `json:"rtMr2" cbor:"2,keyasint"`  // OS measurement
	RtMr3  RtMrHashChainElem `json:"rtMr3" cbor:"3,keyasint"`  // Runtime measurement
	MrSeam HexByte           `json:"mrSeam" cbor:"4,keyasint"` // TDX Module measurement
}

type TDId struct {
	MrOwner       [48]byte `json:"mrOwner" cbor:"0,keyasint"`
	MrOwnerConfig [48]byte `json:"mrOwnerConfig" cbor:"1,keyasint"`
	MrConfigId    [48]byte `json:"mrConfigId" cbor:"2,keyasint"`
}

// ReferenceValue represents the attestation report
// element of types 'SNP Reference Value', 'TPM Reference Value', 'TDX Reference Value', 'SGX Reference Value'
// and 'SW Reference Value'
type ReferenceValue struct {
	Type        string      `json:"type" cbor:"0,keyasint"`
	Sha256      HexByte     `json:"sha256,omitempty" cbor:"1,keyasint,omitempty"`
	Sha384      HexByte     `json:"sha384,omitempty" cbor:"2,keyasint,omitempty"`
	Name        string      `json:"name,omitempty" cbor:"3,keyasint,omitempty"`
	Pcr         *int        `json:"pcr,omitempty" cbor:"4,keyasint,omitempty"`
	Snp         *SnpDetails `json:"snp,omitempty" cbor:"5,keyasint,omitempty"`
	Tdx         *TDXDetails `json:"tdx,omitempty" cbor:"8,keyasint,omitempty"`
	Sgx         *SGXDetails `json:"sgx,omitempty" cbor:"9,keyasint,omitempty"`
	Description string      `json:"description,omitempty" cbor:"6,keyasint,omitempty"`
	EventData   *EventData  `json:"eventdata,omitempty" cbor:"7,keyasint,omitempty"`
}

// AppDescription represents the attestation report
// element of type 'App Description'
type AppDescription struct {
	MetaInfo
	AppManifest string              `json:"appManifest" cbor:"3,keyasint"` // Links to App Manifest.Name
	External    []ExternalInterface `json:"externalConnections,omitempty" cbor:"4,keyasint,omitempty"`
}

// InternalConnection represents the attestation report
// element of type 'Internal Connection'
type InternalConnection struct {
	Type         string `json:"type" cbor:"0,keyasint"`
	NameAppA     string `json:"nameAppA" cbor:"1,keyasint"`     // Links to AppDescription.Name
	EndpointAppA string `json:"endpointAppA" cbor:"2,keyasint"` // Links to AppManifest.Endpoint
	NameAppB     string `json:"nameAppB" cbor:"3,keyasint"`     // Links to AppDescription.Name
	EndpointAppB string `json:"endpointAppB" cbor:"4,keyasint"` // Links to AppManifest.Endpoint
}

// ExternalInterface represents the attestation report
// element of type 'External Interface'
type ExternalInterface struct {
	Type        string `json:"type" cbor:"0,keyasint"`
	AppEndpoint string `json:"appEndpoint" cbor:"1,keyasint"` // Links to AppManifest.Endpoint
	Interface   string `json:"interface" cbor:"2,keyasint"`   // Links to AppDescription.Name
	Port        int    `json:"port" cbor:"3,keyasint"`        // Links to App Manifest.Endpoint
}

// AppManifest represents the attestation report
// element of type 'App Manifest'
type AppManifest struct {
	MetaInfo
	DevCommonName      string           `json:"developerCommonName"  cbor:"3,keyasint"`
	Oss                []string         `json:"oss" cbor:"4,keyasint"` // Links to OsManifest.Name
	Description        string           `json:"description" cbor:"5,keyasint"`
	CertificationLevel int              `json:"certificationLevel" cbor:"6,keyasint"`
	Validity           Validity         `json:"validity" cbor:"7,keyasint"`
	ReferenceValues    []ReferenceValue `json:"referenceValues" cbor:"8,keyasint"`
}

// OsManifest represents the attestation report
// element of type 'OsManifest'
type OsManifest struct {
	MetaInfo
	DevCommonName      string           `json:"developerCommonName" cbor:"3,keyasint"`
	Rtms               []string         `json:"rtms" cbor:"4,keyasint"` // Links to Type RtmManifest.Name
	Description        string           `json:"description" cbor:"5,keyasint"`
	CertificationLevel int              `json:"certificationLevel" cbor:"6,keyasint"`
	Validity           Validity         `json:"validity" cbor:"7,keyasint"`
	ReferenceValues    []ReferenceValue `json:"referenceValues" cbor:"8,keyasint"`
	Details            any              `json:"details,omitempty" cbor:"9,keyasint,omitempty"`
}

// RtmManifest represents the attestation report
// element of type 'RTM Manifest'
type RtmManifest struct {
	MetaInfo
	DevCommonName      string           `json:"developerCommonName" cbor:"3,keyasint"`
	Description        string           `json:"description" cbor:"4,keyasint"`
	CertificationLevel int              `json:"certificationLevel" cbor:"5,keyasint"`
	Validity           Validity         `json:"validity" cbor:"6,keyasint"`
	ReferenceValues    []ReferenceValue `json:"referenceValues" cbor:"7,keyasint"`
	Details            any              `json:"details,omitempty" cbor:"8,keyasint,omitempty"`
}

// DeviceDescription represents the attestation report
// element of type 'Device Description'
type DeviceDescription struct {
	MetaInfo
	Description     string               `json:"description" cbor:"3,keyasint"`
	Location        string               `json:"location" cbor:"4,keyasint"`
	RtmManifest     string               `json:"rtmManifest" cbor:"5,keyasint"`
	OsManifest      string               `json:"osManifest" cbor:"6,keyasint"`
	AppDescriptions []AppDescription     `json:"appDescriptions" cbor:"7,keyasint"`
	Internal        []InternalConnection `json:"internalConnections" cbor:"8,keyasint"`
	External        []ExternalInterface  `json:"externalEndpoints" cbor:"9,keyasint"`
}

// CompanyDescription represents the attestation report
// element of type 'Company Description'
type CompanyDescription struct {
	MetaInfo
	CertificationLevel int      `json:"certificationLevel" cbor:"3,keyasint"`
	Description        string   `json:"description" cbor:"4,keyasint"`
	Validity           Validity `json:"validity" cbor:"5,keyasint"`
}

// DeviceConfig contains the local device configuration parameters
type DeviceConfig struct {
	MetaInfo
	AkCsr CsrParams `json:"akCsr" cbor:"3,keyasint"`
	IkCsr CsrParams `json:"ikCsr" cbor:"4,keyasint"`
}

// CsrParams contains certificate signing request parameters
type CsrParams struct {
	Subject Name     `json:"subject" cbor:"0,keyasint"`
	SANs    []string `json:"sans,omitempty" cbor:"1,keyasint,omitempty"`
}

// Name is the PKIX Name for CsrParams
type Name struct {
	CommonName         string        `json:"commonName,omitempty" cbor:"0,keyasint,omitempty"`
	Country            string        `json:"country,omitempty" cbor:"1,keyasint,omitempty"`
	Organization       string        `json:"organization,omitempty" cbor:"2,keyasint,omitempty"`
	OrganizationalUnit string        `json:"organizationalUnit,omitempty" cbor:"3,keyasint,omitempty"`
	Locality           string        `json:"locality,omitempty" cbor:"4,keyasint,omitempty"`
	Province           string        `json:"province,omitempty" cbor:"5,keyasint,omitempty"`
	StreetAddress      string        `json:"streetAddress,omitempty" cbor:"6,keyasint,omitempty"`
	PostalCode         string        `json:"postalCode,omitempty" cbor:"7,keyasint,omitempty"`
	Names              []interface{} `json:"names,omitempty" cbor:"8,keyasint,omitempty"`
}

// Metadata is an internal structure for manifests and descriptions
type Metadata struct {
	RtmManifest        RtmManifest         `json:"rtmManifest" cbor:"2,keyasint"`
	OsManifest         OsManifest          `json:"osManifest" cbor:"3,keyasint"`
	AppManifests       []AppManifest       `json:"appManifests,omitempty" cbor:"4,keyasint,omitempty"`
	CompanyDescription *CompanyDescription `json:"companyDescription,omitempty" cbor:"5,keyasint,omitempty"`
	DeviceDescription  DeviceDescription   `json:"deviceDescription" cbor:"6,keyasint"`
}

// AttestationReport represents the attestation report in JWS/COSE format with its
// contents already in signed JWS/COSE format
type AttestationReport struct {
	Type               string        `json:"type" cbor:"0,keyasint"`
	Measurements       []Measurement `json:"measurements,omitempty" cbor:"1,keyasint,omitempty"`
	RtmManifest        []byte        `json:"rtmManifests" cbor:"2,keyasint"`
	OsManifest         []byte        `json:"osManifest" cbor:"3,keyasint"`
	AppManifests       [][]byte      `json:"appManifests,omitempty" cbor:"4,keyasint,omitempty"`
	CompanyDescription []byte        `json:"companyDescription,omitempty" cbor:"5,keyasint,omitempty"`
	DeviceDescription  []byte        `json:"deviceDescription" cbor:"6,keyasint"`
	Nonce              []byte        `json:"nonce" cbor:"7,keyasint"`
}

// Generate generates an attestation report with the provided
// nonce and manifests and descriptions metadata. The manifests and descriptions
// must be either raw JWS tokens in the JWS JSON full serialization
// format or CBOR COSE tokens. Takes a list of measurers providing a method
// for collecting  the measurements from a hardware or software interface
func Generate(nonce []byte, metadata [][]byte, measurers []Driver, s Serializer) ([]byte, error) {

	if s == nil {
		return nil, errors.New("serializer not specified")
	}

	// Create attestation report object which will be filled with the attestation
	// data or sent back incomplete in case errors occur
	ar := AttestationReport{
		Type: "Attestation Report",
	}

	if len(nonce) > 32 {
		return nil, fmt.Errorf("nonce exceeds maximum length of 32 bytes")
	}
	ar.Nonce = nonce

	log.Debug("Adding manifests and descriptions to Attestation Report..")

	// Retrieve the manifests and descriptions
	log.Trace("Parsing ", len(metadata), " meta-data objects..")
	numManifests := 0
	for i := 0; i < len(metadata); i++ {

		// Extract plain payload (i.e. the manifest/description itself)
		data, err := s.GetPayload(metadata[i])
		if err != nil {
			log.Warnf("Failed to parse metadata object %v: %v", i, err)
			continue
		}

		// Unmarshal the Type field of the JSON file to determine the type for
		// later processing
		elem := new(MetaInfo)
		err = s.Unmarshal(data, elem)
		if err != nil {
			log.Warnf("Failed to unmarshal data from metadata object %v: %v", i, err)
			continue
		}

		switch elem.Type {
		case "App Manifest":
			log.Debug("Adding App Manifest")
			ar.AppManifests = append(ar.AppManifests, metadata[i])
			numManifests++
		case "OS Manifest":
			log.Debug("Adding OS Manifest")
			ar.OsManifest = metadata[i]
			numManifests++
		case "RTM Manifest":
			log.Debug("Adding RTM Manifest")
			ar.RtmManifest = metadata[i]
			numManifests++
		case "Device Description":
			log.Debug("Adding Device Description")
			ar.DeviceDescription = metadata[i]
		case "Company Description":
			log.Debug("Adding Company Description")
			ar.CompanyDescription = metadata[i]
		}
	}

	if numManifests == 0 {
		log.Warn("Did not find any manifests for the attestation report")
	} else {
		log.Debug("Added ", numManifests, " manifests to attestation report")
	}

	log.Tracef("Retrieving measurements from %v measurers", len(measurers))
	for _, measurer := range measurers {

		// This actually collects the measurements. The methods are implemented
		// in the respective module (e.g. tpm module)
		log.Trace("Getting measurements from measurement interface..")
		measurement, err := measurer.Measure(nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to get measurements: %v", err)
		}

		ar.Measurements = append(ar.Measurements, measurement)
		log.Tracef("Added %v to attestation report", measurement.Type)
	}

	log.Trace("Finished attestation report generation")

	// Marshal data to bytes
	data, err := s.Marshal(ar)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal the Attestation Report: %v", err)
	}

	return data, nil
}

// Sign signs the attestation report with the specified signer 'signer'
func Sign(report []byte, signer Driver, s Serializer) ([]byte, error) {
	return s.Sign(report, signer)
}

// Verify verifies an attestation report in full serialized JWS
// format against the supplied nonce and CA certificate. Verifies the certificate
// chains of all attestation report elements as well as the measurements against
// the reference values and the compatibility of software artefacts.
func Verify(arRaw, nonce, casPem []byte, policies []byte, polEng PolicyEngineSelect, intelCache string) VerificationResult {
	result := VerificationResult{
		Type:        "Verification Result",
		Success:     true,
		SwCertLevel: 0}

	cas, err := internal.ParseCertsPem(casPem)
	if err != nil {
		result.Success = false
		result.ProcessingError = append(result.ProcessingError,
			fmt.Sprintf("Failed to parse specified CA certificate(s): %v", err))
		return result
	}

	// Detect serialization format
	var s Serializer
	if json.Valid(arRaw) {
		log.Trace("Detected JSON serialization")
		s = JsonSerializer{}
	} else if err := cbor.Valid(arRaw); err == nil {
		log.Trace("Detected CBOR serialization")
		s = CborSerializer{}
	} else {
		result.Success = false
		result.ProcessingError = append(result.ProcessingError,
			"Unable to detect AR serialization format")
		return result
	}

	// Verify and unpack attestation report
	ok, ar := verifyAr(arRaw, &result, cas, s)
	if ar == nil {
		result.InternalError = true
	}
	if !ok {
		result.Success = false
		return result
	}

	// Verify and unpack metadata from attestation report
	ok, metadata := verifyMetadata(ar, &result, cas, s)
	if metadata == nil {
		result.InternalError = true
	}
	if !ok {
		result.Success = false
		return result
	}

	// Verify nonce
	if res := bytes.Compare(ar.Nonce, nonce); res != 0 {
		msg := fmt.Sprintf("Nonces mismatch: SuppliedNonce = %v, AttestationReport Nonce = %v", hex.EncodeToString(nonce), hex.EncodeToString(ar.Nonce))
		result.FreshnessCheck.setFalse(&msg)
		result.Success = false
	} else {
		result.FreshnessCheck.Success = true
	}

	refVals, err := collectReferenceValues(metadata)
	if err != nil {
		result.ProcessingError = append(result.ProcessingError, err.Error())
		result.Success = false
	}

	hwAttest := false
	for _, m := range ar.Measurements {

		switch mtype := m.Type; mtype {

		case "TPM Measurement":
			r, ok := verifyTpmMeasurements(m, nonce, refVals["TPM Reference Value"], cas)
			if !ok {
				result.Success = false
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "SNP Measurement":
			r, ok := verifySnpMeasurements(m, nonce, refVals["SNP Reference Value"])
			if !ok {
				result.Success = false
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "TDX Measurement":
			r, ok := verifyTdxMeasurements(m, nonce, intelCache, refVals["TDX Reference Value"])
			if !ok {
				result.Success = false
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "SGX Measurement":
			r, ok := verifySgxMeasurements(m, nonce, intelCache, refVals["SGX Reference Value"])
			if !ok {
				result.Success = false
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "IAS Measurement":
			r, ok := verifyIasMeasurements(m, nonce,
				refVals["IAS Reference Value"], cas)
			if !ok {
				result.Success = false
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		default:
			result.Success = false
			msg := fmt.Sprintf("Unsupported measurement type '%v'", mtype)
			result.ProcessingError = append(result.ProcessingError, msg)
		}
	}

	// The lowest certification level of all components determines the certification
	// level for the device's software stack
	levels := make([]int, 0)
	levels = append(levels, metadata.RtmManifest.CertificationLevel)
	levels = append(levels, metadata.OsManifest.CertificationLevel)
	for _, app := range metadata.AppManifests {
		levels = append(levels, app.CertificationLevel)
	}
	aggCertLevel := levels[0]
	for _, l := range levels {
		if l < aggCertLevel {
			aggCertLevel = l
		}
	}
	// If no hardware trust anchor is present, the maximum certification level is 1
	// If there are reference values with a higher trust level present, the remote attestation
	// must fail
	if !hwAttest && aggCertLevel > 1 {
		msg := fmt.Sprintf("No hardware trust anchor measurements present but claimed certification level is %v, which requires a hardware trust anchor", aggCertLevel)
		result.ProcessingError = append(result.ProcessingError, msg)
		result.Success = false
	}
	result.SwCertLevel = aggCertLevel

	// Verify the compatibility of the attestation report through verifying the
	// compatibility of all components
	appDescriptions := make([]string, 0)
	for _, a := range metadata.DeviceDescription.AppDescriptions {
		appDescriptions = append(appDescriptions, a.AppManifest)
	}

	// Check that the OS and RTM Manifest are specified in the Device Description
	if metadata.DeviceDescription.RtmManifest == metadata.RtmManifest.Name {
		result.DevDescResult.CorrectRtm.Success = true
	} else {
		msg := fmt.Sprintf("Device Description listed wrong RTM Manifest: %v vs. %v", metadata.DeviceDescription.RtmManifest, metadata.RtmManifest.Name)
		result.DevDescResult.CorrectRtm.setFalse(&msg)
		result.DevDescResult.Summary.Success = false
		result.Success = false
	}
	if metadata.DeviceDescription.OsManifest == metadata.OsManifest.Name {
		result.DevDescResult.CorrectOs.Success = true
	} else {
		msg := fmt.Sprintf("Device Description listed wrong OS Manifest: %v vs. %v", metadata.DeviceDescription.OsManifest, metadata.OsManifest.Name)
		result.DevDescResult.CorrectOs.setFalse(&msg)
		result.DevDescResult.Summary.Success = false
		result.Success = false
	}

	// Check that every AppManifest has a corresponding AppDescription
	result.DevDescResult.CorrectApps.Success = true
	for _, a := range metadata.AppManifests {
		if !contains(a.Name, appDescriptions) {
			msg := fmt.Sprintf("Device Description does not list the following App Manifest: %v", a.Name)
			result.DevDescResult.CorrectApps.setFalseMulti(&msg)
			result.DevDescResult.Summary.Success = false
			result.Success = false
		}
	}

	// Check that the Rtm Manifest is compatible with the OS Manifest
	if contains(metadata.RtmManifest.Name, metadata.OsManifest.Rtms) {
		result.DevDescResult.RtmOsCompatibility.Success = true
	} else {
		msg := fmt.Sprintf("RTM Manifest %v is not compatible with OS Manifest %v", metadata.RtmManifest.Name, metadata.OsManifest.Name)
		result.DevDescResult.RtmOsCompatibility.setFalse(&msg)
		result.DevDescResult.Summary.Success = false
		result.Success = false
	}

	// Check that the OS Manifest is compatible with all App Manifests
	result.DevDescResult.OsAppsCompatibility.Success = true
	for _, a := range metadata.AppManifests {
		if !contains(metadata.OsManifest.Name, a.Oss) {
			msg := fmt.Sprintf("OS Manifest %v is not compatible with App Manifest %v", metadata.OsManifest.Name, a.Name)
			result.DevDescResult.OsAppsCompatibility.setFalseMulti(&msg)
			result.DevDescResult.Summary.Success = false
			result.Success = false
		}
	}

	// Validate policies if specified
	if policies != nil {
		result.PolicySuccess = true

		p, ok := policyEngines[polEng]
		if !ok {
			msg := fmt.Sprintf("Internal error: policy engine %v not implemented", polEng)
			result.ProcessingError = append(result.ProcessingError, msg)
			log.Trace(msg)
			result.Success = false
		} else {
			ok = p.Validate(policies, result)
			if !ok {
				result.Success = false
				msg := "Custom policy validation failed"
				result.ProcessingError = append(result.ProcessingError, msg)
				log.Warnf(msg)
			}
		}
	} else {
		log.Tracef("No custom policies specified")
	}

	// Add additional information
	result.Prover = metadata.DeviceDescription.Name
	result.Created = time.Now().Format(time.RFC3339)

	log.Tracef("Verification Result: %v", result.Success)

	return result
}

func extendHash(hash []byte, data []byte) []byte {
	concat := append(hash, data...)
	h := sha256.Sum256(concat)
	ret := make([]byte, 32)
	copy(ret, h[:])
	return ret
}

func extendHash384(hash []byte, data []byte) []byte {
	concat := append(hash, data...)
	h := sha512.Sum384(concat)
	ret := make([]byte, 48)
	copy(ret, h[:])
	return ret
}

func verifyAr(attestationReport []byte, result *VerificationResult,
	cas []*x509.Certificate, s Serializer,
) (bool, *AttestationReport) {

	if result == nil {
		log.Warn("Provided Validation Result was nil")
		return false, nil
	}

	ar := AttestationReport{}

	//Validate Attestation Report signature
	tokenRes, payload, ok := s.VerifyToken(attestationReport, cas)
	result.ReportSignature = tokenRes.SignatureCheck
	if !ok {
		log.Trace("Validation of Attestation Report failed")
		result.Success = false
		return false, &ar
	}

	err := s.Unmarshal(payload, &ar)
	if err != nil {
		msg := fmt.Sprintf("Parsing of Attestation Report failed: %v", err)
		result.ProcessingError = append(result.ProcessingError, msg)
		log.Trace(msg)
		result.Success = false
		return false, &ar
	}

	return true, &ar
}

func verifyMetadata(ar *AttestationReport, result *VerificationResult,
	cas []*x509.Certificate, s Serializer,
) (bool, *Metadata) {

	metadata := Metadata{}

	// Validate and unpack Rtm Manifest
	tokenRes, payload, ok := s.VerifyToken(ar.RtmManifest, cas)
	result.RtmResult.Summary = tokenRes.Summary
	result.RtmResult.SignatureCheck = tokenRes.SignatureCheck
	if !ok {
		log.Trace("Validation of RTM Manifest failed")
		result.Success = false
	} else {
		err := s.Unmarshal(payload, &metadata.RtmManifest)
		if err != nil {
			msg := fmt.Sprintf("Unpacking of RTM Manifest failed: %v", err)
			result.RtmResult.Summary.setFalseMulti(&msg)
			result.Success = false
		} else {
			result.RtmResult.Name = metadata.RtmManifest.Name
			result.RtmResult.Version = metadata.RtmManifest.Version
			result.RtmResult.ValidityCheck = checkValidity(metadata.RtmManifest.Validity)
			result.RtmResult.Details = metadata.RtmManifest.Details
			if !result.RtmResult.ValidityCheck.Success {
				result.RtmResult.Summary.Success = false
				result.Success = false
			}
		}
	}

	// Validate and unpack OS Manifest
	tokenRes, payload, ok = s.VerifyToken(ar.OsManifest, cas)
	result.OsResult.Summary = tokenRes.Summary
	result.OsResult.SignatureCheck = tokenRes.SignatureCheck
	if !ok {
		log.Trace("Validation of OS Manifest failed")
		result.Success = false
	} else {
		err := s.Unmarshal(payload, &metadata.OsManifest)
		if err != nil {
			msg := fmt.Sprintf("Unpacking of OS Manifest failed: %v", err)
			result.OsResult.Summary.setFalseMulti(&msg)
			result.Success = false
		} else {
			result.OsResult.Name = metadata.OsManifest.Name
			result.OsResult.Version = metadata.OsManifest.Version
			result.OsResult.ValidityCheck = checkValidity(metadata.OsManifest.Validity)
			result.OsResult.Details = metadata.OsManifest.Details
			if !result.OsResult.ValidityCheck.Success {
				result.OsResult.Summary.Success = false
				result.Success = false
			}
		}
	}

	// Validate and unpack App Manifests
	for i, amSigned := range ar.AppManifests {
		result.AppResults = append(result.AppResults, ManifestResult{})

		tokenRes, payload, ok = s.VerifyToken(amSigned, cas)
		result.AppResults[i].Summary = tokenRes.Summary
		result.AppResults[i].SignatureCheck = tokenRes.SignatureCheck
		if !ok {
			log.Trace("Validation of App Manifest failed")
			result.Success = false
		} else {
			var am AppManifest
			err := s.Unmarshal(payload, &am)
			if err != nil {
				msg := fmt.Sprintf("Unpacking of App Manifest failed: %v", err)
				result.AppResults[i].Summary.setFalseMulti(&msg)
				result.Success = false
			} else {
				metadata.AppManifests = append(metadata.AppManifests, am)
				result.AppResults[i].Name = am.Name
				result.AppResults[i].Version = am.Version
				result.AppResults[i].ValidityCheck = checkValidity(am.Validity)
				if !result.AppResults[i].ValidityCheck.Success {
					log.Trace("App Manifest invalid - " + am.Name)
					result.AppResults[i].Summary.Success = false
					result.Success = false

				}
			}
		}
	}

	// Validate and unpack Company Description if present
	if ar.CompanyDescription != nil {
		tokenRes, payload, ok = s.VerifyToken(ar.CompanyDescription, cas)
		result.CompDescResult = &CompDescResult{}
		result.CompDescResult.Summary = tokenRes.Summary
		result.CompDescResult.SignatureCheck = tokenRes.SignatureCheck
		if !ok {
			log.Trace("Validation of Company Description Signatures failed")
			result.Success = false
		} else {
			err := s.Unmarshal(payload, &metadata.CompanyDescription)
			if err != nil {
				msg := fmt.Sprintf("Unpacking of Company Description failed: %v", err)
				result.CompDescResult.Summary.setFalseMulti(&msg)
				result.Success = false
			} else {
				result.CompDescResult.Name = metadata.CompanyDescription.Name
				result.CompDescResult.Version = metadata.CompanyDescription.Version
				result.CompDescResult.CompCertLevel = metadata.CompanyDescription.CertificationLevel

				result.CompDescResult.ValidityCheck = checkValidity(metadata.CompanyDescription.Validity)
				if !result.CompDescResult.ValidityCheck.Success {
					log.Trace("Company Description invalid")
					result.CompDescResult.Summary.Success = false
					result.Success = false
				}
			}
		}
	}

	// Validate and unpack Device Description
	tokenRes, payload, ok = s.VerifyToken(ar.DeviceDescription, cas)
	result.DevDescResult.Summary = tokenRes.Summary
	result.DevDescResult.SignatureCheck = tokenRes.SignatureCheck
	if !ok {
		log.Trace("Validation of Device Description failed")
		result.Success = false
	} else {
		err := s.Unmarshal(payload, &metadata.DeviceDescription)
		if err != nil {
			msg := fmt.Sprintf("Unpacking of Device Description failed: %v", err)
			result.DevDescResult.Summary.setFalseMulti(&msg)
		} else {
			result.DevDescResult.Name = metadata.DeviceDescription.Name
			result.DevDescResult.Version = metadata.DeviceDescription.Version
			result.DevDescResult.Description = metadata.DeviceDescription.Description
			result.DevDescResult.Location = metadata.DeviceDescription.Location
		}
	}

	return true, &metadata
}

func checkValidity(val Validity) Result {
	result := Result{}
	result.Success = true

	notBefore, err := time.Parse(time.RFC3339, val.NotBefore)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse NotBefore time. Time.Parse returned %v", err)
		result.setFalse(&msg)
		return result
	}
	notAfter, err := time.Parse(time.RFC3339, val.NotAfter)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse NotAfter time. Time.Parse returned %v", err)
		result.setFalse(&msg)
		return result
	}
	currentTime := time.Now()

	if notBefore.After(currentTime) {
		msg := "Validity check failed: Artifact is not valid yet"
		result.setFalse(&msg)
	}

	if currentTime.After(notAfter) {
		msg := "Validity check failed: Artifact validity has expired"
		result.setFalse(&msg)
	}

	return result
}

// Searches for a specific hash value in the reference values for RTM and OS
func getReferenceValue(hash []byte, refVals []ReferenceValue) *ReferenceValue {
	for _, ver := range refVals {
		if bytes.Equal(ver.Sha256, hash) {
			return &ver
		}
	}
	return nil
}

func collectReferenceValues(metadata *Metadata) (map[string][]ReferenceValue, error) {
	// Gather a list of all reference values independent of the type
	verList := append(metadata.RtmManifest.ReferenceValues, metadata.OsManifest.ReferenceValues...)
	for _, appManifest := range metadata.AppManifests {
		verList = append(verList, appManifest.ReferenceValues...)
	}

	verMap := make(map[string][]ReferenceValue)

	// Iterate through the reference values and sort them into the different types
	for _, v := range verList {
		if v.Type != "SNP Reference Value" && v.Type != "SW Reference Value" && v.Type != "TPM Reference Value" && v.Type != "TDX Reference Value" && v.Type != "SGX Reference Value" {
			return nil, fmt.Errorf("reference value of type %v is not supported", v.Type)
		}
		verMap[v.Type] = append(verMap[v.Type], v)
	}
	return verMap, nil
}

func checkExtensionUint8(cert *x509.Certificate, oid string, value uint8) error {

	for _, ext := range cert.Extensions {

		if ext.Id.String() == oid {
			if len(ext.Value) != 3 && len(ext.Value) != 4 {
				return fmt.Errorf("extension %v value unexpected length %v (expected 3 or 4)", oid, len(ext.Value))
			}
			if ext.Value[0] != 0x2 {
				return fmt.Errorf("extension %v value[0] = %v does not match expected value 2 (tag Integer)", oid, ext.Value[0])
			}
			if ext.Value[1] == 0x1 {
				if ext.Value[2] != value {
					return fmt.Errorf("extension %v value[2] = %v does not match expected value %v", oid, ext.Value[2], value)
				}
			} else if ext.Value[1] == 0x2 {
				// Due to openssl, the sign bit must remain zero for positive integers
				// even though this field is defined as unsigned int in the AMD spec
				// Thus, if the most significant bit is required, one byte of additional 0x00 padding is added
				if ext.Value[2] != 0x00 || ext.Value[3] != value {
					return fmt.Errorf("extension %v value = %v%v does not match expected value  %v", oid, ext.Value[2], ext.Value[3], value)
				}
			} else {
				return fmt.Errorf("extension %v value[1] = %v does not match expected value 1 or 2 (length of integer)", oid, ext.Value[1])
			}
			return nil
		}
	}

	return fmt.Errorf("extension %v not present in certificate", oid)
}

func checkExtensionBuf(cert *x509.Certificate, oid string, buf []byte) error {

	for _, ext := range cert.Extensions {

		if ext.Id.String() == oid {
			if cmp := bytes.Compare(ext.Value, buf); cmp != 0 {
				return fmt.Errorf("extension %v value %v does not match expected value %v", oid, hex.EncodeToString(ext.Value), hex.EncodeToString(buf))
			}
			return nil
		}
	}

	return fmt.Errorf("extension %v not present in certificate", oid)
}

func contains(elem string, list []string) bool {
	for _, s := range list {
		if s == elem {
			return true
		}
	}
	return false
}

func (r *Result) setFalse(msg *string) {
	r.Success = false
	if msg != nil {
		r.Details = *msg
		log.Trace(*msg)
	}
}

func (r *ResultMulti) setFalseMulti(msg *string) {
	r.Success = false
	if msg != nil {
		r.Details = append(r.Details, *msg)
		log.Trace(*msg)
	}
}
