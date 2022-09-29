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
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	log "github.com/sirupsen/logrus"

	"time"
)

// Measurement is a generic interface for a Measurement, such as a TpmMeasurement
type Measurement interface{}

// Measurer is an interface implementing the Measure method for each type of measurement
// Each type of interface that is capable of providing measurements (such
// as the tpmw module) is expected to implement this method. The
// attestationreport module will call this method to retrieve the measurements
// of the platform during attestation report generation.
type Measurer interface {
	Measure(nonce []byte) (Measurement, error)
}

// Signer is a generic interface for an entity capable of signing an attestation report,
// such as a TPM or other hardware interface
type Signing interface{}

type Signer interface {
	Lock()
	Unlock()
	GetSigningKeys() (crypto.PrivateKey, crypto.PublicKey, error)
	GetCertChain() CertChain
}

// Serializer is a generic interface providing methods for data serialization and
// de-serialization. This enables to generate and verify attestation reports in
// different formats, such as JSON/JWS or CBOR/COSE
type Serializer interface {
	GetPayload(raw []byte) ([]byte, error)
	Marshal(v any) ([]byte, error)
	Unmarshal(data []byte, v any) error
	Sign(report []byte, signer Signer) (bool, []byte)
	VerifyToken(data []byte, roots []*x509.Certificate) (JwsResult, []byte, bool)
}

type Policies interface{}

type PolicyValidator interface {
	Validate(result VerificationResult) error
}

// Type is a helper struct for just extracting the 'Type' of metadata
type Type struct {
	Type string `json:"type" cbor:"0,keyasint"`
}

// Validity is a helper struct for 'Validity'
type Validity struct {
	NotBefore string `json:"notBefore" cbor:"0,keyasint"`
	NotAfter  string `json:"notAfter" cbor:"1,keyasint"`
}

const timeLayout = "20060102150405"

// HashChainElem represents the attestation report
// element of type 'Hash Chain' embedded in 'TPM Measurement'
type HashChainElem struct {
	Type   string    `json:"type" cbor:"0,keyasint"`
	Pcr    int32     `json:"pcr" cbor:"1,keyasint"`
	Sha256 []HexByte `json:"sha256" cbor:"2,keyasint"`
}

// CertChain is a helper struct for certificate chains,
// consisting of a leaf certificate, an arbitrary number
// of intermediate (sub-CA) certificates and a CA certificate
type CertChain struct {
	Leaf          []byte   `json:"leaf" cbor:"0,keyasint"`
	Intermediates [][]byte `json:"intermediates" cbor:"1,keyasint"`
	Ca            []byte   `json:"ca" cbor:"2,keyasint"`
}

// TpmMeasurement represents the attestation report
// element of type 'TPM Measurement'
type TpmMeasurement struct {
	Type      string           `json:"type" cbor:"0,keyasint"`
	Message   HexByte          `json:"message" cbor:"1,keyasint"`
	Signature HexByte          `json:"signature" cbor:"2,keyasint"`
	Certs     CertChain        `json:"certs" cbor:"3,keyasint"`
	HashChain []*HashChainElem `json:"hashChain" cbor:"4,keyasint"`
}

// SnpMeasurement represents the attestation report
// element of type 'SNP Measurement' signed by the device
type SnpMeasurement struct {
	Type   string    `json:"type" cbor:"0,keyasint"`
	Report []byte    `json:"blob" cbor:"1,keyasint"`
	Certs  CertChain `json:"certs" cbor:"2,keyasint"`
}

// SwMeasurement represents the attestation report
// element of type 'Software Measurement'
type SwMeasurement struct {
	Type   string  `json:"type" cbor:"0,keyasint"`
	Name   string  `json:"name" cbor:"1,keyasint"`
	Sha256 HexByte `json:"sha256" cbor:"2,keyasint"`
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
	Version uint32    `json:"version" cbor:"0,keyasint"`
	KeyId   string    `json:"caKeyId" cbor:"1,keyasint"`
	Policy  SnpPolicy `json:"policy" cbor:"2,keyasint"`
	Fw      SnpFw     `json:"fw" cbor:"3,keyasint"`
	Tcb     SnpTcb    `json:"tcb" cbor:"4,keyasint"`
}

// Verification represents the attestation report
// element of types 'SNP Verification', 'TPM Verification'
// and 'SW Verification'
type Verification struct {
	Type   string      `json:"type" cbor:"0,keyasint,omitempty"`
	Sha256 HexByte     `json:"sha256,omitempty" cbor:"1,keyasint,omitempty"`
	Sha384 HexByte     `json:"sha384,omitempty" cbor:"2,keyasint,omitempty"`
	Name   string      `json:"name,omitempty" cbor:"3,keyasint,omitempty"`
	Pcr    *int        `json:"pcr,omitempty" cbor:"4,keyasint,omitempty"`
	Snp    *SnpDetails `json:"snp,omitempty" cbor:"5,keyasint,omitempty"`
}

// AppDescription represents the attestation report
// element of type 'App Description'
type AppDescription struct {
	Type        string              `json:"type"`
	Name        string              `json:"name"`
	AppManifest string              `json:"appManifest" cbor:"0,keyasint,omitempty"` // Links to App Manifest.Name
	External    []ExternalInterface `json:"externalConnections" cbor:"0,keyasint"`
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
	Type        string `json:"type"  cbor:"0,keyasint"`
	AppEndpoint string `json:"appEndpoint"  cbor:"1,keyasint"` // Links to AppManifest.Endpoint
	Interface   string `json:"interface"  cbor:"2,keyasint"`   // Links to AppDescription.Name
	Port        int    `json:"port"  cbor:"3,keyasint"`        // Links to App Manifest.Endpoint
}

// AppManifest represents the attestation report
// element of type 'App Manifest'
type AppManifest struct {
	Type               string         `json:"type"  cbor:"0,keyasint"`
	Name               string         `json:"name"  cbor:"1,keyasint"`
	DevCommonName      string         `json:"developerCommonName"  cbor:"2,keyasint"`
	Version            string         `json:"version"  cbor:"3,keyasint"`
	Oss                []string       `json:"oss"  cbor:"4,keyasint"` // Links to OsManifest.Name
	Description        string         `json:"description"  cbor:"5,keyasint"`
	CertificationLevel int            `json:"certificationLevel"  cbor:"6,keyasint"`
	Validity           Validity       `json:"validity"  cbor:"7,keyasint"`
	Verifications      []Verification `json:"verifications"  cbor:"8,keyasint"`
}

// OsManifest represents the attestation report
// element of type 'OsManifest'
type OsManifest struct {
	Type               string         `json:"type"  cbor:"0,keyasint"`
	Name               string         `json:"name"  cbor:"1,keyasint"`
	DevCommonName      string         `json:"developerCommonName"  cbor:"2,keyasint"`
	Version            string         `json:"version"  cbor:"3,keyasint"`
	Rtms               []string       `json:"rtms"  cbor:"4,keyasint"` // Links to Type RtmManifest.Name
	Description        string         `json:"description"  cbor:"5,keyasint"`
	CertificationLevel int            `json:"certificationLevel"  cbor:"6,keyasint"`
	Validity           Validity       `json:"validity"  cbor:"7,keyasint"`
	Verifications      []Verification `json:"verifications"  cbor:"8,keyasint"`
}

// RtmManifest represents the attestation report
// element of type 'RTM Manifest'
type RtmManifest struct {
	Type               string         `json:"type" cbor:"0,keyasint"`
	Name               string         `json:"name" cbor:"1,keyasint"`
	DevCommonName      string         `json:"developerCommonName" cbor:"2,keyasint"`
	Version            string         `json:"version" cbor:"3,keyasint"`
	Description        string         `json:"description" cbor:"4,keyasint"`
	CertificationLevel int            `json:"certificationLevel" cbor:"5,keyasint"`
	Validity           Validity       `json:"validity" cbor:"5,keyasint"`
	Verifications      []Verification `json:"verifications" cbor:"6,keyasint"`
}

// DeviceDescription represents the attestation report
// element of type 'Device Description'
type DeviceDescription struct {
	Type            string               `json:"type" cbor:"0,keyasint"`
	Fqdn            string               `json:"fqdn" cbor:"1,keyasint"`
	Description     string               `json:"description" cbor:"2,keyasint"`
	Location        string               `json:"location" cbor:"3,keyasint"`
	RtmManifest     string               `json:"rtmManifest" cbor:"4,keyasint"`
	OsManifest      string               `json:"osManifest" cbor:"5,keyasint"`
	AppDescriptions []AppDescription     `json:"appDescriptions" cbor:"6,keyasint"`
	Internal        []InternalConnection `json:"internalConnections" cbor:"7,keyasint"`
	External        []ExternalInterface  `json:"externalEndpoints" cbor:"8,keyasint"`
}

// CompanyDescription represents the attestation report
// element of type 'Company Description'
type CompanyDescription struct {
	Type               string   `json:"type" cbor:"0,keyasint"`
	DN                 string   `json:"dn" cbor:"1,keyasint"`
	CertificationLevel int      `json:"certificationLevel" cbor:"2,keyasint"`
	Description        string   `json:"description" cbor:"3,keyasint"`
	Validity           Validity `json:"validity" cbor:"4,keyasint"`
}

// CertParams contains params of an x.509 certificate. The tpm module cannot send an AK CSR
// to the server, as the AK is a restricted key which does not allow signing of non-TPM-based
// objects such as CSRs. Therefore, pass the certificate parameters encoded in this structure
type CertParams struct {
	Type    string   `json:"type" cbor:"0,keyasint"`
	Subject Name     `json:"subject,omitempty" cbor:"1,keyasint,omitempty"`
	SANs    []string `json:"sans,omitempty" cbor:"2,keyasint,omitempty"`
}

// Name is the PKIX Name for CertParams
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

// ArPlain represents the attestation report with
// its plain elements
type ArPlain struct {
	Type               string              `json:"type" cbor:"0,keyasint"`
	TpmM               *TpmMeasurement     `json:"tpmMeasurement,omitempty" cbor:"1,keyasint,omitempty"`
	SnpM               *SnpMeasurement     `json:"snpMeasurement,omitempty" cbor:"2,keyasint,omitempty"`
	SWM                []SwMeasurement     `json:"swMeasurements,omitempty" cbor:"3,keyasint,omitempty"`
	RtmManifest        RtmManifest         `json:"rtmManifest" cbor:"4,keyasint"`
	OsManifest         OsManifest          `json:"osManifest" cbor:"5,keyasint"`
	AppManifests       []AppManifest       `json:"appManifests,omitempty" cbor:"6,keyasint,omitempty"`
	CompanyDescription *CompanyDescription `json:"companyDescription,omitempty" cbor:"7,keyasint,omitempty"`
	DeviceDescription  DeviceDescription   `json:"deviceDescription" cbor:"8,keyasint"`
	Nonce              []byte              `json:"nonce" cbor:"9,keyasint"`
}

// ArJws represents the attestation report in JWS/COSE format with its
// contents already in signed JWS/COSE format
type ArJws struct {
	Type               string          `json:"type" cbor:"0,keyasint"`
	TpmM               *TpmMeasurement `json:"tpmMeasurement,omitempty" cbor:"1,keyasint,omitempty"`
	SnpM               *SnpMeasurement `json:"snpMeasurement,omitempty" cbor:"2,keyasint,omitempty"`
	SWM                []SwMeasurement `json:"swMeasurements,omitempty" cbor:"3,keyasint,omitempty"`
	RtmManifest        []byte          `json:"rtmManifests" cbor:"4,keyasint"`
	OsManifest         []byte          `json:"osManifest" cbor:"5,keyasint"`
	AppManifests       [][]byte        `json:"appManifests,omitempty" cbor:"6,keyasint,omitempty"`
	CompanyDescription []byte          `json:"companyDescription,omitempty" cbor:"7,keyasint,omitempty"`
	DeviceDescription  []byte          `json:"deviceDescription" cbor:"8,keyasint"`
	Nonce              []byte          `json:"nonce" cbor:"9,keyasint"`
}

// Generate generates an attestation report with the provided
// nonce 'nonce' and manifests and descriptions 'metadata'. The manifests and
// descriptions must be either raw JWS tokens in the JWS JSON full serialization
// format or CBOR COSE tokens. Takes a list of 'measurements' implementing the
// attestation report 'Measurer' interface providing a method for collecting
// the measurements from a hardware or software interface
func Generate(nonce []byte, metadata [][]byte, measurements []Measurement, s Serializer) ([]byte, error) {
	// Create attestation report object which will be filled with the attestation
	// data or sent back incomplete in case errors occur
	// TODO this will not work!!
	ar := ArJws{
		Type: "Attestation Report",
	}

	if len(nonce) > 32 {
		return nil, fmt.Errorf("Generate Attestation Report: Nonce exceeds maximum length of 32 bytes")
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
		t := new(Type)
		err = s.Unmarshal(data, t)
		if err != nil {
			log.Warnf("Failed to unmarshal data from metadata object %v: %v", i, err)
			continue
		}

		switch t.Type {
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

	log.Tracef("Retrieving measurements from %v measurement interfaces", len(measurements))
	for _, m := range measurements {
		measurer, ok := m.(Measurer)
		if !ok {
			log.Warn("Internal Error: Measurement does not implement Measurer. Will not add measurement to attestation report")
			continue
		}

		// This actually collects the measurements. The methods are implemented
		// in the respective module (e.g. tpm module)
		log.Trace("Getting measurements from measurement interface..")
		data, err := measurer.Measure(nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to get measurements: %v", err)
		}

		// Check the type of the measurements and add it to the attestation report
		if tpmData, ok := data.(TpmMeasurement); ok {
			log.Tracef("Added %v to attestation report", tpmData.Type)
			ar.TpmM = &tpmData
		} else if swData, ok := data.(SwMeasurement); ok {
			log.Tracef("Added %v to attestation report", swData.Type)
			ar.SWM = append(ar.SWM, swData)
		} else if snpData, ok := data.(SnpMeasurement); ok {
			log.Tracef("Added %v to attestation report", snpData.Type)
			ar.SnpM = &snpData
		} else {
			log.Error("Error: Unsupported measurement interface type")
		}
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
func Sign(report []byte, signer Signer, s Serializer) (bool, []byte) {
	return s.Sign(report, signer)
}

// Verify verifies an attestation report in full serialized JWS
// format against the supplied nonce and CA certificate. Verifies the certificate
// chains of all attestation report elements as well as the measurements against
// the verifications and the compatibility of software artefacts.
func Verify(arRaw string, nonce, casPem []byte, policies []Policies, s Serializer) VerificationResult {
	result := VerificationResult{
		Type:        "Verification Result",
		Success:     true,
		SwCertLevel: 0}

	// Verify ALL signatures and unpack plain AttestationReport
	ok, ar := verifyAndUnpackAttestationReport(arRaw, &result, casPem, s)
	if ar == nil {
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

	verifications, err := collectVerifications(ar)
	if err != nil {
		result.ProcessingError = append(result.ProcessingError, err.Error())
		result.Success = false
	}

	// If present, verify TPM measurements against provided TPM verifications
	result.MeasResult.TpmMeasResult, ok = verifyTpmMeasurements(ar.TpmM, nonce,
		verifications["TPM Verification"], casPem)
	if !ok {
		result.Success = false
	}

	// If present, verify AMD SEV SNP measurements against provided SNP verifications
	result.MeasResult.SnpMeasResult, ok = verifySnpMeasurements(ar.SnpM, nonce,
		verifications["SNP Verification"])
	if !ok {
		result.Success = false
	}

	// If present, verify software measurements against provided software verifications
	result.MeasResult.SwMeasResult, ok = verifySwMeasurements(ar.SWM,
		verifications["SW Verification"])
	if !ok {
		result.Success = false
	}

	// The lowest certification level of all components determines the certification
	// level for the device's software stack
	levels := make([]int, 0)
	levels = append(levels, ar.RtmManifest.CertificationLevel)
	levels = append(levels, ar.OsManifest.CertificationLevel)
	for _, app := range ar.AppManifests {
		levels = append(levels, app.CertificationLevel)
	}
	aggCertLevel := levels[0]
	for _, l := range levels {
		if l < aggCertLevel {
			aggCertLevel = l
		}
	}
	// If no hardware trust anchor is present, the maximum certification level is 1
	// If there are verifications with a higher trust level present, the remote attestation
	// must fail
	if ar.TpmM == nil && ar.SnpM == nil && aggCertLevel > 1 {
		msg := fmt.Sprintf("No hardware trust anchor measurements present but claimed certification level is %v, which requires a hardware trust anchor", aggCertLevel)
		result.ProcessingError = append(result.ProcessingError, msg)
		result.Success = false
	}
	result.SwCertLevel = aggCertLevel

	// Verify the compatibility of the attestation report through verifying the
	// compatibility of all components
	appDescriptions := make([]string, 0)
	for _, a := range ar.DeviceDescription.AppDescriptions {
		appDescriptions = append(appDescriptions, a.AppManifest)
	}

	// Check that the OS and RTM Manifest are specified in the Device Description
	if ar.DeviceDescription.RtmManifest == ar.RtmManifest.Name {
		result.DevDescResult.CorrectRtm.Success = true
	} else {
		msg := fmt.Sprintf("Device Description listed wrong RTM Manifest: %v vs. %v", ar.DeviceDescription.RtmManifest, ar.RtmManifest.Name)
		result.DevDescResult.CorrectRtm.setFalse(&msg)
		result.DevDescResult.Summary.Success = false
		result.Success = false
	}
	if ar.DeviceDescription.OsManifest == ar.OsManifest.Name {
		result.DevDescResult.CorrectOs.Success = true
	} else {
		msg := fmt.Sprintf("Device Description listed wrong OS Manifest: %v vs. %v", ar.DeviceDescription.OsManifest, ar.OsManifest.Name)
		result.DevDescResult.CorrectOs.setFalse(&msg)
		result.DevDescResult.Summary.Success = false
		result.Success = false
	}

	// Check that every AppManifest has a corresponding AppDescription
	result.DevDescResult.CorrectApps.Success = true
	for _, a := range ar.AppManifests {
		if !contains(a.Name, appDescriptions) {
			msg := fmt.Sprintf("Device Description does not list the following App Manifest: %v", a.Name)
			result.DevDescResult.CorrectApps.setFalseMulti(&msg)
			result.DevDescResult.Summary.Success = false
			result.Success = false
		}
	}

	// Check that the Rtm Manifest is compatible with the OS Manifest
	if contains(ar.RtmManifest.Name, ar.OsManifest.Rtms) {
		result.DevDescResult.RtmOsCompatibility.Success = true
	} else {
		msg := fmt.Sprintf("RTM Manifest %v is not compatible with OS Manifest %v", ar.RtmManifest.Name, ar.OsManifest.Name)
		result.DevDescResult.RtmOsCompatibility.setFalse(&msg)
		result.DevDescResult.Summary.Success = false
		result.Success = false
	}

	// Check that the OS Manifest is compatible with all App Manifests
	result.DevDescResult.OsAppsCompatibility.Success = true
	for _, a := range ar.AppManifests {
		if !contains(ar.OsManifest.Name, a.Oss) {
			msg := fmt.Sprintf("OS Manifest %v is not compatible with App Manifest %v", ar.OsManifest.Name, a.Name)
			result.DevDescResult.OsAppsCompatibility.setFalseMulti(&msg)
			result.DevDescResult.Summary.Success = false
			result.Success = false
		}
	}

	// Validate every specified policy
	for _, policy := range policies {
		pv, ok := policy.(PolicyValidator)
		if !ok {
			msg := "Internal Error: policy does not implement PolicyValidator"
			log.Warn(msg)
			result.Success = false
			result.ProcessingError = append(result.ProcessingError, msg)
			continue
		}

		err := pv.Validate(result)
		if err != nil {
			result.Success = false
			// TODO should be two different types, result without success and policy validation
			// which are merged together here
			log.Warnf("policy validation failed: %v", err)
		}
	}

	return result
}

func extendHash(hash []byte, data []byte) []byte {
	concat := append(hash, data...)
	h := sha256.Sum256(concat)
	ret := make([]byte, 32)
	copy(ret, h[:])
	return ret
}

// loadCert loads a certificate from PEM encoded data
func loadCert(data []byte) (*x509.Certificate, error) {
	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	cert, err := x509.ParseCertificate(input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 Certificate: %v", err)
	}
	return cert, nil
}

// loadCerts loads one or more certificates from PEM encoded data
func loadCerts(data []byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0)
	input := data

	for block, rest := pem.Decode(input); block != nil; block, rest = pem.Decode(rest) {

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse x509 Certificate: %v", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func verifyAndUnpackAttestationReport(attestationReport string, result *VerificationResult, casPem []byte, s Serializer) (bool, *ArPlain) {
	if result == nil {
		log.Warn("Provided Validation Result was nil")
		return false, nil
	}

	ar := ArPlain{}

	roots, err := loadCerts(casPem)
	if err != nil {
		log.Trace("Loading PEM encoded CA certificate(s) failed")
		result.Success = false
		return false, &ar
	}

	//Validate Attestation Report signature
	jwsValRes, payload, ok := s.VerifyToken([]byte(attestationReport), roots)
	result.ReportSignature = jwsValRes.SignatureCheck
	if !ok {
		log.Trace("Verification of Attestation Report Signatures failed")
		result.Success = false
		return false, &ar
	}

	var arJws ArJws
	err = s.Unmarshal(payload, &arJws)
	if err != nil {
		msg := fmt.Sprintf("Parsing of Attestation Report failed: %v", err)
		result.ProcessingError = append(result.ProcessingError, msg)
		log.Trace(msg)
		result.Success = false
		return false, &ar
	}

	ar.Type = "ArPlain"
	ar.TpmM = arJws.TpmM
	ar.SnpM = arJws.SnpM
	ar.SWM = arJws.SWM
	ar.Nonce = arJws.Nonce

	// Validate and unpack Rtm Manifest
	jwsValRes, payload, ok = s.VerifyToken([]byte(arJws.RtmManifest), roots)
	result.RtmResult.Summary = jwsValRes.Summary
	result.RtmResult.SignatureCheck = jwsValRes.SignatureCheck
	if !ok {
		log.Trace("Verification of RTM Manifest Signatures failed")
		result.Success = false
	}
	err = s.Unmarshal(payload, &ar.RtmManifest)
	if err != nil {
		msg := fmt.Sprintf("Unpacking of RTM Manifest failed: %v", err)
		result.RtmResult.Summary.setFalseMulti(&msg)
		result.Success = false
	} else {
		result.RtmResult.Name = ar.RtmManifest.Name
		result.RtmResult.ValidityCheck = checkValidity(ar.RtmManifest.Validity)
		if !result.RtmResult.ValidityCheck.Success {
			result.RtmResult.Summary.Success = false
			result.Success = false
		}
	}

	// Validate and unpack OS Manifest
	jwsValRes, payload, ok = s.VerifyToken([]byte(arJws.OsManifest), roots)
	result.OsResult.Summary = jwsValRes.Summary
	result.OsResult.SignatureCheck = jwsValRes.SignatureCheck
	if !ok {
		log.Trace("Verification of OS Manifest Signatures failed")
		result.Success = false
	}
	err = s.Unmarshal(payload, &ar.OsManifest)
	if err != nil {
		msg := fmt.Sprintf("Unpacking of OS Manifest failed: %v", err)
		result.OsResult.Summary.setFalseMulti(&msg)
		result.Success = false
	} else {
		result.OsResult.Name = ar.OsManifest.Name
		result.OsResult.ValidityCheck = checkValidity(ar.OsManifest.Validity)
		if !result.OsResult.ValidityCheck.Success {
			result.OsResult.Summary.Success = false
			result.Success = false
		}
	}

	// Validate and unpack App Manifests
	for i, amSigned := range arJws.AppManifests {
		result.AppResults = append(result.AppResults, ManifestResult{})

		jwsValRes, payload, ok = s.VerifyToken([]byte(amSigned), roots)
		result.AppResults[i].Summary = jwsValRes.Summary
		result.AppResults[i].SignatureCheck = jwsValRes.SignatureCheck
		if !ok {
			log.Trace("Verification of App Manifest Signatures failed")
			result.Success = false
		}

		var am AppManifest
		err = s.Unmarshal(payload, &am)
		if err != nil {
			msg := fmt.Sprintf("Unpacking of App Manifest failed: %v", err)
			result.AppResults[i].Summary.setFalseMulti(&msg)
			result.Success = false
		} else {
			ar.AppManifests = append(ar.AppManifests, am)
			result.AppResults[i].Name = am.Name
			result.AppResults[i].ValidityCheck = checkValidity(am.Validity)
			if !result.AppResults[i].ValidityCheck.Success {
				log.Trace("App Manifest invalid - " + am.Name)
				result.AppResults[i].Summary.Success = false
				result.Success = false

			}
		}
	}

	// Validate and unpack Company Description if present
	if arJws.CompanyDescription != nil {
		jwsValRes, payload, ok = s.VerifyToken([]byte(arJws.CompanyDescription), roots)
		result.CompDescResult = &CompDescResult{}
		result.CompDescResult.Summary = jwsValRes.Summary
		result.CompDescResult.SignatureCheck = jwsValRes.SignatureCheck
		if !ok {
			log.Trace("Verification of Company Description Signatures failed")
			result.Success = false
		}
		err = s.Unmarshal(payload, &ar.CompanyDescription)
		if err != nil {
			msg := fmt.Sprintf("Unpacking of Company Description failed: %v", err)
			result.CompDescResult.Summary.setFalseMulti(&msg)
			result.Success = false
		} else {
			result.CompDescResult.Name = ar.CompanyDescription.DN
			result.CompDescResult.CompCertLevel = ar.CompanyDescription.CertificationLevel

			result.CompDescResult.ValidityCheck = checkValidity(ar.CompanyDescription.Validity)
			if !result.CompDescResult.ValidityCheck.Success {
				log.Trace("Company Description invalid")
				result.CompDescResult.Summary.Success = false
				result.Success = false
			}
		}
	}

	// Validate and unpack Device Description
	jwsValRes, payload, ok = s.VerifyToken([]byte(arJws.DeviceDescription), roots)
	result.DevDescResult.Summary = jwsValRes.Summary
	result.DevDescResult.SignatureCheck = jwsValRes.SignatureCheck
	if !ok {
		log.Trace("Verification of Device Description Signatures failed")
		result.Success = false
	}
	err = s.Unmarshal(payload, &ar.DeviceDescription)
	if err != nil {
		msg := fmt.Sprintf("Unpacking of Device Description failed: %v", err)
		result.DevDescResult.Summary.setFalseMulti(&msg)
	}

	result.PlainAttReport = ar
	return true, &ar
}

func checkValidity(val Validity) Result {
	result := Result{}
	result.Success = true

	notBefore, err := time.Parse(timeLayout, val.NotBefore)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse NotBefore time. Time.Parse returned %v", err)
		result.setFalse(&msg)
		return result
	}
	notAfter, err := time.Parse(timeLayout, val.NotAfter)
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

// Searches for a specific hash value in the verifications for RTM and OS
func getVerification(hash []byte, verifications []Verification) *Verification {
	for _, ver := range verifications {
		if bytes.Equal(ver.Sha256, hash) {
			return &ver
		}
	}
	return nil
}

func verifySwMeasurements(swMeasurements []SwMeasurement, verifications []Verification) ([]SwMeasurementResult, bool) {

	swMeasurementResults := make([]SwMeasurementResult, 0)
	ok := true

	// Check that every verification is reflected by a measurement
	for _, v := range verifications {
		swRes := SwMeasurementResult{}
		swRes.Validation.Success = false
		swRes.VerName = v.Name
		found := false
		for _, swm := range swMeasurements {
			if bytes.Equal(swm.Sha256, v.Sha256) {
				swRes.MeasName = swm.Name
				swRes.Validation.Success = true
				found = true
				break
			}
		}
		if !found {
			msg := fmt.Sprintf("no SW Measurement found for SW Verification %v (hash: %v)", v.Name, v.Sha256)
			swRes.Validation.setFalse(&msg)
			ok = false
		}
		swMeasurementResults = append(swMeasurementResults, swRes)
	}

	// Check that every measurement is reflected by a verification
	for _, swM := range swMeasurements {
		found := false
		for _, swV := range verifications {
			if bytes.Equal(swM.Sha256, swV.Sha256) {
				found = true
				break
			}
		}
		if !found {
			swRes := SwMeasurementResult{}
			swRes.MeasName = swM.Name
			msg := fmt.Sprintf("no SW Verification found for SW Measurement: %v", swM.Sha256)
			swRes.Validation.setFalse(&msg)
			swMeasurementResults = append(swMeasurementResults, swRes)
			ok = false
		}
	}

	return swMeasurementResults, ok
}

func collectVerifications(ar *ArPlain) (map[string][]Verification, error) {
	// Gather a list of all verifications independent of the type
	verList := append(ar.RtmManifest.Verifications, ar.OsManifest.Verifications...)
	for _, appManifest := range ar.AppManifests {
		verList = append(verList, appManifest.Verifications...)
	}

	verMap := make(map[string][]Verification)

	// Iterate through the verifications and sort them into the different types
	for _, v := range verList {
		if v.Type != "SNP Verification" && v.Type != "SW Verification" && v.Type != "TPM Verification" {
			return nil, fmt.Errorf("verification of type %v is not supported", v.Type)
		}
		verMap[v.Type] = append(verMap[v.Type], v)
	}
	return verMap, nil
}

func checkExtensionUint8(cert *x509.Certificate, oid string, value uint8) error {

	for _, ext := range cert.Extensions {

		if ext.Id.String() == oid {
			if len(ext.Value) != 3 {
				return fmt.Errorf("extension %v value unexpected length %v (expected 3)", oid, len(ext.Value))
			}
			if ext.Value[0] != 0x2 {
				return fmt.Errorf("extension %v value[0] = %v does not match expected value 2", oid, ext.Value[0])
			}
			if ext.Value[1] != 0x1 {
				return fmt.Errorf("extension %v value[1] = %v does not match expected value 1", oid, ext.Value[1])
			}
			if ext.Value[2] != value {
				return fmt.Errorf("extension %v value[2] = %v does not match expected value %v", oid, ext.Value[2], value)
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
