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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"

	log "github.com/sirupsen/logrus"

	"gopkg.in/square/go-jose.v2"

	"time"

	"github.com/google/go-tpm/tpm2"
)

// Measurement is a generic interface for a Measurement, such as a TpmMeasurement
type Measurement interface{}

// Measurer is an interface implementing the Measure method for each type of measurement
// Each type of interface that is capable of providing measurements (such
// as the tpmw module) is expected to implement this method. The
// attestationreport module will call this method to retrieve the measurements
// of the platform during attestation report generation.
type Measurer interface {
	Measure(mp MeasurementParams) (Measurement, error)
}

// MeasurementParams is a generic interface for measurement parameters
type MeasurementParams interface{}

// JSONType is a helper struct for just extracting the JSON 'Type'
type JSONType struct {
	Type string `json:"type"`
}

// Validity is a helper struct for JSON 'Validity'
type Validity struct {
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

const timeLayout = "20060102150405"

// HashChainElem represents the JSON attestation report
// element of type 'Hash Chain' embedded in 'TPM Measurement'
type HashChainElem struct {
	Type   string   `json:"type"`
	Pcr    int32    `json:"pcr"`
	Sha256 []string `json:"sha256"`
}

// CertChain is a helper struct for certificate chains,
// consisting of a leaf certificate, an arbitrary number
// of intermediate (sub-CA) certificates and a CA certificate
type CertChain struct {
	Leaf          string   `json:"leaf"`
	Intermediates []string `json:"intermediates"`
	Ca            string   `json:"ca"`
}

// TpmMeasurement represents the JSON attestation report
// element of type 'TPM Measurement'
type TpmMeasurement struct {
	Type      string           `json:"type"`
	Message   string           `json:"message"`
	Signature string           `json:"signature"`
	Certs     CertChain        `json:"certs"`
	HashChain []*HashChainElem `json:"hashChain"`
}

// SnpMeasurement represents the JSON attestation report
// element of type 'SNP Measurement' signed by the device
type SnpMeasurement struct {
	Type   string    `json:"type"`
	Report []byte    `json:"blob"`
	Certs  CertChain `json:"certs"`
}

// SwMeasurement represents the JSON attestation report
// element of type 'Software Measurement'
type SwMeasurement struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Sha256 string `json:"sha256"`
}

// TpmVerification represents the JSON attestation report
// element of type 'TPM Verification'
type TpmVerification struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Pcr    int    `json:"pcr"`
	Sha256 string `json:"sha256"`
}

type SnpPolicy struct {
	Type         string `json:"type"`
	SingleSocket bool   `json:"singleSocket"`
	Debug        bool   `json:"debug"`
	Migration    bool   `json:"migration"`
	Smt          bool   `json:"smt"`
	AbiMajor     uint8  `json:"abiMajor"`
	AbiMinor     uint8  `json:"abiMinor"`
}

// SnpVerification represents the JSON attestation report
// element of type 'SNP Verification'
type SnpVerification struct {
	Type    string    `json:"type"`
	Sha256  string    `json:"sha256"`
	Version uint32    `json:"version"`
	Policy  SnpPolicy `json:"policy"`
}

// SwVerification represents the JSON attestation report
// element of type 'Software Verification'
type SwVerification struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Sha256 string `json:"sha256"`
}

// AppDescription represents the JSON attestation report
// element of type 'App Description'
type AppDescription struct {
	Type        string              `json:"type"`
	Name        string              `json:"name"`
	AppManifest string              `json:"appManifest"` // Links to Type 'App Manifest'->'Name'
	External    []ExternalInterface `json:"externalConnections"`
}

// InternalConnection represents the JSON attestation report
// element of type 'Internal Connection'
type InternalConnection struct {
	Type         string `json:"type"`
	NameAppA     string `json:"nameAppA"`     // Links to Type 'App Description'->'Name'
	EndpointAppA string `json:"endpointAppA"` // Links to Type 'App Manifest'->'Endpoint'
	NameAppB     string `json:"nameAppB"`     // Links to Type 'App Description'->'Name'
	EndpointAppB string `json:"endpointAppB"` // Links to Type 'App Manifest'->'Endpoint'
}

// ExternalInterface represents the JSON attestation report
// element of type 'External Interface'
type ExternalInterface struct {
	Type        string `json:"type"`
	AppEndpoint string `json:"appEndpoint"` // Links to Type 'App Manifest'->'Endpoint'
	Interface   string `json:"interface"`   // Links to Type 'App Description'->'Name'
	Port        int    `json:"port"`        // Links to Type 'App Manifest'->'Endpoint'
}

// AppManifest represents the JSON attestation report
// element of type 'App Manifest'
type AppManifest struct {
	Type               string           `json:"type"`
	Name               string           `json:"name"`
	DevCommonName      string           `json:"developerCommonName"`
	Version            string           `json:"version"`
	Oss                []string         `json:"oss"` // Links to Type 'OsManifest'->'Name'
	Description        string           `json:"description"`
	CertificationLevel int              `json:"certificationLevel"`
	Validity           Validity         `json:"validity"`
	Verifications      []SwVerification `json:"verifications"`
}

// OsManifest represents the JSON attestation report
// element of type 'OsManifest'
type OsManifest struct {
	Type               string            `json:"type"`
	Name               string            `json:"name"`
	DevCommonName      string            `json:"developerCommonName"`
	Version            string            `json:"version"`
	Rtms               []string          `json:"rtms"` // Links to Type 'RTM Manifest'->'Name'
	Description        string            `json:"description"`
	CertificationLevel int               `json:"certificationLevel"`
	Validity           Validity          `json:"validity"`
	Verifications      []TpmVerification `json:"verifications"`
}

// RtmManifest represents the JSON attestation report
// element of type 'RTM Manifest'
type RtmManifest struct {
	Type               string            `json:"type"`
	Name               string            `json:"name"`
	DevCommonName      string            `json:"developerCommonName"`
	Version            string            `json:"version"`
	Description        string            `json:"description"`
	CertificationLevel int               `json:"certificationLevel"`
	Validity           Validity          `json:"validity"`
	Verifications      []TpmVerification `json:"verifications"`
}

// DeviceDescription represents the JSON attestation report
// element of type 'Device Description'
type DeviceDescription struct {
	Type            string               `json:"type"`
	Fqdn            string               `json:"fqdn"`
	Description     string               `json:"description"`
	Location        string               `json:"location"`
	RtmManifest     string               `json:"rtmManifest"`
	OsManifest      string               `json:"osManifest"`
	AppDescriptions []AppDescription     `json:"appDescriptions"`
	Internal        []InternalConnection `json:"internalConnections"`
	External        []ExternalInterface  `json:"externalEndpoints"`
}

// CompanyDescription represents the JSON attestation report
// element of type 'Company Description'
type CompanyDescription struct {
	Type               string   `json:"type"`
	DN                 string   `json:"dn"`
	CertificationLevel int      `json:"certificationLevel"`
	Description        string   `json:"description"`
	Validity           Validity `json:"validity"`
}

// CertParams contains params of an x.509 certificate. The tpm module cannot send an AK CSR
// to the server, as the AK is a restricted key which does not allow signing of non-TPM-based
// objects such as CSRs. Therefore, pass the certificate parameters encoded in this structure
type CertParams struct {
	Type    string   `json:"type"`
	Subject Name     `json:"subject,omitempty"`
	SANs    []string `json:"sans,omitempty"`
}

// Name is the PKIX Name for CertParams
type Name struct {
	CommonName         string        `json:"commonName,omitempty"`
	Country            string        `json:"country,omitempty"`
	Organization       string        `json:"organization,omitempty"`
	OrganizationalUnit string        `json:"organizationalUnit,omitempty"`
	Locality           string        `json:"locality,omitempty"`
	Province           string        `json:"province,omitempty"`
	StreetAddress      string        `json:"streetAddress,omitempty"`
	PostalCode         string        `json:"postalCode,omitempty"`
	Names              []interface{} `json:"names,omitempty"`
}

// ArPlain represents the attestation report with
// its plain elements
type ArPlain struct {
	Type               string             `json:"type"`
	TpmM               TpmMeasurement     `json:"tpmMeasurement,omitempty"`
	SWM                []SwMeasurement    `json:"swMeasurements,omitempty"`
	RtmManifest        RtmManifest        `json:"rtmManifest"`
	OsManifest         OsManifest         `json:"osManifest"`
	AppManifests       []AppManifest      `json:"appManifests"`
	CompanyDescription CompanyDescription `json:"companyDescription"`
	DeviceDescription  DeviceDescription  `json:"deviceDescription"`
	Nonce              string             `json:"nonce"`
}

// ArJws represents the attestation report in JWS format with its
// contents already in signed JWs format
type ArJws struct {
	Type               string          `json:"type"`
	TpmM               TpmMeasurement  `json:"tpmMeasurement,omitempty"`
	SWM                []SwMeasurement `json:"swMeasurements,omitempty"`
	RtmManifest        string          `json:"rtmManifests"`
	OsManifest         string          `json:"osManifest"`
	AppManifests       []string        `json:"appManifests"`
	CompanyDescription string          `json:"companyDescription"`
	DeviceDescription  string          `json:"deviceDescription"`
	Nonce              string          `json:"nonce"`
}

// TpmParams are Parameters for retrieving TPM measurements: The
// nonce is embedded into the quote. Pcrs must be set to the PCRs
// that should be embedded into the quote. Certs represent the AK
// certificate chain including EK and CA. UseIma species if the
// kernel's Integrity Measurement Architecture (IMA) should be used
// and ImaPcr specifies the PCR used by the IMA (kernel config)
type TpmParams struct {
	Nonce  []byte
	Pcrs   []int
	Certs  CertChain
	UseIma bool
	ImaPcr int32
}

// SnpParams are parameters for retrieving AMD SEV-SNP measurements:
// Currently, this is only the nonce, which is embedded into the
// signed measurement
type SnpParams struct {
	Nonce []byte
}

// SwParams are parameters for retrieving SW measurements. Currently none required
type SwParams struct{}

// In IDS contexts, the different certificates used for signing meta-data
// must have appropriate roles so that e.g. an operator cannot impersonate
// an evaluator. This is an optional feature. If used, the corresponding
// roles must be set in the  OrganizationalUnit (OU) field in the
// x.509 certificates
type SignerRoles struct {
	ManifestSigners    []string
	CompanyDescSigners []string
	ArSigners          []string
	ConnDescSigners    []string
}

type snpreport struct {
	// Table 24 @ https://www.amd.com/system/files/TechDocs/56860.pdf
	Status     uint32
	ReportSize uint32
	Reserved0  [24]byte
	// Table 21 @ https://www.amd.com/system/files/TechDocs/56860.pdf
	Version         uint32
	GuestSvn        uint32
	Policy          uint64
	FamilyId        [16]byte
	ImageId         [16]byte
	Vmpl            uint32
	SignatureAlgo   uint32
	Currentcb       uint64 // platform_version
	PlatformInfo    uint64
	AuthorKeyEn     uint32
	Reserved1       uint32
	ReportData      [64]byte
	Measurement     [48]byte
	HostData        [32]byte
	IdKeyDigest     [48]byte
	AuthorKeyDigest [48]byte
	ReportId        [32]byte
	ReportIdMa      [32]byte
	ReportedTcb     uint64
	Reserved2       [24]byte
	ChipId          [64]byte
	//Reserved3 [192]byte
	CommittedTcb   uint64
	CurrentBuild   uint8
	CurrentMinor   uint8
	CurrentMajor   uint8
	Reserved3a     uint8
	CommittedBuild uint8
	CommittedMinor uint8
	CommittedMajor uint8
	Reserved3b     uint8
	LaunchTcb      uint64
	Reserved3c     [168]byte
	// Table 23 @ https://www.amd.com/system/files/TechDocs/56860.pdf
	SignatureR [72]byte
	SignatureS [72]byte
	Reserved4  [368]byte
}

const (
	ecdsa384_with_sha384 = 1
)

const (
	header_offset    = 0x20
	signature_offset = 0x2A0
)

// Generate generates an attestation report with the provided
// nonce 'nonce' and manifests and descriptions 'metadata'. The manifests and
// descriptions must be raw JWS tokens in the JWS JSON full serialization
// format. Takes a list of 'measurements' and accompanying 'measurementParams',
// which must be arrays of the same length. The 'measurements' must
// implement the attestation report 'Measurer' interface providing
// a method for collecting the measurements from a hardware or software
// interface
func Generate(nonce []byte, metadata [][]byte, measurements []Measurement, measurementParams []MeasurementParams) ArJws {

	// Create attestation report object which will be filled with the attestation
	// data or sent back incomplete in case errors occur
	ar := ArJws{
		Type: "Attestation Report",
	}

	if len(nonce) > 32 {
		log.Warn("Generate Attestation Report: Nonce exceeds maximum length of 32 bytes")
		return ar
	}
	ar.Nonce = hex.EncodeToString(nonce)

	log.Debug("Adding manifests and descriptions to Attestation Report..")

	// Retrieve the manifests and descriptions
	log.Trace("Parsing ", len(metadata), " meta-data objects..")
	numManifests := 0
	for i := 0; i < len(metadata); i++ {

		// Extract plain payload (i.e. the manifest/description itself) out of base64-encoded
		// JSON Web Signature
		jws, err := jose.ParseSigned(string(metadata[i]))
		if err != nil {
			log.Warnf("Failed to parse metadata object %v: %v", i, err)
			continue
		}
		data := jws.UnsafePayloadWithoutVerification()

		// Unmarshal the Type field of the JSON file to determine the type for
		// later processing
		t := new(JSONType)
		err = json.Unmarshal(data, t)
		if err != nil {
			log.Warnf("Failed to unmarshal data from metadata object %v: %v", i, err)
			continue
		}

		switch t.Type {
		case "App Manifest":
			log.Debug("Adding App Manifest")
			ar.AppManifests = append(ar.AppManifests, jws.FullSerialize())
			numManifests++
		case "OS Manifest":
			log.Debug("Adding OS Manifest")
			ar.OsManifest = jws.FullSerialize()
			numManifests++
		case "RTM Manifest":
			log.Debug("Adding RTM Manifest")
			ar.RtmManifest = jws.FullSerialize()
			numManifests++
		case "Device Description":
			log.Debug("Adding Device Description")
			ar.DeviceDescription = jws.FullSerialize()
		case "Company Description":
			log.Debug("Adding Company Description")
			ar.CompanyDescription = jws.FullSerialize()
		default:
			log.Warn("Unknown manifest type ", t.Type)
		}
	}

	if numManifests == 0 {
		log.Warn("Did not find any manifests for the attestation report")
	} else {
		log.Debug("Added ", numManifests, " manifests to attestation report")
	}

	// Add the measurements of the platform to the attestation report.
	// The methods for retrieving the data are implemented in the wrappers
	// for the specific hardware or software module, such as the TPM module
	if len(measurements) != len(measurementParams) {
		log.Warn("Internal Error: length of measurements does not match length of measuremt params. Will not add measurements to attestation report")
		return ar
	}

	for i, m := range measurements {
		measurer, ok := m.(Measurer)
		if !ok {
			log.Warn("Internal Error: Measurement does not implement Measurer. Will not add measurement to attestation report")
			continue
		}

		// This actually collects the measurements. The methods are implemented
		// in the respective module (e.g. tpm module)
		log.Trace("Getting measurements from measurement interface..")
		data, err := measurer.Measure(measurementParams[i])
		if err != nil {
			log.Warnf("Failed to get measurements: %v", err)
			return ar
		}

		// Check the type of the measurements and add it to the attestation report
		if tpmData, ok := data.(TpmMeasurement); ok {
			ar.TpmM = tpmData
		} else if SwData, ok := data.(SwMeasurement); ok {
			ar.SWM = append(ar.SWM, SwData)
		} else {
			log.Error("Error: Unsupported measurement interface type")
		}
	}

	log.Trace("Finished attestation report generation")

	return ar
}

// Sign signs the attestation report with private key 'priv' and appends the
// pem encoded certificate chain 'certsPem' to the JWS structure. The
// certificates must be handed over in the order they should be appended
// (Signing Certificate -> Intermediate Certificates -> Root CA Certificate)
// Parameter 'mu' is an optional mutex, in case the private key requires exclusive
// access (e.g. because it is located in a hardware module)
func Sign(mu *sync.Mutex, ar ArJws, priv crypto.PrivateKey, pub crypto.PublicKey, certsPem [][]byte) (bool, []byte) {
	var err error

	log.Trace("Signing attestation report")

	// certificate chain in base64 encoding
	certsb64 := make([]string, 0)
	for i, certPem := range certsPem {
		cert, err := loadCert(certPem)
		if err != nil {
			log.Errorf("Failed to load cert[%v]: %v", i, err)
			return false, nil
		}

		certsb64 = append(certsb64, base64.StdEncoding.EncodeToString(cert.Raw))
	}

	// Get jose.SignatureAlgorithm
	// Saltlength and further algorithms are set to the recommended default by x509
	// we assume these defaults are correct
	var alg jose.SignatureAlgorithm
	alg, err = algFromKeyType(pub)
	if err != nil {
		log.Error(err)
		return false, nil
	}
	log.Trace("Chosen signature algorithm: ", alg)
	// create jose.OpaqueSigner with hwSigner wrapper (tpm key)
	var hws *hwSigner
	var opaqueSigner jose.OpaqueSigner
	hws = &hwSigner{
		pk:     &jose.JSONWebKey{Key: pub},
		signer: priv,
		alg:    alg,
	}
	opaqueSigner = jose.OpaqueSigner(hws)

	// Create jose.Signer with OpaqueSigner
	// x5c: adds Certificate Chain in later result
	var opt jose.SignerOptions
	var signer jose.Signer
	signer, err = jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: opaqueSigner}, opt.WithHeader("x5c", certsb64))
	if err != nil {
		log.Error("Failed to setup signer for the Attestation Report: ", err)
		return false, nil
	}

	// Marshal data to bytes
	data, err := json.Marshal(ar)
	if err != nil {
		log.Error("Failed to marshal the Attestation Report: ", err)
		return false, nil
	}

	// If a mutex is present, lock it to ensure exclusive access to the signing key
	if mu != nil {
		log.Trace("Trying to get lock on TPM for signing")
		mu.Lock()
		log.Trace("Got lock on TPM for signing")
		defer func() {
			log.Trace("Releasing TPM Lock for signing")
			mu.Unlock()
			log.Trace("Released TPM Lock for signing")
		}()
	}

	// sign
	log.Trace("Performing Sign operation")
	obj, err := signer.Sign(data)
	if err != nil {
		log.Error("Failed to sign the Attestation Report: ", err)
		return false, nil
	}
	log.Trace("Signed attestation report")

	// return signature in bytes
	var msg string
	msg = obj.FullSerialize()

	return true, []byte(msg)
}

// Verify verifies an attestation report in full serialized JWS
// format against the supplied nonce and CA certificate. Verifies the certificate
// chains of all attestation report elements as well as the measurements against
// the verifications and the compatibility of software artefacts.
func Verify(arRaw string, nonce, caCertPem []byte, roles *SignerRoles) VerificationResult {
	result := VerificationResult{
		Type:        "Verification Result",
		Success:     true,
		SwCertLevel: 0}

	// Verify ALL signatures and unpack plain AttestationReport
	ok, ar := verifyAndUnpackAttestationReport(arRaw, &result, caCertPem, roles)
	if ar == nil {
		result.InternalError = true
	}
	if !ok {
		result.Success = false
		return result
	}

	// Verify nonce
	arnonce, aerr := hex.DecodeString(ar.Nonce)
	vrNonceStr := hex.EncodeToString(nonce)
	if aerr != nil {
		msg := fmt.Sprintf("Failed to decode nonce in Attestation Report: %v", aerr)
		result.FreshnessCheck.setFalse(&msg)
		result.Success = false
	}
	if res := bytes.Compare(arnonce, nonce); res != 0 {
		msg := fmt.Sprintf("Nonces mismatch: SuppliedNonce = %v, AttestationReport Nonce = %v", vrNonceStr, ar.Nonce)
		result.FreshnessCheck.setFalse(&msg)
		result.Success = false
	} else {
		result.FreshnessCheck.Success = true
	}

	// Verify TPM measurements if present: Verify quote, signature and aggregated PCR value
	// As the TPM is currently the only implemented trust anchor, we always implement this check
	// TODO if other trust anchors are supported, evaluate which is present here
	result.MeasResult.TpmMeasResult, ok = verifyTpmMeasurements(&ar.TpmM, nonce, ar.RtmManifest.Verifications, ar.OsManifest.Verifications)
	if !ok {
		result.Success = false
	}

	// Verify software measurements against app manifests
	result.MeasResult.SwMeasResult, ok = verifySwMeasurements(ar.SWM, ar.AppManifests)
	if !ok {
		result.Success = false
	}

	// The lowest certification level of all components determines the certification
	// level for the device's software stack
	levels := make([]int, 0)
	levels = append(levels, ar.CompanyDescription.CertificationLevel)
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
		if contains(a.Name, appDescriptions) == false {
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
		if contains(ar.OsManifest.Name, a.Oss) == false {
			msg := fmt.Sprintf("OS Manifest %v is not compatible with App Manifest %v", ar.OsManifest.Name, a.Name)
			result.DevDescResult.OsAppsCompatibility.setFalseMulti(&msg)
			result.DevDescResult.Summary.Success = false
			result.Success = false
		}
	}
	return result
}

// Deduces jose signature algorithm from provided key type
func algFromKeyType(pub crypto.PublicKey) (jose.SignatureAlgorithm, error) {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		switch key.Size() {
		case 256:
			// FUTURE: use RSA PSS: PS256
			return jose.RS256, nil
		case 512:
			// FUTURE: use RSA PSS: PS512
			return jose.RS512, nil
		default:
			return jose.RS256, fmt.Errorf("Failed to determine algorithm from key type: unknown RSA key size: %v", key.Size())
		}
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P224(), elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		default:
			return jose.RS256, errors.New("Failed to determine algorithm from key type: unknown elliptic curve")
		}
	default:
		return jose.RS256, errors.New("Failed to determine algorithm from key type: unknown key type")
	}
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
		return nil, fmt.Errorf("Failed to parse x509 Certificate: %v", err)
	}
	return cert, nil
}

// loadPrivateKey loads a private key from PEM encoded data
func loadPrivateKey(data []byte) interface{} {
	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	var priv interface{}
	priv, err := x509.ParseECPrivateKey(input)
	if err != nil {
		log.Error("Failed to parse x509 Certificate ", err)
		return nil
	}
	return priv
}

// Verifies signatures and certificate chains for JWS tokens
// Optionally uses the 'OU' field of the certificate to check if the certificate
// was signed by a valid role.
func VerifyJws(data string, roots *x509.CertPool, roles []string) (JwsResult, []byte, bool) {
	opts := x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:     roots,
	}

	result := JwsResult{}
	ok := true

	jwsData, err := jose.ParseSigned(data)
	if err != nil {
		msg := fmt.Sprintf("Data could not be parsed - %v", err)
		result.Summary.setFalseMulti(&msg)
		return result, nil, false
	}

	if len(jwsData.Signatures) == 0 {
		msg := fmt.Sprintf("JWS does not contain signatures")
		result.Summary.setFalseMulti(&msg)
		return result, nil, false
	}

	index := make([]int, len(jwsData.Signatures))
	payloads := make([][]byte, len(jwsData.Signatures))
	for i, sig := range jwsData.Signatures {
		result.SignatureCheck = append(result.SignatureCheck, SignatureResult{})

		certs, err := sig.Protected.Certificates(opts)
		if err == nil {
			result.SignatureCheck[i].Name = certs[0][0].Subject.CommonName
			result.SignatureCheck[i].Organization = certs[0][0].Subject.Organization
			result.SignatureCheck[i].CertCheck.Success = true
		} else {
			if certs != nil {
				result.SignatureCheck[i].Name = certs[0][0].Subject.CommonName
				result.SignatureCheck[i].Organization = certs[0][0].Subject.Organization
			}
			msg := fmt.Sprintf("Validation of certificate chain failed: %v", err)
			result.SignatureCheck[i].CertCheck.setFalse(&msg)
			ok = false
			continue
		}

		index[i], _, payloads[i], err = jwsData.VerifyMulti(certs[0][0].PublicKey)
		if err == nil {
			result.SignatureCheck[i].Signature.Success = true
		} else {
			msg := fmt.Sprintf("Signature verification failed: %v", err)
			result.SignatureCheck[i].Signature.setFalse(&msg)
			ok = false
		}

		if index[i] != i {
			msg := fmt.Sprintf("Order of signatures incorrect")
			result.Summary.setFalseMulti(&msg)
		}

		if i > 0 {
			if bytes.Compare(payloads[i], payloads[i-1]) != 0 {
				msg := fmt.Sprintf("Payloads differ for jws with multiple signatures")
				result.Summary.setFalseMulti(&msg)
			}
		}

		// Optionally validate that the JWS token was signed with a certificate with the correct
		// role which is set in the 'OU' field of the certificate
		if roles != nil {
			if len(roles) != len(jwsData.Signatures) {
				msg := fmt.Sprintf("Expected %v signatures for JWS (got %v)", len(roles), len(jwsData.Signatures))
				result.Summary.setFalseMulti(&msg)
				return result, nil, false
			}
			r := certs[0][0].Subject.OrganizationalUnit[0]
			if r == roles[i] {
				rc := Result{
					Success: true}
				result.SignatureCheck[i].RoleCheck = &rc
			} else {
				rc := Result{}
				result.SignatureCheck[i].RoleCheck = &rc
				msg := fmt.Sprintf("Role %v does not match expected role %v", r, roles[i])
				result.SignatureCheck[i].RoleCheck.setFalse(&msg)
				ok = false
			}
		}
	}

	payload := payloads[0]
	result.Summary.Success = ok

	return result, payload, ok
}

func verifyAndUnpackAttestationReport(attestationReport string, result *VerificationResult, caCertPem []byte, roles *SignerRoles) (bool, *ArPlain) {
	if result == nil {
		log.Warn("Provided Validation Result was nil")
		return false, nil
	}

	ar := ArPlain{}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(caCertPem)
	if !ok {
		log.Warn("Failed to setup trusted cert pool")
		result.InternalError = true
		result.Success = true
		return false, &ar
	}

	// Roles are optional, only use them if provided
	r := SignerRoles{}
	if roles != nil {
		r = *roles
	}

	//Validate Attestation Report signature
	jwsValRes, payload, ok := VerifyJws(attestationReport, roots, r.ArSigners)
	result.ReportSignature = jwsValRes.SignatureCheck
	if !ok {
		log.Trace("Verification of Attestation Report Signatures failed")
		result.Success = false
		return false, &ar
	}

	var arJws ArJws
	err := json.Unmarshal(payload, &arJws)
	if err != nil {
		msg := fmt.Sprintf("Parsing of Attestation Report failed: %v", err)
		result.ProcessingError = append(result.ProcessingError, msg)
		log.Trace(msg)
		result.Success = false
		return false, &ar
	}

	ar.Type = "ArPlain"
	ar.TpmM = arJws.TpmM
	ar.SWM = arJws.SWM
	ar.Nonce = arJws.Nonce

	// Validate and unpack Rtm Manifest
	jwsValRes, payload, ok = VerifyJws(arJws.RtmManifest, roots, r.ManifestSigners)
	result.RtmResult.Summary = jwsValRes.Summary
	result.RtmResult.SignatureCheck = jwsValRes.SignatureCheck
	if !ok {
		log.Trace("Verification of RTM Manifest Signatures failed")
		result.Success = false
	}
	err = json.Unmarshal(payload, &ar.RtmManifest)
	if err != nil {
		msg := fmt.Sprintf("Unpacking of RTM Manifest failed: %v", err)
		result.RtmResult.Summary.setFalseMulti(&msg)
		result.Success = false
	} else {
		result.RtmResult.Name = ar.RtmManifest.Name
		result.RtmResult.ValidityCheck = checkValidity(ar.RtmManifest.Validity)
		if result.RtmResult.ValidityCheck.Success == false {
			result.RtmResult.Summary.Success = false
			result.Success = false
		}
	}

	// Validate and unpack OS Manifest
	jwsValRes, payload, ok = VerifyJws(arJws.OsManifest, roots, r.ManifestSigners)
	result.OsResult.Summary = jwsValRes.Summary
	result.OsResult.SignatureCheck = jwsValRes.SignatureCheck
	if !ok {
		log.Trace("Verification of OS Manifest Signatures failed")
		result.Success = false
	}
	err = json.Unmarshal(payload, &ar.OsManifest)
	if err != nil {
		msg := fmt.Sprintf("Unpacking of OS Manifest failed: %v", err)
		result.OsResult.Summary.setFalseMulti(&msg)
		result.Success = false
	} else {
		result.OsResult.Name = ar.OsManifest.Name
		result.OsResult.ValidityCheck = checkValidity(ar.OsManifest.Validity)
		if result.OsResult.ValidityCheck.Success == false {
			result.OsResult.Summary.Success = false
			result.Success = false
		}
	}

	// Validate and unpack App Manifests
	for i, amSigned := range arJws.AppManifests {
		result.AppResults = append(result.AppResults, ManifestResult{})

		jwsValRes, payload, ok = VerifyJws(amSigned, roots, r.ManifestSigners)
		result.AppResults[i].Summary = jwsValRes.Summary
		result.AppResults[i].SignatureCheck = jwsValRes.SignatureCheck
		if !ok {
			log.Trace("Verification of App Manifest Signatures failed")
			result.Success = false
		}

		var am AppManifest
		err = json.Unmarshal(payload, &am)
		if err != nil {
			msg := fmt.Sprintf("Unpacking of App Manifest failed: %v", err)
			result.AppResults[i].Summary.setFalseMulti(&msg)
			result.Success = false
		} else {
			ar.AppManifests = append(ar.AppManifests, am)
			result.AppResults[i].Name = am.Name
			result.AppResults[i].ValidityCheck = checkValidity(am.Validity)
			if result.AppResults[i].ValidityCheck.Success == false {
				log.Trace("App Manifest invalid - " + am.Name)
				result.AppResults[i].Summary.Success = false
				result.Success = false

			}
		}
	}

	// Validate and unpack Company Description
	jwsValRes, payload, ok = VerifyJws(arJws.CompanyDescription, roots, r.CompanyDescSigners)
	result.CompDescResult.Summary = jwsValRes.Summary
	result.CompDescResult.SignatureCheck = jwsValRes.SignatureCheck
	if !ok {
		log.Trace("Verification of Company Description Signatures failed")
		result.CompDescResult.Summary.Success = false
		result.Success = false
	}
	err = json.Unmarshal(payload, &ar.CompanyDescription)
	if err != nil {
		msg := fmt.Sprintf("Unpacking of Company Description failed: %v", err)
		result.CompDescResult.Summary.setFalseMulti(&msg)
		result.Success = false
	} else {
		result.CompDescResult.Name = ar.CompanyDescription.DN
		result.CompDescResult.CompCertLevel = ar.CompanyDescription.CertificationLevel

		result.CompDescResult.ValidityCheck = checkValidity(ar.CompanyDescription.Validity)
		if result.CompDescResult.ValidityCheck.Success == false {
			log.Trace("Company Description invalid")
			result.CompDescResult.Summary.Success = false
			result.Success = false
		}
	}

	// Validate and unpack Device Description
	jwsValRes, payload, ok = VerifyJws(arJws.DeviceDescription, roots, r.ConnDescSigners)
	result.DevDescResult.Summary = jwsValRes.Summary
	result.DevDescResult.SignatureCheck = jwsValRes.SignatureCheck
	if !ok {
		log.Trace("Verification of Device Description Signatures failed")
		result.Success = false
	}
	err = json.Unmarshal(payload, &ar.DeviceDescription)
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
		msg := fmt.Sprintf("Validity check failed: Artifact is not valid yet")
		result.setFalse(&msg)
	}

	if currentTime.After(notAfter) {
		msg := fmt.Sprintf("Validity check failed: Artifact validity has expired")
		result.setFalse(&msg)
	}

	return result
}

// Searches for a specific hash value in the verifications for RTM and OS
func getVerification(hash []byte, rtmVer, osVer []TpmVerification) *TpmVerification {
	for _, ver := range rtmVer {
		h, _ := hex.DecodeString(ver.Sha256)
		if bytes.Compare(h, hash) == 0 {
			return &ver
		}
	}

	for _, ver := range osVer {
		h, _ := hex.DecodeString(ver.Sha256)
		if bytes.Compare(h, hash) == 0 {
			return &ver
		}
	}
	return nil
}

// Computes the expected value for the specified PCR based on the verifications in the RTM and OS Manifests and
// counts the expected number of extension operations
func extendVerifications(pcr int, rtmVer, osVer []TpmVerification) ([]byte, int) {
	result := make([]byte, 32)
	n := 0
	for _, ver := range rtmVer {
		if !(pcr == ver.Pcr) {
			continue
		}
		h, _ := hex.DecodeString(ver.Sha256)
		result = extendHash(result, h)
		n++
	}

	for _, ver := range osVer {
		if !(pcr == ver.Pcr) {
			continue
		}
		h, _ := hex.DecodeString(ver.Sha256)
		result = extendHash(result, h)
		n++
	}
	return result, n
}

func verifyTpmMeasurements(tpmM *TpmMeasurement, nonce []byte, rtmVerifications, osVerifications []TpmVerification) (TpmMeasurementResult, bool) {
	result := TpmMeasurementResult{}
	ok := true

	// Extend the verifications to re-calculate the PCR value and evaluate it against the measured
	// PCR value. In case of a measurement list, also extend the measured values to re-calculate
	// the measured PCR value
	verifications := make(map[int][]byte)

	numExtends := 0
	for _, hce := range tpmM.HashChain {
		pcrRes := PcrResult{}
		pcrRes.Pcr = int(hce.Pcr)

		if len(hce.Sha256) == 1 {
			// This means, that the value from the PCR was directly taken for the measurement
			measurement, _ := hex.DecodeString(hce.Sha256[0])

			// Calculate the expected PCR value from the verifications
			ver, n := extendVerifications(int(hce.Pcr), rtmVerifications, osVerifications)
			verifications[int(hce.Pcr)] = ver
			numExtends += n

			// Compare the expected PCR value with the measured PCR value
			if bytes.Compare(measurement, verifications[int(hce.Pcr)]) == 0 {
				pcrRes.Validation.Success = true
			} else {
				msg := fmt.Sprintf("PCR value did not match expectation: %v vs. %v", hce.Sha256[0], hex.EncodeToString(verifications[int(hce.Pcr)]))
				pcrRes.Validation.setFalseMulti(&msg)
				ok = false
			}
		} else {
			// This means, that the values of the individual software artefacts were stored
			// In this case, we must extend those values in order to re-calculate the final
			// PCR value
			hash := make([]byte, 32)
			for _, sha256 := range hce.Sha256 {
				h, _ := hex.DecodeString(sha256)
				hash = extendHash(hash, h)

				// Check, if a verification exists for the measured value
				v := getVerification(h, rtmVerifications, osVerifications)
				if v != nil {
					pcrRes.Validation.Success = true
					verifications[int(hce.Pcr)] = hash
					numExtends++
				} else {
					msg := fmt.Sprintf("No verification found for measurement: %v", sha256)
					pcrRes.Validation.setFalseMulti(&msg)
					ok = false
				}
			}
		}
		result.PcrRecalculation = append(result.PcrRecalculation, pcrRes)
	}

	// Check that every verification was extended
	if numExtends != (len(rtmVerifications) + len(osVerifications)) {
		msg := fmt.Sprintf("Could not find each expected artefact in measurements (Total: %v, Expected: %v)", numExtends, len(rtmVerifications)+len(osVerifications))
		result.Summary.setFalse(&msg)
		ok = false
	}

	// Extract TPM Quote (TPMS ATTEST) and signature
	quote, err := hex.DecodeString(tpmM.Message)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode TPM quote: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}
	tpmsAttest, err := tpm2.DecodeAttestationData(quote)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode TPM attestation data: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}
	sig, err := hex.DecodeString(tpmM.Signature)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode TPM signature: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Verify nonce with nonce from TPM Quote
	if bytes.Compare(nonce, tpmsAttest.ExtraData) == 0 {
		result.QuoteFreshness.Success = true
	} else {
		msg := fmt.Sprintf("Nonces mismatch: Supplied Nonce = %v, TPM Quote Nonce = %v)", hex.EncodeToString(nonce), hex.EncodeToString(tpmsAttest.ExtraData))
		result.QuoteFreshness.setFalse(&msg)
		ok = false
	}

	// Verify aggregated PCR against TPM Quote PCRDigest: Hash all verifications together then compare
	sum := make([]byte, 0)
	for i := range tpmM.HashChain {
		_, ok := verifications[int(tpmM.HashChain[i].Pcr)]
		if !ok {
			continue
		}
		sum = append(sum, verifications[int(tpmM.HashChain[i].Pcr)]...)
	}
	verPcr := sha256.Sum256(sum)
	if bytes.Compare(verPcr[:], tpmsAttest.AttestedQuoteInfo.PCRDigest) == 0 {
		result.AggPcrQuoteMatch.Success = true
	} else {
		msg := fmt.Sprintf("Aggregated PCR does not match Quote PCR: %v vs. %v", hex.EncodeToString(verPcr[:]), hex.EncodeToString(tpmsAttest.AttestedQuoteInfo.PCRDigest))
		result.AggPcrQuoteMatch.setFalse(&msg)
		ok = false
	}

	result.QuoteSignature = verifyTpmQuoteSignature(quote, sig, tpmM.Certs.Leaf)
	if result.QuoteSignature.Signature.Success == false {
		ok = false
	}

	certCheck, certChainOk := verifyCertChain(&tpmM.Certs)
	if !certChainOk {
		ok = false
	}
	result.QuoteSignature.CertCheck = certCheck

	result.Summary.Success = ok

	return result, ok
}

func verifySwMeasurements(swMeasurements []SwMeasurement, appManifests []AppManifest) ([]SwMeasurementResult, bool) {
	swMeasurementResults := make([]SwMeasurementResult, 0)
	ok := true

	for _, swM := range swMeasurements {
		swRes := SwMeasurementResult{}
		swRes.Validation.Success = false
		swRes.MeasName = swM.Name

		for _, app := range appManifests {
			for _, swV := range app.Verifications {
				verificationHash, errv := hex.DecodeString(swM.Sha256)
				measurementHash, errm := hex.DecodeString(swV.Sha256)
				if (errm == nil) && (errv == nil) && bytes.Compare(verificationHash, measurementHash) == 0 {
					swRes.AppName = app.Name
					swRes.VerName = swV.Name
					swRes.Validation.Success = true
					break
				}
			}
		}

		if !swRes.Validation.Success {
			msg := fmt.Sprintf("No verification found for measurement: %v", swM.Sha256)
			swRes.Validation.setFalseMulti(&msg)
			ok = false
		}

		swMeasurementResults = append(swMeasurementResults, swRes)
	}

	// Check whether measurements were found for each delivered app manifest
	for _, app := range appManifests {
		for _, swV := range app.Verifications {

			found := false
			for _, smr := range swMeasurementResults {
				if smr.AppName == app.Name && smr.VerName == swV.Name {
					found = true
					break
				}
			}

			if !found {
				swRes := SwMeasurementResult{
					AppName: app.Name,
					VerName: swV.Name}
				msg := fmt.Sprintf("No measurement found for available verification: %v", swV.Sha256)
				swRes.Validation.setFalseMulti(&msg)
				ok = false
				swMeasurementResults = append(swMeasurementResults, swRes)
			}
		}
	}

	return swMeasurementResults, ok
}

func verifyCertChain(certs *CertChain) (Result, bool) {
	result := Result{}
	result.Success = true

	intermediatesPool := x509.NewCertPool()
	for _, intermediate := range certs.Intermediates {
		ok := intermediatesPool.AppendCertsFromPEM([]byte(intermediate))
		if !ok {
			msg := fmt.Sprintf("Failed to append certificate from PEM")
			result.setFalse(&msg)
			return result, false
		}
	}
	rootsPool := x509.NewCertPool()
	ok := rootsPool.AppendCertsFromPEM([]byte(certs.Ca))
	if !ok {
		msg := fmt.Sprintf("Failed to append certificate from PEM")
		result.setFalse(&msg)
		return result, false
	}

	block, _ := pem.Decode([]byte(certs.Leaf))
	if block == nil || block.Type != "CERTIFICATE" {
		msg := fmt.Sprintf("Failed to parse leaf certificate")
		result.setFalse(&msg)
		return result, false
	}
	leafCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse leaf certificate public key: %v", err)
		result.setFalse(&msg)
		return result, false
	}

	chain, err := leafCert.Verify(x509.VerifyOptions{Roots: rootsPool, Intermediates: intermediatesPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		msg := fmt.Sprintf("Failed to validate certificate chain: %v", err)
		result.setFalse(&msg)
		return result, false
	}

	expectedLen := len(intermediatesPool.Subjects()) + len(rootsPool.Subjects()) + 1
	if len(chain[0]) != expectedLen {
		msg := fmt.Sprintf("Expected chain of length %v (got %v)", expectedLen, len(chain[0]))
		result.setFalse(&msg)
		return result, false
	}

	return result, true
}

func verifyTpmQuoteSignature(quote, sig []byte, cert string) SignatureResult {
	result := SignatureResult{}
	result.Signature.Success = true

	buf := new(bytes.Buffer)
	buf.Write((sig))
	tpmtSig, err := tpm2.DecodeSignature(buf)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode TPM signature: %v", err)
		result.Signature.setFalse(&msg)
		return result
	}

	if tpmtSig.Alg != tpm2.AlgRSASSA {
		msg := fmt.Sprintf("Hash algorithm %v not supported", tpmtSig.Alg)
		result.Signature.setFalse(&msg)
		return result
	}

	// Extract public key from x509 certificate
	x509Cert, err := loadCert([]byte(cert))
	if err != nil {
		msg := fmt.Sprintf("Failed to parse TPM certificate: %v", err)
		result.Signature.setFalse(&msg)
		return result
	}
	pubKey, ok := x509Cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		msg := fmt.Sprintf("Failed to extract public key from certificate")
		result.Signature.setFalse(&msg)
		return result
	}
	hashAlg, err := tpmtSig.RSA.HashAlg.Hash()
	if err != nil {
		msg := fmt.Sprintf("Hash algorithm not supported")
		result.Signature.setFalse(&msg)
		return result
	}

	// Store Name and Organization of AK Cert for the report
	result.Name = x509Cert.Subject.CommonName
	result.Organization = x509Cert.Subject.Organization

	// Hash the quote and Verify the TPM Quote signature
	hashed := sha256.Sum256(quote)
	err = rsa.VerifyPKCS1v15(pubKey, hashAlg, hashed[:], tpmtSig.RSA.Signature)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify TPM quote signature: %v", err)
		result.Signature.setFalse(&msg)
		return result
	}
	return result
}

func verifySnpMeasurements(snpM *SnpMeasurement, v *SnpVerification, nonce []byte) (SnpMeasurementResult, bool) {
	result := SnpMeasurementResult{}
	ok := true

	var s snpreport
	b := bytes.NewBuffer(snpM.Report)

	err := binary.Read(b, binary.LittleEndian, &s)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode SNP attestation data: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Compare Nonce for Freshness (called Report Data in the SNP Attestation Report Structure)
	if cmp := bytes.Compare(s.ReportData[:], nonce); cmp != 0 {
		msg := fmt.Sprintf("Nonces mismatch: Supplied Nonce = %v, TPM Quote Nonce = %v)", hex.EncodeToString(nonce), hex.EncodeToString(s.ReportData[:]))
		result.Freshness.setFalse(&msg)
		ok = false
	}

	// Verify Signature, created with SNP VCEK private key
	sig, ret := verifySnpSignature(snpM.Report, s, []byte(snpM.Certs.Leaf))
	if !ret {
		ok = false
	}
	result.Signature = sig

	// Verify the SNP certificate chain
	certCheck, certChainOk := verifyCertChain(&snpM.Certs)
	if !certChainOk {
		ok = false
	}
	result.Signature.CertCheck = certCheck

	// Compare Measurements
	m, err := hex.DecodeString(v.Sha256)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode SNP Measurement: %v", err)
		result.Summary.setFalse(&msg)
		ok = false
	}
	if cmp := bytes.Compare(s.Measurement[:], m); cmp != 0 {
		msg := fmt.Sprintf("SNP Measurement mismatch: Supplied measurement = %v, SNP report measurement = %v", v.Sha256, hex.EncodeToString(s.Measurement[:]))
		result.MeasurementMatch.setFalse(&msg)
		ok = false
	}

	// Compare SNP parameters
	result.ParamsMatch, ret = verifySnpParams(&s, v)
	if !ret {
		ok = false
	}

	result.Summary.Success = ok

	return result, ok
}

func verifySnpParams(s *snpreport, v *SnpVerification) (Result, bool) {
	result := Result{
		Success: true,
	}

	if s.Version != v.Version {
		msg := fmt.Sprintf("SNP report version mismatch: Report = %v, supplied = %v", s.Version, v.Version)
		result.setFalse(&msg)
	}

	abiMajor := uint8(s.Policy & 0xFF)
	abiMinor := uint8((s.Policy >> 8) & 0xFF)
	smt := (s.Policy & (1 << 16)) != 0
	migration := (s.Policy & (1 << 18)) != 0
	debug := (s.Policy & (1 << 19)) != 0
	singleSocket := (s.Policy & (1 << 20)) != 0

	if abiMajor != v.Policy.AbiMajor {
		msg := fmt.Sprintf("SNP report AbiMinor mismatch: Report = %v, supplied = %v", abiMajor, v.Policy.AbiMajor)
		result.setFalse(&msg)
	}
	if abiMinor != v.Policy.AbiMinor {
		msg := fmt.Sprintf("SNP report AbiMinor mismatch: Report = %v, supplied = %v", abiMinor, v.Policy.AbiMinor)
		result.setFalse(&msg)
	}
	if smt != v.Policy.Smt {
		msg := fmt.Sprintf("SNP report SMT mismatch: Report = %v, supplied = %v", smt, v.Policy.Smt)
		result.setFalse(&msg)
	}
	if migration != v.Policy.Migration {
		msg := fmt.Sprintf("SNP report Migration Agent mismatch: Report = %v, supplied = %v", migration, v.Policy.Migration)
		result.setFalse(&msg)
	}
	if debug != v.Policy.Debug {
		msg := fmt.Sprintf("SNP report Debug Support mismatch: Report = %v, supplied = %v", debug, v.Policy.Debug)
		result.setFalse(&msg)
	}
	if singleSocket != v.Policy.SingleSocket {
		msg := fmt.Sprintf("SNP report SingleSocket mismatch: Report = %v, supplied = %v", singleSocket, v.Policy.SingleSocket)
		result.setFalse(&msg)
	}

	return result, result.Success
}

func checkExtensionUint8(cert *x509.Certificate, oid string, value uint8) error {

	for _, ext := range cert.Extensions {

		if ext.Id.String() == oid {
			if len(ext.Value) != 3 {
				return fmt.Errorf("Extension %v value unexpected length %v (expected 3)", oid, len(ext.Value))
			}
			if ext.Value[0] != 0x2 {
				return fmt.Errorf("Extension %v value[0] = %v does not match expected value 2", oid, ext.Value[0])
			}
			if ext.Value[1] != 0x1 {
				return fmt.Errorf("Extension %v value[1] = %v does not match expected value 1", oid, ext.Value[0])
			}
			if ext.Value[2] != value {
				return fmt.Errorf("Extension %v value[2] = %v does not match expected value %v", oid, ext.Value[0], value)
			}
			return nil
		}
	}

	return fmt.Errorf("Extension %v not present in certificate", oid)
}

func checkExtensionBuf(cert *x509.Certificate, oid string, buf []byte) error {

	for _, ext := range cert.Extensions {

		if ext.Id.String() == oid {
			if cmp := bytes.Compare(ext.Value, buf); cmp != 0 {
				return fmt.Errorf("Extension %v value %v does not match expected value %v", oid, hex.EncodeToString(ext.Value), hex.EncodeToString(buf))
			}
			return nil
		}
	}

	return fmt.Errorf("Extension %v not present in certificate", oid)
}

func checkExtensions(cert *x509.Certificate, report *snpreport) (ResultMulti, bool) {
	result := ResultMulti{}
	ok := true
	tcb := report.ReportedTcb

	if err := checkExtensionUint8(cert, "1.3.6.1.4.1.3704.1.3.1", uint8(tcb)); err != nil {
		msg := fmt.Sprintf("SEV BL Extension Check failed: %v", err)
		result.setFalseMulti(&msg)
		ok = false
	}

	if err := checkExtensionUint8(cert, "1.3.6.1.4.1.3704.1.3.2", uint8(tcb>>8)); err != nil {
		msg := fmt.Sprintf("SEV TEE Extension Check failed: %v", err)
		result.setFalseMulti(&msg)
		ok = false
	}

	if err := checkExtensionUint8(cert, "1.3.6.1.4.1.3704.1.3.3", uint8(tcb>>48)); err != nil {
		msg := fmt.Sprintf("SEV SNP Extension Check failed: %v", err)
		result.setFalseMulti(&msg)
		ok = false
	}

	if err := checkExtensionUint8(cert, "1.3.6.1.4.1.3704.1.3.8", uint8(tcb>>56)); err != nil {
		msg := fmt.Sprintf("SEV UCODE Extension Check failed: %v", err)
		result.setFalseMulti(&msg)
		ok = false
	}

	if err := checkExtensionBuf(cert, "1.3.6.1.4.1.3704.1.4", report.ChipId[:]); err != nil {
		msg := fmt.Sprintf("Chip ID Extension Check failed: %v", err)
		result.setFalseMulti(&msg)
		ok = false
	}

	result.Success = ok

	return result, ok
}

func verifySnpSignature(reportRaw []byte, report snpreport, cert []byte) (SignatureResult, bool) {
	result := SignatureResult{}

	if len(reportRaw) < (header_offset + signature_offset) {
		msg := fmt.Sprintf("Internal Error: Report buffer too small")
		result.Signature.setFalse(&msg)
		return result, false
	}

	// Strip the header and the signature from the report and hash for signature verification
	// Table 21, 23 @ https://www.amd.com/system/files/TechDocs/56860.pdf
	digest := sha512.Sum384(reportRaw[0x20 : 0x20+0x2A0])

	// Golang SetBytes expects BigEndian byte array, but SNP values are little endian
	rRaw := report.SignatureR[:]
	for i := 0; i < len(rRaw)/2; i++ {
		rRaw[i], rRaw[len(rRaw)-i-1] = rRaw[len(rRaw)-i-1], rRaw[i]
	}
	sRaw := report.SignatureS[:]
	for i := 0; i < len(sRaw)/2; i++ {
		sRaw[i], sRaw[len(sRaw)-i-1] = sRaw[len(sRaw)-i-1], sRaw[i]
	}

	// Convert r, s to Big Int
	r := new(big.Int)
	r.SetBytes(rRaw)
	s := new(big.Int)
	s.SetBytes(sRaw)

	// Load the VCEK certificate
	c, err := loadCert(cert)
	if err != nil {
		msg := fmt.Sprintf("Failed to load certificate: %v", err)
		result.Signature.setFalse(&msg)
		return result, false
	}
	result.Name = c.Subject.CommonName
	result.Organization = c.Subject.Organization

	// Examine SNP x509 extensions
	extensionResult, ok := checkExtensions(c, &report)
	result.ExtensionsCheck = &extensionResult
	if !ok {
		return result, false
	}

	// Check that the algorithm is supported
	if report.SignatureAlgo != ecdsa384_with_sha384 {
		msg := fmt.Sprintf("Siganture Algorithm %v not supported", report.SignatureAlgo)
		result.Signature.setFalse(&msg)
		return result, false
	}

	// Extract the public key from the certificate
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		msg := fmt.Sprintf("Failed to extract ECDSA public key from certificate")
		result.Signature.setFalse(&msg)
		return result, false
	}

	// Verify ECDSA Signature represented by r and s
	ok = ecdsa.Verify(pub, digest[:], r, s)
	if !ok {
		msg := fmt.Sprintf("Failed to verify SNP report signature")
		result.Signature.setFalse(&msg)
		return result, false
	}
	log.Trace("Successfully verified SNP report signature")

	return result, true
}

// Used for the JOSE Opaque Signer Interface. This enables signing
// the attestation report with hardware-based keys (such as TPM-based keys)
type hwSigner struct {
	pk     *jose.JSONWebKey
	signer crypto.PrivateKey
	alg    jose.SignatureAlgorithm
}

// Implements the JOSE Opaque Signer Interface. This enables signing
// the attestation report with hardware-based keys (such as TPM-based keys)
func (hws *hwSigner) Public() *jose.JSONWebKey {
	return hws.pk
}

// Implements the JOSE Opaque Signer Interface. This enables signing
// the attestation report with hardware-based keys (such as TPM-based keys)
func (hws *hwSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{hws.alg}
}

// Implements the JOSE Opaque Signer Interface. This enables signing
// the attestation report with hardware-based keys (such as TPM-based keys)
func (hws *hwSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	// EC-specific: key size in byte for later padding
	var keySize int
	// Determine hash / SignerOpts from algorithm
	var opts crypto.SignerOpts
	switch alg {
	case jose.RS256, jose.ES256: // RSA, ECDSA with SHA256
		keySize = 32 // 256 bit
		opts = crypto.SHA256
	case jose.PS256: // RSA PSS with SHA256
		// we force default saltLengths, same as x509 and TPM2.0
		opts = &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}
	case jose.RS384, jose.ES384: // RSA, ECDSA with SHA384
		keySize = 48
		opts = crypto.SHA384
	case jose.PS384: // RSA PSS with SHA384
		opts = &rsa.PSSOptions{SaltLength: 48, Hash: crypto.SHA384}
	case jose.RS512, jose.ES512: // RSA, ECDSA with SHA512
		keySize = 66 // 521 bit + padding
		opts = crypto.SHA512
	case jose.PS512: // RSA PSS with SHA512
		opts = &rsa.PSSOptions{SaltLength: 64, Hash: crypto.SHA512}
	default:
		return nil, errors.New("Signing failed: Could not determine appropriate hash type")
	}

	// Hash payload
	hasher := opts.HashFunc().New()
	// According to documentation, Write() on hash never fails
	_, _ = hasher.Write(payload)
	hashed := hasher.Sum(nil)

	// sign payload
	switch alg {
	case jose.ES256, jose.ES384, jose.ES512:
		// Obtain signature
		asn1Sig, err := hws.signer.(crypto.Signer).Sign(rand.Reader, hashed, opts)
		if err != nil {
			return nil, err
		}
		// Convert from asn1 format (as specified in crypto) to concatenated and padded format for go-jose
		type ecdsasig struct {
			R *big.Int
			S *big.Int
		}
		var esig ecdsasig
		ret := make([]byte, 2*keySize)
		_, err = asn1.Unmarshal(asn1Sig, &esig)
		if err != nil {
			return nil, errors.New("ECDSA Signature was not in expected format.")
		}
		// Fill return buffer with padded keys
		rBytes := esig.R.Bytes()
		sBytes := esig.S.Bytes()
		copy(ret[keySize-len(rBytes):keySize], rBytes)
		copy(ret[2*keySize-len(sBytes):2*keySize], sBytes)
		return ret, nil
	default:
		// The return format of all other signatures does not need to be adapted for go-jose
		return hws.signer.(crypto.Signer).Sign(rand.Reader, hashed, opts)
	}
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
	}
	log.Trace(*msg)
}

func (r *ResultMulti) setFalseMulti(msg *string) {
	r.Success = false
	if msg != nil {
		r.Details = append(r.Details, *msg)
	}
	log.Trace(*msg)
}
