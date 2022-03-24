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
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
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

// TpmCerts is a helper struct for the AK certificate chain
type TpmCerts struct {
	AkCert        string   `json:"akCert"`
	Intermediates []string `json:"akIntermediates"`
	CaCert        string   `json:"caCertificate"`
}

// TpmMeasurement represents the JSON attestation report
// element of type 'TPM Measurement'
type TpmMeasurement struct {
	Type      string           `json:"type"`
	Message   string           `json:"message"`
	Signature string           `json:"signature"`
	Certs     TpmCerts         `json:"certs"`
	HashChain []*HashChainElem `json:"hashChain"`
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
	Certs  TpmCerts
	UseIma bool
	ImaPcr int32
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
			log.Warnf("Failed to get measurements: %v\n", err)
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
		cert := loadCert(certPem)
		if cert == nil {
			log.Errorf("Failed to load cert[%v]", i)
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
		result.Success = false
		result.FreshnessCheck.Success = false
		msg := fmt.Sprintf("Failed to decode nonce in Attestation Report: %v", aerr)
		result.FreshnessCheck.Details = msg
		log.Trace(msg)
	}
	if res := bytes.Compare(arnonce, nonce); res != 0 {
		result.Success = false
		result.FreshnessCheck.Success = false
		msg := fmt.Sprintf("Nonces mismatch: SuppliedNonce = %v, AttestationReport Nonce = %v", vrNonceStr, ar.Nonce)
		result.FreshnessCheck.Details = msg
		log.Trace(msg)
	} else {
		result.FreshnessCheck.Success = true
	}

	// Verify TPM measurements if present: Extend the verifications to re-calculate the PCR value
	// and evaluate it against the measured PCR value. In case of a measurement list, also extend
	// the measured values to re-calculate the measured PCR value
	verifications := make(map[int][]byte)
	result.MeasResult.TpmMeasResult.Summary.Success = true

	numExtends := 0
	for _, hce := range ar.TpmM.HashChain {
		pcrRes := PcrResult{}
		pcrRes.Pcr = int(hce.Pcr)

		if len(hce.Sha256) == 1 {
			// This means, that the value from the PCR was directly taken for the measurement
			measurement, _ := hex.DecodeString(hce.Sha256[0])

			// Calculate the expected PCR value from the verifications
			ver, n := extendVerifications(int(hce.Pcr), ar.RtmManifest.Verifications, ar.OsManifest.Verifications)
			verifications[int(hce.Pcr)] = ver
			numExtends += n

			// Compare the expected PCR value with the measured PCR value
			if bytes.Compare(measurement, verifications[int(hce.Pcr)]) == 0 {
				pcrRes.Success = true
			} else {
				pcrRes.Success = false
				result.MeasResult.TpmMeasResult.Summary.Success = false
				result.Success = false
				msg := fmt.Sprintf("PCR value did not match expectation: %v vs. %v", hce.Sha256[0], hex.EncodeToString(verifications[int(hce.Pcr)]))
				pcrRes.Details = append(pcrRes.Details, msg)
				log.Warn(fmt.Sprintf("VERIFICATION ERROR: PCR%v: %v", hce.Pcr, msg))
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
				v := getVerification(h, ar.RtmManifest.Verifications, ar.OsManifest.Verifications)
				if v != nil {
					pcrRes.Success = true
					verifications[int(hce.Pcr)] = hash
					numExtends++
				} else {
					pcrRes.Success = false
					result.MeasResult.TpmMeasResult.Summary.Success = false
					result.Success = false
					msg := fmt.Sprintf("No verification found for measurement: %v", sha256)
					pcrRes.Details = append(pcrRes.Details, msg)
					log.Warn(fmt.Sprintf("VERIFICATION ERROR: PCR%v: %v", hce.Pcr, msg))
				}
			}
		}
		result.MeasResult.TpmMeasResult.PcrRecalculation = append(result.MeasResult.TpmMeasResult.PcrRecalculation, pcrRes)
	}

	// Check that every verification was extended
	if numExtends != (len(ar.OsManifest.Verifications) + len(ar.RtmManifest.Verifications)) {
		result.MeasResult.TpmMeasResult.Summary.Success = false
		result.Success = false
		msg := fmt.Sprintf("Could not find each expected artefact in measurements (Total: %v, Expected: %v)", numExtends, len(ar.OsManifest.Verifications)+len(ar.RtmManifest.Verifications))
		result.MeasResult.TpmMeasResult.Summary.Details = msg
		log.Trace(msg)
	}

	// Verify TPM measurements if present: Verify quote, signature and aggregated PCR value
	// As the TPM is currently the only implemented trust anchor, we always implement this check
	// TODO if other trust anchors are supported, evaluate which is present here
	tpmQuoteRes := verifyTpmMeasurements(&ar.TpmM, nonce, verifications)
	if tpmQuoteRes.Summary.Success == false {
		result.MeasResult.TpmMeasResult.Summary.Success = false
		result.Success = false
	}
	result.MeasResult.TpmMeasResult.AggPcrQuoteMatch = tpmQuoteRes.AggPcrQuoteMatch
	result.MeasResult.TpmMeasResult.QuoteFreshness = tpmQuoteRes.QuoteFreshness
	result.MeasResult.TpmMeasResult.QuoteSignature = tpmQuoteRes.QuoteSignature

	// Verify software measurements against app manifests
	for _, swM := range ar.SWM {
		swRes := SwMeasurementResult{}
		swRes.Success = false
		swRes.MeasName = swM.Name

		for _, app := range ar.AppManifests {
			for _, swV := range app.Verifications {
				verificationHash, errv := hex.DecodeString(swM.Sha256)
				measurementHash, errm := hex.DecodeString(swV.Sha256)
				if (errm == nil) && (errv == nil) && bytes.Compare(verificationHash, measurementHash) == 0 {
					swRes.AppName = app.Name
					swRes.VerName = swV.Name
					swRes.Success = true
					break
				}
			}
		}

		if swRes.Success == false {
			swRes.Details = "No verification found for available measurement"
			msg := fmt.Sprintf("VERIFICATION ERROR: Type: %v, Name: %v, Sha256: %v", swM.Type, swM.Name, swM.Sha256)
			log.Warn(msg)
		}

		result.MeasResult.SwMeasResult = append(result.MeasResult.SwMeasResult, swRes)
	}

	// Check whether measurements were found for each delivered app manifest
	for _, app := range ar.AppManifests {
		for _, swV := range app.Verifications {

			found := false
			for _, smr := range result.MeasResult.SwMeasResult {
				if smr.AppName == app.Name && smr.VerName == swV.Name {
					found = true
					break
				}
			}

			if found == false {
				swRes := SwMeasurementResult{}
				swRes.Success = false
				swRes.AppName = app.Name
				swRes.VerName = swV.Name
				swRes.Details = "No measurement found for available verification"
				result.MeasResult.SwMeasResult = append(result.MeasResult.SwMeasResult, swRes)
				msg := fmt.Sprintf("VERIFICATION ERROR: Type: %v, Name: %v, Sha256: %v", swV.Type, swV.Name, swV.Sha256)
				log.Warn(msg)
			}
		}
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
		result.DevDescResult.CorrectRtm.Success = false
		msg := fmt.Sprintf("Device Description listed wrong RTM Manifest: %v vs. %v\n", ar.DeviceDescription.RtmManifest, ar.RtmManifest.Name)
		result.DevDescResult.CorrectRtm.Details = msg
		result.DevDescResult.Summary.Success = false
		result.Success = false
		log.Trace(msg)
	}
	if ar.DeviceDescription.OsManifest == ar.OsManifest.Name {
		result.DevDescResult.CorrectOs.Success = true
	} else {
		result.DevDescResult.CorrectOs.Success = false
		msg := fmt.Sprintf("Device Description listed wrong OS Manifest: %v vs. %v\n", ar.DeviceDescription.OsManifest, ar.OsManifest.Name)
		result.DevDescResult.CorrectOs.Details = msg
		result.DevDescResult.Summary.Success = false
		result.Success = false
		log.Trace(msg)
	}

	// Check that every AppManifest has a corresponding AppDescription
	result.DevDescResult.CorrectApps.Success = true
	for _, a := range ar.AppManifests {
		if contains(a.Name, appDescriptions) == false {
			result.DevDescResult.CorrectApps.Success = false
			msg := fmt.Sprintf("Device Description does not list the following App Manifest: %v\n", a.Name)
			result.DevDescResult.CorrectApps.Details = result.DevDescResult.CorrectApps.Details + msg
			result.DevDescResult.Summary.Success = false
			result.Success = false
			log.Trace(msg)
		}
	}

	// Check that the Rtm Manifest is compatible with the OS Manifest
	if contains(ar.RtmManifest.Name, ar.OsManifest.Rtms) {
		result.DevDescResult.RtmOsCompatibility.Success = true
	} else {
		result.DevDescResult.RtmOsCompatibility.Success = false
		msg := fmt.Sprintf("RTM Manifest %v is not compatible with OS Manifest %v", ar.RtmManifest.Name, ar.OsManifest.Name)
		result.DevDescResult.RtmOsCompatibility.Details = msg
		result.DevDescResult.Summary.Success = false
		result.Success = false
		log.Trace(msg)
	}

	// Check that the OS Manifest is compatible with all App Manifests
	result.DevDescResult.OsAppsCompatibility.Success = true
	for _, a := range ar.AppManifests {
		if contains(ar.OsManifest.Name, a.Oss) == false {
			result.DevDescResult.OsAppsCompatibility.Success = false
			msg := fmt.Sprintf("OS Manifest %v is not compatible with App Manifest %v\n", ar.OsManifest.Name, a.Name)
			result.DevDescResult.OsAppsCompatibility.Details = result.DevDescResult.OsAppsCompatibility.Details + msg
			result.DevDescResult.Summary.Success = false
			result.Success = false
			log.Trace(msg)
		}
	}
	return result
}

// Deduces jose signature algoritm from provided key type
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

func extendHash(hash []byte, extend []byte) []byte {
	concat := append(hash, extend...)
	h := sha256.Sum256(concat)
	ret := make([]byte, 32)
	copy(ret, h[:])
	return ret
}

// loadCert loads a certificate from PEM encoded data
func loadCert(data []byte) *x509.Certificate {
	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	cert, err := x509.ParseCertificate(input)
	if err != nil {
		log.Error("Failed to parse x509 Certificate ", err)
		return nil
	}
	return cert
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

// Verifies signature and certificate chain for JWS tokens with multiple signatures,
// e.g. manifests or company descriptions
// Currently uses the 'OU' field of the certificate to check if the certificate
// was signed by a valid role.
func verifyJws(data string, roots *x509.CertPool, roles []string) (JwsResult, []byte) {
	//Extract certificates and validate certificate chains in the process
	opts := x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:     roots,
	}

	result := JwsResult{}
	result.Summary.Success = true

	jwsData, err := jose.ParseSigned(data)
	if err != nil {
		result.Summary.Success = false
		msg := fmt.Sprintf("Data could not be parsed - %v\n", err)
		result.Summary.Details = msg
		log.Trace(msg)
		return result, nil
	}

	if len(jwsData.Signatures) == 0 {
		result.Summary.Success = false
		msg := fmt.Sprintf("JWS does not contain signatures\n")
		result.Summary.Details = msg
		log.Trace(msg)
		return result, nil
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
			result.SignatureCheck[i].CertCheck.Success = false
			msg := fmt.Sprintf("Validation of certificate chain failed: %v\n", err)
			result.SignatureCheck[i].CertCheck.Details = msg
			result.Summary.Success = false
			log.Trace(msg)
			continue
		}

		index[i], _, payloads[i], err = jwsData.VerifyMulti(certs[0][0].PublicKey)
		if err == nil {
			result.SignatureCheck[i].Signature.Success = true
		} else {
			result.SignatureCheck[i].Signature.Success = false
			result.SignatureCheck[i].Signature.Details = fmt.Sprintf("Signature verification failed: %v\n", err)
			result.Summary.Success = false
			log.Warn(fmt.Sprintf("VERIFICATION ERROR: Signature from %v: %v - %v", certs[0][0].Subject.OrganizationalUnit[0], certs[0][0].Subject.CommonName, err))
		}

		if index[i] != i {
			result.Summary.Success = false
			msg := fmt.Sprintf("Order of signatures incorrect\n")
			result.Summary.Details = result.Summary.Details + msg
			log.Trace(msg)
		}

		if i > 0 {
			if bytes.Compare(payloads[i], payloads[i-1]) != 0 {
				result.Summary.Success = false
				msg := fmt.Sprintf("Payloads differ for jws with multiple signatures")
				result.Summary.Details = result.Summary.Details + msg
				log.Trace(msg)
			}
		}

		// Optionally validate that the JWS token was signed with a certificate with the correct
		// role which is set in the 'OU' field of the certificate
		if roles != nil {
			if len(roles) != len(jwsData.Signatures) {
				result.Summary.Success = false
				msg := fmt.Sprintf("Expected %v signatures for JWS (got %v)", len(roles), len(jwsData.Signatures))
				result.Summary.Details = result.Summary.Details + msg
				log.Trace(msg)
				return result, nil
			}
			r := certs[0][0].Subject.OrganizationalUnit[0]
			if r == roles[i] {
				rc := Result{
					Success: true}
				result.SignatureCheck[i].RoleCheck = &rc
			} else {
				rc := Result{
					Success: false,
					Details: fmt.Sprintf("Role %v does not match expected role %v", r, roles[i])}
				result.SignatureCheck[i].RoleCheck = &rc
				result.Summary.Success = false
				log.Warn(fmt.Sprintf("VERIFICATION ERROR: Role %v does not match expected role %v", r, roles[i]))
			}
		}
	}

	payload := payloads[0]

	return result, payload
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
		result.Success = false
		msg := "Failed to setup trusted cert pool\n"
		result.ProcessingError = result.ProcessingError + msg
		log.Warn(msg)
		result.InternalError = true
		return false, &ar
	}

	// Roles are optional, only use them if provided
	r := SignerRoles{}
	if roles != nil {
		r = *roles
	}

	//Validate Attestation Report signature
	jwsValRes, payload := verifyJws(attestationReport, roots, r.ArSigners)
	if jwsValRes.Summary.Success == true {
		result.ReportSignature = jwsValRes.SignatureCheck
	} else {
		result.ReportSignature = jwsValRes.SignatureCheck
		log.Trace("Verification of Attestation Report Signatures failed")
	}

	var arJws ArJws
	err := json.Unmarshal(payload, &arJws)
	if err != nil {
		result.Success = false
		msg := fmt.Sprintf("Parsing of Attestation Report failed: %v\n", err)
		result.ProcessingError = result.ProcessingError + msg
		log.Trace(msg)
		return false, &ar
	}

	ar.Type = "ArPlain"
	ar.TpmM = arJws.TpmM
	ar.SWM = arJws.SWM
	ar.Nonce = arJws.Nonce

	//Validate and unpack Rtm Manifest
	jwsValRes, payload = verifyJws(arJws.RtmManifest, roots, r.ManifestSigners)
	if jwsValRes.Summary.Success == true {
		result.RtmResult.Summary = jwsValRes.Summary
		result.RtmResult.SignatureCheck = jwsValRes.SignatureCheck
	} else {
		result.Success = false
		result.RtmResult.Summary = jwsValRes.Summary
		result.RtmResult.SignatureCheck = jwsValRes.SignatureCheck
		log.Trace("Verification of RTM Manifest Signatures failed")
	}

	err = json.Unmarshal(payload, &ar.RtmManifest)
	if err != nil {
		result.Success = false
		msg := fmt.Sprintf("Unpacking of RTM Manifest failed: %v\n", err)
		result.ProcessingError = result.ProcessingError + msg
		log.Trace(msg)
	}
	result.RtmResult.Name = ar.RtmManifest.Name

	valRes := checkValidity(ar.RtmManifest.Validity)
	if valRes.Success == false {
		result.Success = false
		log.Trace("RTM Manifest invalid")
	}
	result.RtmResult.ValidityCheck = valRes

	//Validate and unpack OS Manifest
	jwsValRes, payload = verifyJws(arJws.OsManifest, roots, r.ManifestSigners)
	if jwsValRes.Summary.Success == true {
		result.OsResult.Summary = jwsValRes.Summary
		result.OsResult.SignatureCheck = jwsValRes.SignatureCheck
	} else {
		result.Success = false
		result.OsResult.Summary = jwsValRes.Summary
		result.OsResult.SignatureCheck = jwsValRes.SignatureCheck
		log.Trace("Verification of OS Manifest Signatures failed")
	}

	err = json.Unmarshal(payload, &ar.OsManifest)
	if err != nil {
		result.Success = false
		msg := fmt.Sprintf("Unpacking of OS Manifest failed: %v\n", err)
		result.ProcessingError = result.ProcessingError + msg
		log.Trace(msg)
	}
	result.OsResult.Name = ar.OsManifest.Name

	valRes = checkValidity(ar.OsManifest.Validity)
	if valRes.Success == false {
		result.Success = false
		log.Trace("OS Manifest invalid")
	}
	result.OsResult.ValidityCheck = valRes

	//Validate and unpack App Manifests
	for i, amSigned := range arJws.AppManifests {
		result.AppResults = append(result.AppResults, ManifestResult{})
		jwsValRes, payload = verifyJws(amSigned, roots, r.ManifestSigners)
		if jwsValRes.Summary.Success == true {
			result.AppResults[i].Summary = jwsValRes.Summary
			result.AppResults[i].SignatureCheck = jwsValRes.SignatureCheck
		} else {
			result.Success = false
			result.AppResults[i].Summary = jwsValRes.Summary
			result.AppResults[i].SignatureCheck = jwsValRes.SignatureCheck
			log.Trace("Verification of App Manifest Signatures failed")
		}

		var am AppManifest
		err = json.Unmarshal(payload, &am)
		if err != nil {
			result.Success = false
			msg := fmt.Sprintf("Unpacking of App Manifest failed: %v\n", err)
			result.ProcessingError = result.ProcessingError + msg
			log.Trace(msg)
		}
		ar.AppManifests = append(ar.AppManifests, am)
		result.AppResults[i].Name = am.Name

		valRes = checkValidity(am.Validity)
		if valRes.Success == false {
			result.Success = false
			log.Trace("App Manifest invalid - " + am.Name)
		}
		result.AppResults[i].ValidityCheck = valRes
	}

	// Validate and unpack Company Description
	jwsValRes, payload = verifyJws(arJws.CompanyDescription, roots, r.CompanyDescSigners)
	result.CompDescResult.SignatureCheck = jwsValRes.SignatureCheck
	if jwsValRes.Summary.Success == false {
		result.Success = false
		log.Trace("Verification of Company Description Signatures failed")
	}

	err = json.Unmarshal(payload, &ar.CompanyDescription)
	if err != nil {
		result.Success = false
		msg := fmt.Sprintf("Unpacking of Company Description failed: %v\n", err)
		result.ProcessingError = result.ProcessingError + msg
		log.Trace(msg)
	}
	result.CompDescResult.Name = ar.CompanyDescription.DN
	result.CompDescResult.CompCertLevel = ar.CompanyDescription.CertificationLevel

	valRes = checkValidity(ar.CompanyDescription.Validity)
	if valRes.Success == false {
		result.Success = false
		log.Trace("Company Description invalid")
	}
	result.CompDescResult.ValidityCheck = valRes

	//Validate and unpack Device Description
	jwsValRes, payload = verifyJws(arJws.DeviceDescription, roots, r.ConnDescSigners)
	result.DevDescResult.Summary = jwsValRes.Summary
	result.DevDescResult.SignatureCheck = jwsValRes.SignatureCheck
	if jwsValRes.Summary.Success == false {
		result.Success = false
		log.Trace("Verification of Device Description Signatures failed")
	}

	err = json.Unmarshal(payload, &ar.DeviceDescription)
	if err != nil {
		result.Success = false
		msg := fmt.Sprintf("Unpacking of Device Description failed: %v\n", err)
		result.ProcessingError = result.ProcessingError + msg
		log.Trace(msg)
	}

	// Compare the device and the operator affiliation (based on "organization" field in the identity certificates)
	found := false
	for _, o := range result.DevDescResult.SignatureCheck[0].Organization {
		if contains(o, result.ReportSignature[0].Organization) {
			result.DevDescResult.OpAffiliation.Success = true
			found = true
			break
		}
	}
	if found == false {
		result.DevDescResult.OpAffiliation.Success = false
		msg := fmt.Sprintf("No match for affiliations of operator and device certificate: %v vs %v", result.DevDescResult.SignatureCheck[0].Organization, result.ReportSignature[0].Organization)
		result.DevDescResult.OpAffiliation.Details = msg
		result.Success = false
		log.Trace(msg)
	}

	result.PlainAttReport = ar
	return true, &ar
}

func checkValidity(val Validity) Result {
	result := Result{}
	result.Success = true

	notBefore, err := time.Parse(timeLayout, val.NotBefore)
	if err != nil {
		result.Success = false
		result.Details = fmt.Sprintf("Failed to parse NotBefore time. Time.Parse returned %v", err)
		return result
	}
	notAfter, err := time.Parse(timeLayout, val.NotAfter)
	if err != nil {
		result.Success = false
		result.Details = fmt.Sprintf("Failed to parse NotAfter time. Time.Parse returned %v", err)
		return result
	}
	currentTime := time.Now()

	if notBefore.After(currentTime) {
		result.Success = false
		result.Details = fmt.Sprintf("Validity check failed: Artifact is not valid yet")
	}

	if currentTime.After(notAfter) {
		result.Success = false
		result.Details = fmt.Sprintf("Validity check failed: Artifact validity has expired")
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
	extend := make([]byte, 32)
	n := 0
	for _, ver := range rtmVer {
		if !(pcr == ver.Pcr) {
			continue
		}
		h, _ := hex.DecodeString(ver.Sha256)
		extend = extendHash(extend, h)
		n++
	}

	for _, ver := range osVer {
		if !(pcr == ver.Pcr) {
			continue
		}
		h, _ := hex.DecodeString(ver.Sha256)
		extend = extendHash(extend, h)
		n++
	}
	return extend, n
}

func verifyTpmMeasurements(tpmM *TpmMeasurement, nonce []byte, verifications map[int][]byte) TpmMeasurementResult {
	result := TpmMeasurementResult{}
	result.Summary.Success = true

	if len(tpmM.HashChain) != len(verifications) {
		result.Summary.Success = false
		msg := fmt.Sprintf("Number of measured PCRs does not match with verifications: %v vs %v", len(tpmM.HashChain), len(verifications))
		result.Summary.Details = msg
		log.Trace(msg)
		return result
	}

	// Iterate through verifications and compare PCR values to measurement PCR values
	// TODO: can be removed since the recalculation of PCRs and comparison to verifications is covered in Verify()
	for i := range tpmM.HashChain {

		verPcr, ok := verifications[int(tpmM.HashChain[i].Pcr)]
		if !ok {
			result.Summary.Success = false
			msg := fmt.Sprintf("Cannot find verification for measured PCR%v", tpmM.HashChain[i].Pcr)
			result.Summary.Details = msg
			log.Trace(msg)
			continue
		}

		// The measurements can contain the PCR value directly or the list that was
		// extended into the PCR
		var measPcr []byte
		if len(tpmM.HashChain[i].Sha256) == 1 {
			measPcr, _ = hex.DecodeString(tpmM.HashChain[i].Sha256[0])
		} else {
			hash := make([]byte, 32)
			for _, sha256 := range tpmM.HashChain[i].Sha256 {
				h, _ := hex.DecodeString(sha256)
				hash = extendHash(hash, h)
			}
			measPcr = hash
		}

		if bytes.Compare(measPcr, verPcr) == 0 {
			result.Summary.Success = true
		} else {
			result.Summary.Success = false
			result.Summary.Details = fmt.Sprintf("Validation failed for the measured PCR value: %v", hex.EncodeToString(measPcr))
			log.Warn(fmt.Sprintf("VERIFICATION ERROR - PCR%v: %v", tpmM.HashChain[i].Pcr, hex.EncodeToString(measPcr)))
		}
	}

	// Extract TPM Quote (TPMS ATTEST) and signature
	quote, err := hex.DecodeString(tpmM.Message)
	if err != nil {
		result.Summary.Success = false
		msg := fmt.Sprintf("Failed to decode TPM quote: %v", err)
		result.Summary.Details = msg
		log.Trace(msg)
		return result
	}

	sig, err := hex.DecodeString(tpmM.Signature)
	if err != nil {
		result.Summary.Success = false
		msg := fmt.Sprintf("Failed to decode TPM signature: %v", err)
		result.Summary.Details = msg
		log.Trace(msg)
		return result
	}

	tpmsAttest, err := tpm2.DecodeAttestationData(quote)
	if err != nil {
		result.Summary.Success = false
		msg := fmt.Sprintf("Failed to decode TPM attestation data: %v", err)
		result.Summary.Details = msg
		log.Warn("VERIFCATION ERROR: ", msg)
		return result
	}

	// Verify nonce with nonce from TPM Quote
	if bytes.Compare(nonce, tpmsAttest.ExtraData) == 0 {
		result.QuoteFreshness.Success = true
	} else {
		result.QuoteFreshness.Success = false
		msg := fmt.Sprintf("Nonces mismatch: Supplied Nonce = %v, TPM Quote Nonce = %v)", hex.EncodeToString(nonce), hex.EncodeToString(tpmsAttest.ExtraData))
		result.QuoteFreshness.Details = msg
		result.Summary.Success = false
		log.Trace(msg)
	}

	// Verify aggregated PCR against TPM Quote PCRDigest: Hash all verifications together then compare
	sum := make([]byte, 0)
	for i := range tpmM.HashChain {
		sum = append(sum, verifications[int(tpmM.HashChain[i].Pcr)]...)
	}
	verPcr := sha256.Sum256(sum)
	if bytes.Compare(verPcr[:], tpmsAttest.AttestedQuoteInfo.PCRDigest) == 0 {
		result.AggPcrQuoteMatch.Success = true
	} else {
		result.AggPcrQuoteMatch.Success = false
		msg := fmt.Sprintf("Aggregated PCR does not match Quote PCR: %v vs. %v", hex.EncodeToString(verPcr[:]), hex.EncodeToString(tpmsAttest.AttestedQuoteInfo.PCRDigest))
		result.AggPcrQuoteMatch.Details = msg
		result.Summary.Success = false
		log.Trace(msg)
	}

	result.QuoteSignature = verifyTpmQuoteSignature(quote, sig, tpmM.Certs.AkCert)
	if result.QuoteSignature.Signature.Success == false {
		result.Summary.Success = false
	}

	result.QuoteSignature.CertCheck = verifyTpmCertChain(&tpmM.Certs)
	if result.QuoteSignature.CertCheck.Success == false {
		result.Summary.Success = false
	}
	return result
}

func verifyTpmCertChain(certs *TpmCerts) Result {
	result := Result{}
	result.Success = true

	intermediatesPool := x509.NewCertPool()
	for _, intermediate := range certs.Intermediates {
		ok := intermediatesPool.AppendCertsFromPEM([]byte(intermediate))
		if !ok {
			result.Success = false
			msg := fmt.Sprintf("Failed to append certificate from PEM")
			result.Details = msg
			log.Trace(msg)
			return result
		}
	}
	rootsPool := x509.NewCertPool()
	ok := rootsPool.AppendCertsFromPEM([]byte(certs.CaCert))
	if !ok {
		result.Success = false
		msg := fmt.Sprintf("Failed to append certificate from PEM")
		result.Details = msg
		log.Trace(msg)
		return result
	}

	block, _ := pem.Decode([]byte(certs.AkCert))
	if block == nil || block.Type != "CERTIFICATE" {
		result.Success = false
		msg := fmt.Sprintf("Failed to parse AK certificate")
		result.Details = msg
		log.Trace(msg)
		return result
	}
	akCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		result.Success = false
		msg := fmt.Sprintf("Failed to parse AK: %v", err)
		result.Details = msg
		log.Trace(msg)
		return result
	}

	chain, err := akCert.Verify(x509.VerifyOptions{Roots: rootsPool, Intermediates: intermediatesPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		result.Success = false
		msg := fmt.Sprintf("Failed to validate AK cert chain: %v", err)
		result.Details = msg
		log.Trace(msg)
		return result
	}

	expectedLen := len(intermediatesPool.Subjects()) + len(rootsPool.Subjects()) + 1
	if len(chain[0]) != expectedLen {
		result.Success = false
		msg := fmt.Sprintf("Expected chain of length %v (got %v)", expectedLen, len(chain[0]))
		result.Details = msg
		log.Trace(msg)
		return result
	}

	return result
}

func verifyTpmQuoteSignature(quote, sig []byte, cert string) SignatureResult {
	result := SignatureResult{}
	result.Signature.Success = true

	buf := new(bytes.Buffer)
	buf.Write((sig))
	tpmtSig, err := tpm2.DecodeSignature(buf)
	if err != nil {
		result.Signature.Success = false
		msg := fmt.Sprintf("Failed to decode TPM signature: %v", err)
		result.Signature.Details = msg
		log.Trace(msg)
		return result
	}

	if tpmtSig.Alg != tpm2.AlgRSASSA {
		result.Signature.Success = false
		msg := fmt.Sprintf("Hash algorithm %v not supported", tpmtSig.Alg)
		result.Signature.Details = msg
		log.Trace(msg)
		return result
	}

	// Extract public key from x509 certificate
	p, _ := pem.Decode([]byte(cert))
	if p == nil {
		result.Signature.Success = false
		msg := fmt.Sprintf("Failed to decode TPM certificate")
		result.Signature.Details = msg
		log.Trace(msg)
		return result
	}
	x509Cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		result.Signature.Success = false
		msg := fmt.Sprintf("Failed to parse TPM certificate: %v", err)
		result.Signature.Details = msg
		log.Trace(msg)
		return result
	}
	pubKey, ok := x509Cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		result.Signature.Success = false
		msg := fmt.Sprintf("Failed to extract public key from certificate")
		result.Signature.Details = msg
		log.Trace(msg)
		return result
	}
	hashAlg, err := tpmtSig.RSA.HashAlg.Hash()
	if err != nil {
		result.Signature.Success = false
		msg := fmt.Sprintf("Hash algorithm not supported")
		result.Signature.Details = msg
		log.Trace(msg)
		return result
	}

	// Store Name and Organization of AK Cert for the report
	result.Name = x509Cert.Subject.CommonName
	result.Organization = x509Cert.Subject.Organization

	// Hash the quote and Verify the TPM Quote signature
	hashed := sha256.Sum256(quote)
	err = rsa.VerifyPKCS1v15(pubKey, hashAlg, hashed[:], tpmtSig.RSA.Signature)
	if err != nil {
		result.Signature.Success = false
		msg := fmt.Sprintf("Failed to verify TPM quote signature: %v\n", err)
		result.Signature.Details = msg
		log.Trace(msg)
		return result
	}
	return result
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
