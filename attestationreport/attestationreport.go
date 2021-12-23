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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"

	"gopkg.in/square/go-jose.v2"

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

// HashChainElem represents the JSON attestation report
// element of type 'Hash Chain' embedded in 'TPM Measurement'
type HashChainElem struct {
	Type   string   `json:"type"`
	Pcr    int32    `json:"pcr"`
	Sha256 []string `json:sha256"`
}

// TpmCerts is a helper struct for the AK certificate chain
type TpmCerts struct {
	AkCert        string   `json:"akCert"`
	Intermediates []string `json:"akIntermediates"`
	CaCert        string   `json:"caCertificate"`
}

// TpmMeasurement represents the JSON attestation report
// element of type 'TPM Measurement' signed by the device
type TpmMeasurement struct {
	Type      string           `json:"type"`
	Message   string           `json:"message"`
	Signature string           `json:"signature"`
	Certs     TpmCerts         `json:"certs"`
	HashChain []*HashChainElem `json:"hashChain"`
}

// SwMeasurement represents the JSON attestation report
// element of type 'Software Measurement' signed by the device
type SwMeasurement struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Sha256 string `json:"sha256"`
}

// TpmVerification represents the JSON attestation report
// element of type 'TPM Verification' signed by the device
type TpmVerification struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Pcr    int    `json:"pcr"`
	Sha256 string `json:"sha256"`
}

// SwVerification represents the JSON attestation report
// element of type 'Software Verification' signed by the device
type SwVerification struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Sha256 string `json:"sha256"`
}

// AppDescription represents the JSON attestation report
// element of type 'App Description' signed by the operator
type AppDescription struct {
	Type        string              `json:"type"`
	Name        string              `json:"name"`
	AppManifest string              `json:"appManifest"` // Links to Type 'App Manifest'->'Name'
	External    []ExternalInterface `json:"externalConnections"`
}

// InternalConnection represents the JSON attestation report
// element of type 'Internal Connection' signed by the operator
type InternalConnection struct {
	Type         string `json:"type"`
	NameAppA     string `json:"nameAppA"`     // Links to Type 'App Description'->'Name'
	EndpointAppA string `json:"endpointAppA"` // Links to Type 'App Manifest'->'Endpoint'
	NameAppB     string `json:"nameAppB"`     // Links to Type 'App Description'->'Name'
	EndpointAppB string `json:"endpointAppB"` // Links to Type 'App Manifest'->'Endpoint'
}

// ExternalInterface represents the JSON attestation report
// element of type 'External Interfaces' signed by the operator
type ExternalInterface struct {
	Type        string `json:"type"`
	AppEndpoint string `json:"appEndpoint"` // Links to Type 'App Manifest'->'Endpoint'
	Interface   string `json:"interface"`   // Links to Type 'App Description'->'Name'
	Port        int    `json:"port"`        // Links to Type 'App Manifest'->'Endpoint'
}

// AppManifest represents the JSON attestation report
// element of type 'App Manifest' signed by developer, evaluator, certifier
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
// element of type 'OsManifest' signed by developer, evaluator, certifier
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
// element of type 'RTM Manifest' signed by developer, evaluator, certifier
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

// ConnectorDescription represents the JSON attestation report
// element of type 'Connector Description' signed by the operator
type ConnectorDescription struct {
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
// element of type 'Company Description' signed by company representative, evaluator, certifier
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
	Type                 string               `json:"type"`
	TpmM                 TpmMeasurement       `json:"tpmMeasurement,omitempty"`
	SWM                  []SwMeasurement      `json:"swMeasurements,omitempty"`
	RtmManifest          RtmManifest          `json:"rtmManifest"`
	OsManifest           OsManifest           `json:"osManifest"`
	AppManifests         []AppManifest        `json:"appManifests"`
	CompanyDescription   CompanyDescription   `json:"companyDescription"`
	ConnectorDescription ConnectorDescription `json:"connectorDescription"`
	Nonce                string               `json:"nonce"`
}

// ArJws represents the attestation report in JWS format with its
// contents already in signed JWs format
type ArJws struct {
	Type                 string          `json:"type"`
	TpmM                 TpmMeasurement  `json:"tpmMeasurement,omitempty"`
	SWM                  []SwMeasurement `json:"swMeasurements,omitempty"`
	RtmManifest          string          `json:"rtmManifests"`
	OsManifest           string          `json:"osManifest"`
	AppManifests         []string        `json:"appManifests"`
	CompanyDescription   string          `json:"companyDescription"`
	ConnectorDescription string          `json:"connectorDescription"`
	Nonce                string          `json:"nonce"`
}

// VerificationResult represents the following JSON attestation report
// element of type 'Verification Result'.
type VerificationResult struct {
	Type      string   `json:"type"`
	Success   bool     `json:"raSuccessful"`
	CertLevel int      `json:"certificationLevel"`
	Log       []string `json:"log"`
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

// The different certificates used for signing meta-data must have
// appropriate roles which is currently set in the OrganizationalUnit (OU)
// field in the x.509 certificates
var (
	manifestSignerRoles   = []string{"developer", "evaluator", "certifier"}
	companyDesSignerRoles = []string{"operator", "evaluator", "certifier"}
	arSignerRole          = string("device")
	connDesSignerRole     = string("operator")
)

// GenAttestationReport generates an attestation report with the provided
// nonce 'nonce' and manifests and descriptions 'metadata'. The manifests and
// descriptions must be raw JWS tokens in the JWS JSON full serialization
// format. Takes a list of 'measurements' and accompanying 'measurementParams',
// which must be arrays of the same length. The 'measurements' must
// implement the attestation report 'Measurer' interface providing
// a method for collecting the measurements from a hardware or software
// interface
func GenAttestationReport(nonce []byte, metadata [][]byte, measurements []Measurement, measurementParams []MeasurementParams) ArJws {

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
		case "Connector Description":
			log.Debug("Adding Connector Description")
			ar.ConnectorDescription = jws.FullSerialize()
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
		data, err := measurer.Measure(measurementParams[i])
		if err != nil {
			log.Warn("Failed to retrieve measurements: %v", err)
			return ar
		}

		// Check the type of the measurements and add it to the attestation report
		if tpmData, ok := data.(TpmMeasurement); ok {
			ar.TpmM = tpmData
		} else if SwData, ok := data.(SwMeasurement); ok {
			ar.SWM = append(ar.SWM, SwData)
		} else {
			fmt.Println("Internal error: Unsupported Measurement Type")
		}
	}

	return ar
}

// SignAttestationReport signs the attestation report with private key 'priv' and
// appends the pem encoded certificate chain 'certsPem' to the JWS structure. The
// certificates must be handed over in the order they should be appended
// (Signing Certificate -> Intermediate Certificates -> Root CA Certificate)
func SignAttestationReport(ar ArJws, priv crypto.PrivateKey, pub crypto.PublicKey, certsPem [][]byte) (bool, []byte) {

	certsb64 := make([]string, 0)
	for i, certPem := range certsPem {
		cert := loadCert(certPem)
		if cert == nil {
			log.Error("Failed to load cert[%v]", i)
		}

		certsb64 = append(certsb64, base64.StdEncoding.EncodeToString(cert.Raw))
	}

	hws := &hwSigner{
		pk:     &jose.JSONWebKey{Key: pub},
		signer: priv.(crypto.Signer),
		algs:   []jose.SignatureAlgorithm{jose.RS256},
	}

	opaqueSigner := jose.OpaqueSigner(hws)
	alg := hws.algs[0]
	var opt jose.SignerOptions
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: opaqueSigner}, opt.WithHeader("x5c", certsb64))
	if err != nil {
		log.Error("Failed to setup signer for the Attestation Report: ", err)
		return false, nil
	}

	data, err := json.Marshal(ar)
	if err != nil {
		log.Error("Failed to marshal the Attestation Report: ", err)
		return false, nil
	}

	obj, err := signer.Sign(data)
	if err != nil {
		log.Error("Failed to sign the Attestation Report: ", err)
		return false, nil
	}

	var msg string
	msg = obj.FullSerialize()

	return true, []byte(msg)
}

// VerifyAttestationReport verifies an attestation report in full serialized JWS
// format against the supplied nonce and CA certificate. Verifies the certificate
// chains of all attestation report elements as well as the measurements against
// the verifications and the compatibility of software artefacts.
func VerifyAttestationReport(arRaw string, nonce, caCertPem []byte) VerificationResult {
	result := VerificationResult{
		Type:      "Verification Result",
		Success:   true,
		CertLevel: 0}

	// Verify ALL signatures and unpack plain AttestationReport
	ar, err := verifyAndUnpackAttestationReport(arRaw, &result, caCertPem)
	if err != nil {
		log.Warn("Failed to verify and unpack attestation report: ", err)
		return result
	}

	// Verify nonce
	arnonce, aerr := hex.DecodeString(ar.Nonce)
	vrNonceStr := hex.EncodeToString(nonce)
	if aerr != nil {
		msg := fmt.Sprintf("VERIFICATION ERROR: Nonces mismatch (%v vs. %v)", ar.Nonce, vrNonceStr)
		result.update(false, msg)
	}
	if res := bytes.Compare(arnonce, nonce); res != 0 {
		msg := fmt.Sprintf("VERIFICATION ERROR: Nonces mismatch (%v vs. %v)", ar.Nonce, vrNonceStr)
		result.update(false, msg)
	} else {
		msg := fmt.Sprintf("VERIFICATION SUCCESS: Nonces match (%v)", ar.Nonce)
		result.update(true, msg)
	}

	// Verify TPM measurements if present: Extend the verifications to re-calculate the PCR value
	// and evaluate it against the measured PCR value. In case of a measurement list, also extend
	// the measured values to re-calculate the measured PCR value
	verifications := make(map[int][]byte)
	numExtends := 0
	for _, hce := range ar.TpmM.HashChain {
		if len(hce.Sha256) == 1 {
			// This means, that the value from the PCR was directly taken for the measurement
			msg := fmt.Sprintf("MEASUREMENT (single) PCR%v: %v", hce.Pcr, hce.Sha256[0])
			result.update(true, msg)
			measurement, _ := hex.DecodeString(hce.Sha256[0])

			// Calculate the expected PCR value from the verifications
			ver, n := extendVerifications(int(hce.Pcr), ar.RtmManifest.Verifications, ar.OsManifest.Verifications, &result)
			verifications[int(hce.Pcr)] = ver
			numExtends += n

			// Compare the expected PCR value with the measured PCR value
			if bytes.Compare(measurement, verifications[int(hce.Pcr)]) == 0 {
				msg = fmt.Sprintf("VERIFICATION SUCCESS: PCR%v: %v", hce.Pcr, hce.Sha256[0])
				result.update(true, msg)
			} else {
				msg = fmt.Sprintf("VERIFICATION ERROR: PCR%v: %v", hce.Pcr, hce.Sha256[0])
				result.update(false, msg)
			}
		} else {
			// This means, that the values of the individual software artefacts were stored
			// In this case, we must extend those values in order to re-calculate the final
			// PCR value
			hash := make([]byte, 32)
			for _, sha256 := range hce.Sha256 {

				msg := fmt.Sprintf("MEASUREMENT (multip): PCR%v: %v", hce.Pcr, sha256)
				result.update(true, msg)

				h, _ := hex.DecodeString(sha256)
				hash = extendHash(hash, h)

				// Check, if a verification exists for the measured value
				v := getVerification(h, ar.RtmManifest.Verifications, ar.OsManifest.Verifications)
				if v != nil {
					msg = fmt.Sprintf("VERIFICATION SUCCESS: PCR%v: %v %v", hce.Pcr, v.Sha256, v.Name)
					result.update(true, msg)
					verifications[int(hce.Pcr)] = hash
					numExtends++
				} else {
					msg = fmt.Sprintf("VERIFICATION ERROR: PCR%v: %v", hce.Pcr, hex.EncodeToString(h))
					result.update(false, msg)
				}
			}
		}
	}

	// Check that every verification was extended
	if numExtends != (len(ar.OsManifest.Verifications) + len(ar.RtmManifest.Verifications)) {
		msg := fmt.Sprintf("VERIFICATION ERROR: Could not find every expected artefact (Total: %v, Expected: %v)", numExtends, len(ar.OsManifest.Verifications)+len(ar.RtmManifest.Verifications))
		result.update(false, msg)
	}

	// Verify TPM measurements if present: Verify quote, signature and aggregated PCR value
	// As the TPM is currently the only implemented trust anchor, we always implement this check
	// TODO if other trust anchors are supported, evaluate which is present here
	verifyTpmMeasurements(&ar.TpmM, nonce, verifications, &result)

	// Verify software measurements against app manifests and vice versa, if present
	for _, swM := range ar.SWM {
		success := false
		for _, app := range ar.AppManifests {
			for _, swV := range app.Verifications {
				verificationHash, errv := hex.DecodeString(swM.Sha256)
				measurementHash, errm := hex.DecodeString(swV.Sha256)
				if (errm == nil) && (errv == nil) && bytes.Compare(verificationHash, measurementHash) == 0 {
					msg := fmt.Sprintf("VERIFICATION SUCCESS: Type: %v, Name: %v, Sha256: %v", swM.Type, swM.Name, swM.Sha256)
					result.update(true, msg)
					success = true
					break
				}
			}
		}
		if success == false {
			msg := fmt.Sprintf("VERIFICATION ERROR: Type: %v, Name: %v, Sha256: %v", swM.Type, swM.Name, swM.Sha256)
			result.update(false, msg)
		}
	}
	for _, app := range ar.AppManifests {
		for _, swV := range app.Verifications {
			success := false
			for _, swM := range ar.SWM {
				verificationHash, errv := hex.DecodeString(swM.Sha256)
				measurementHash, errm := hex.DecodeString(swV.Sha256)
				if (errm == nil) && (errv == nil) && bytes.Compare(verificationHash, measurementHash) == 0 {
					msg := fmt.Sprintf("VERIFICATION SUCCESS: Type: %v, Name: %v, Sha256: %v", swV.Type, swV.Name, swV.Sha256)
					result.update(true, msg)
					success = true
					break
				}
			}
			if success == false {
				msg := fmt.Sprintf("VERIFICATION ERROR: Type: %v, Name: %v, Sha256: %v", swV.Type, swV.Name, swV.Sha256)
				result.update(false, msg)
			}
		}
	}

	// The lowest certification level of all components determines the certification
	// level for the connector
	levels := make([]int, 0)
	levels = append(levels, ar.CompanyDescription.CertificationLevel)
	levels = append(levels, ar.RtmManifest.CertificationLevel)
	levels = append(levels, ar.OsManifest.CertificationLevel)
	for _, app := range ar.AppManifests {
		levels = append(levels, app.CertificationLevel)
	}
	aggCertLevel := levels[0]
	for _, l := range levels {
		log.Trace("Certification Level of object: ", l)
		if l < aggCertLevel {
			aggCertLevel = l
		}
	}
	result.CertLevel = aggCertLevel
	log.Debug("Final certification level: ", result.CertLevel)

	// Verify the compatibility of the attestation report through verifying the
	// compatibility of all components
	appDescriptions := make([]string, 0)
	for _, a := range ar.ConnectorDescription.AppDescriptions {
		appDescriptions = append(appDescriptions, a.AppManifest)
	}

	// Check that the OS and RTM Manifest are specified in the Connector Description
	if ar.ConnectorDescription.RtmManifest == ar.RtmManifest.Name {
		result.update(true, "COMPATIBILITY SUCCESS: Found RTM Manifest "+ar.RtmManifest.Name+" in Connector Description")
	} else {
		msg := "COMPATIBILITY ERROR: Failed to find RTM Manifest " + ar.RtmManifest.Name + " in Connector Description"
		log.Warn(msg)
		result.update(false, msg)
	}
	if ar.ConnectorDescription.OsManifest == ar.OsManifest.Name {
		result.update(true, "COMPATIBILITY SUCCESS: Found OS Manifest "+ar.OsManifest.Name+" in Connector Description")
	} else {
		msg := "COMPATIBILITY ERROR: Failed to find OS Manifest " + ar.OsManifest.Name + " in Connector Description"
		log.Warn(msg)
		result.update(false, msg)
	}

	// Check that every AppManifest has a corresponding AppDescription
	for _, a := range ar.AppManifests {
		if contains(a.Name, appDescriptions) {
			result.update(true, "COMPATIBILITY SUCCESS: Found App Manifest "+a.Name+" in App Description")
		} else {
			msg := "COMPATIBILITY ERROR: Failed to find App Manifest " + a.Name + " in App Description"
			log.Warn(msg)
			result.update(false, msg)
		}
	}

	// Check that the Rtm Manifest is compatible with the OS Manifest
	if contains(ar.RtmManifest.Name, ar.OsManifest.Rtms) {
		result.update(true, "COMPATIBILITY SUCCESS: RTM Manifest "+ar.RtmManifest.Name+" is compatible with OS Manifest "+ar.OsManifest.Name)
	} else {
		msg := "COMPATIBILITY ERROR: RTM Manifest " + ar.RtmManifest.Name + " not compatible with OS Manifest " + ar.OsManifest.Name
		log.Warn(msg)
		result.update(false, msg)
	}

	// Check that the OS Manifest is compatible with all App Manifests
	for _, a := range ar.AppManifests {
		if contains(ar.OsManifest.Name, a.Oss) {
			result.update(true, "COMPATIBILITY SUCCESS: OS Manifest "+ar.OsManifest.Name+" is compatible with App Manifest "+a.Name)
		} else {
			msg := "COMPATIBILITY ERROR: OS Manifest " + ar.OsManifest.Name + " not compatible with App Manifest " + a.Name
			log.Warn(msg)
			result.update(false, msg)
		}
	}

	return result
}

func (result *VerificationResult) update(success bool, msg string) {
	if !success {
		log.Warn(msg)
		result.Success = false
	} else {
		log.Debug(msg)
	}
	result.Log = append(result.Log, msg)
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
func verifyJwsMulti(data string, roots *x509.CertPool, roles []string, result *VerificationResult) (ok bool, payload []byte) {
	//Extract certificates and validate certificate chains in the process
	opts := x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:     roots,
	}
	success := true

	jwsData, err := jose.ParseSigned(data)
	if err != nil {
		result.update(false, fmt.Sprintf("PROCESSING ERROR: Data could not be parsed - %v", err))
		return false, nil
	}

	if len(roles) != len(jwsData.Signatures) {
		result.update(false, fmt.Sprintf("VERIFICATION ERROR: Expected %v signatures for JWS (got %v)", len(roles), len(jwsData.Signatures)))
		return false, nil
	}
	result.update(true, fmt.Sprintf("VERIFICATION SUCCESS: Number of signatures matches expected number (%v)", len(roles)))

	index := make([]int, len(jwsData.Signatures))
	payloads := make([][]byte, len(jwsData.Signatures))
	for i, sig := range jwsData.Signatures {

		certs, err := sig.Protected.Certificates(opts)
		if err == nil {
			result.update(true, fmt.Sprintf("VERIFICATION SUCCESS: Certificate chain for %v: %v", certs[0][0].Subject.OrganizationalUnit[0], certs[0][0].Subject.CommonName))
		} else {
			result.update(false, fmt.Sprintf("VERIFICATION ERROR: Certificate chain: %v", err))
			success = false
			continue
		}

		index[i], _, payloads[i], err = jwsData.VerifyMulti(certs[0][0].PublicKey)
		if err == nil {
			result.update(true, fmt.Sprintf("VERIFICATION SUCCESS: Signature from %v: %v", certs[0][0].Subject.OrganizationalUnit[0], certs[0][0].Subject.CommonName))
		} else {
			result.update(false, fmt.Sprintf("VERIFICATION ERROR: Signature from %v: %v - %v", certs[0][0].Subject.OrganizationalUnit[0], certs[0][0].Subject.CommonName, err))
			success = false
		}

		if index[i] != i {
			result.update(false, fmt.Sprintf("VERIFICATION ERROR: Order of signatures incorrect"))
			success = false
		}

		if i > 0 {
			if bytes.Compare(payloads[i], payloads[i-1]) != 0 {
				result.update(false, "VERIFICATION ERROR: Payloads differ for jws with multiple signatures")
				success = false
			}
		}

		// Validate that the JWS token was signed with a certificate with the correct
		// role which is set in the 'OU' field of the certificate
		r := certs[0][0].Subject.OrganizationalUnit[0]
		if r == roles[i] {
			result.update(true, fmt.Sprintf("VERIFICATION SUCCESS: Role matches expected role %v", r))
		} else {
			result.update(false, fmt.Sprintf("VERIFICATION ERROR: Role %v does not match expected role %v", r, roles[i]))
		}
	}

	payload = payloads[0]

	return success, payload
}

// Verifies signature and certificate chain for JWS tokens with single signature,
// e.g. attestation reports or connector descriptions
// Currently uses the 'OU' field of the certificate to check if the certificate
// was signed by a valid role.
func verifyJws(data string, roots *x509.CertPool, role string, result *VerificationResult) (bool, []byte) {
	// Extract certificates and validate certificate chains in the process
	opts := x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:     roots,
	}
	success := true

	jwsData, err := jose.ParseSigned(data)
	if err != nil {
		result.update(false, fmt.Sprintf("verifyJws: Data could not be parsed - %v", err))
		return false, nil
	}

	certs, err := jwsData.Signatures[0].Protected.Certificates(opts)
	if err == nil {
		result.update(true, fmt.Sprintf("VERIFICATION SUCCESS: Certificate chain for %v: %v", certs[0][0].Subject.OrganizationalUnit[0], certs[0][0].Subject.CommonName))
	} else {
		result.update(false, fmt.Sprintf("VERIFICATION ERROR: Certificate chain: %v", err))
		return false, nil
	}

	payload, err := jwsData.Verify(certs[0][0].PublicKey)
	if err == nil {
		result.update(true, fmt.Sprintf("VERIFICATION SUCCESS: Signature from %v: %v", certs[0][0].Subject.OrganizationalUnit[0], certs[0][0].Subject.CommonName))
	} else {
		result.update(false, fmt.Sprintf("VERIFICATION ERROR: Signature from %v: %v - %v", certs[0][0].Subject.OrganizationalUnit[0], certs[0][0].Subject.CommonName, err))
		success = false
	}

	// Validate that the JWS token was signed with a certificate with the correct
	// role which is set in the 'OU' field of the certificate
	r := certs[0][0].Subject.OrganizationalUnit[0]
	if r == role {
		result.update(true, fmt.Sprintf("VERIFICATION SUCCESS: Role matches expected role %v", r))
	} else {
		result.update(false, fmt.Sprintf("VERIFICATION ERROR: Role %v does not match expected role %v", r, role))
		success = false
	}

	return success, payload
}

func verifyAndUnpackAttestationReport(attestationReport string, result *VerificationResult, caCertPem []byte) (ArPlain, error) {
	ar := ArPlain{}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(caCertPem)
	if !ok {
		result.update(false, "PROCESSING ERROR: Failed to setup trusted cert pool")
		return ar, errors.New("Failed to setup trusted cert pool")
	}

	//Validate Attestation Report signature
	log.Printf("Starting Verification of Attestation Report Signature\n")
	ok, payload := verifyJws(attestationReport, roots, arSignerRole, result)
	if ok == true {
		log.WithFields(log.Fields{
			"payload": string(payload),
		}).Trace("Signature successfully verified")
		result.update(true, "VERIFICATION SUCCESS: Verification of Attestation Report Signatures successful")
	} else {
		result.update(false, "VERIFICATION ERROR: Verification of Attestation Report Signatures failed")
		return ar, fmt.Errorf("Verification of Attestation Report Signatures failed")
	}

	var arJws ArJws
	err := json.Unmarshal(payload, &arJws)
	if err != nil {
		result.update(false, "PROCESSING ERROR: Parsing of Attestation Report content failed")
		return ar, err
	}

	ar.Type = "ArPlain"
	ar.TpmM = arJws.TpmM
	ar.SWM = arJws.SWM
	ar.Nonce = arJws.Nonce

	//Validate and unpack Rtm Manifest
	log.Debug("Starting Verification of RTM Manifest Signatures\n")
	ok, payload = verifyJwsMulti(arJws.RtmManifest, roots, manifestSignerRoles, result)
	if ok == true {
		log.WithFields(log.Fields{
			"type":    "RTM Manifest",
			"payload": string(payload),
		}).Trace("Signature successfully verified")
		result.update(true, "VERIFICATION SUCCESS: Verification of RTM Manifest Signatures successful")
	} else {
		log.Error("Signature Verification for RTM Manifest failed\n")
		result.update(false, "VERIFICATION ERROR: Verification of RTM Manifest Signatures failed")
	}

	err = json.Unmarshal(payload, &ar.RtmManifest)
	if err != nil {
		log.Error("Failed to unpack RTM Manifest. Json.Unmarshal returned ", err)
		result.update(false, "PROCESSING ERROR: Unpacking of RTM Manifest failed")
	}

	//Validate and unpack OS Manifest
	log.Debug("Starting Verification of OS Manifest Signatures\n")
	ok, payload = verifyJwsMulti(arJws.OsManifest, roots, manifestSignerRoles, result)
	if ok == true {
		log.WithFields(log.Fields{
			"type":    "OS Manifest",
			"payload": string(payload),
		}).Trace("Signature successfully verified")
		result.update(true, "VERIFICATION SUCCESS: Verification of OS Manifest Signatures successful")
	} else {
		result.update(false, "VERIFICATION ERROR: Verification of OS Manifest Signatures failed")
	}

	err = json.Unmarshal(payload, &ar.OsManifest)
	if err != nil {
		result.update(false, "PROCESSING ERROR: Unpacking of OS Manifest failed")
	}

	//Validate and unpack App Manifests
	for i, amSigned := range arJws.AppManifests {
		log.Debug("Starting Verification of App Manifest %d Signatures", i)
		ok, payload = verifyJwsMulti(amSigned, roots, manifestSignerRoles, result)
		if ok == true {
			log.WithFields(log.Fields{
				"type":    "App Manifest",
				"payload": string(payload),
			}).Trace("Signature successfully verified")
			result.update(true, "VERIFICATION SUCCESS: Verification of App Manifest Signatures successful")
		} else {
			result.update(false, "VERIFICATION ERROR: Verification of App Manifest Signatures failed")
		}

		var am AppManifest
		err = json.Unmarshal(payload, &am)
		if err != nil {
			result.update(false, "PROCESSING ERROR: Unpacking of App Manifest failed")
		}
		ar.AppManifests = append(ar.AppManifests, am)
	}

	// Validate and unpack Company Description
	log.Debug("Starting Verification of Company Description Signatures\n")
	ok, payload = verifyJwsMulti(arJws.CompanyDescription, roots, companyDesSignerRoles, result)
	if ok == true {
		log.WithFields(log.Fields{
			"payload": string(payload),
		}).Trace("Signature successfully verified")
		result.update(true, "VERIFICATION SUCCESS: Verification of Company Description Signatures successful")
	} else {
		result.update(false, "VERIFICATION ERROR: Verification of Company Description Signatures failed")
	}

	err = json.Unmarshal(payload, &ar.CompanyDescription)
	if err != nil {
		result.update(false, "PROCESSING ERROR: Unpacking of Company Description failed")
	}

	//Validate and unpack Connector Description
	log.Debug("Starting Verification of Connector Description Signatures\n")
	ok, payload = verifyJws(arJws.ConnectorDescription, roots, connDesSignerRole, result)
	if ok == true {
		log.WithFields(log.Fields{
			"type":    "Connector Description",
			"payload": string(payload),
		}).Trace("Signature successfully verified")
		result.update(true, "VERIFICATION SUCCESS: Verification of Connector Description Signatures successful")
	} else {
		result.update(false, "VERIFICATION ERROR: Verification of Connector Description Signatures failed")
	}

	err = json.Unmarshal(payload, &ar.ConnectorDescription)
	if err != nil {
		log.Error("Failed to unpack Connector Description. Json.Unmarshal returned ", err)
		result.update(false, "PROCESSING ERROR: Unpacking of Connector Description failed")
	}

	return ar, nil
}

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

func extendVerifications(pcr int, rtmVer, osVer []TpmVerification, result *VerificationResult) ([]byte, int) {
	extend := make([]byte, 32)
	n := 0
	for _, ver := range rtmVer {
		if !(pcr == ver.Pcr) {
			continue
		}
		h, _ := hex.DecodeString(ver.Sha256)
		msg := fmt.Sprintf("PROCESSING verification PCR%v: %v, name = %v", ver.Pcr, ver.Sha256, ver.Name)
		result.update(true, msg)
		extend = extendHash(extend, h)
		n++
	}

	for _, ver := range osVer {
		if !(pcr == ver.Pcr) {
			continue
		}
		h, _ := hex.DecodeString(ver.Sha256)
		msg := fmt.Sprintf("PROCESSING verification PCR%v: %v, name = %v", ver.Pcr, ver.Sha256, ver.Name)
		result.update(true, msg)
		extend = extendHash(extend, h)
		n++
	}
	return extend, n
}

func verifyTpmMeasurements(tpmM *TpmMeasurement, nonce []byte, verifications map[int][]byte, result *VerificationResult) {

	if len(tpmM.HashChain) != len(verifications) {
		result.update(false, fmt.Sprintf("VERIFICATION ERROR: Length of measured PCRs does not match with verifications: %v", len(verifications)))
		return
	}

	log.Trace("Length of measured PCRs matches with verifications: ", len(verifications))

	// Iterate through verifications and compare PCR values to measurement PCR values
	for i := range tpmM.HashChain {

		verPcr, ok := verifications[int(tpmM.HashChain[i].Pcr)]
		if !ok {
			result.update(false, fmt.Sprintf("VERIFICATION ERROR: Cannot find verification for measured PCR%v", tpmM.HashChain[i].Pcr))
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
			result.update(true, fmt.Sprintf("VERIFICATION SUCCESS - PCR%v: %v", tpmM.HashChain[i].Pcr, hex.EncodeToString(measPcr)))
		} else {
			result.update(false, fmt.Sprintf("VERIFICATION ERROR - PCR%v: %v", tpmM.HashChain[i].Pcr, hex.EncodeToString(measPcr)))
		}
	}

	// Extract TPM Quote (TPMS ATTEST) and signature
	quote, err := hex.DecodeString(tpmM.Message)
	if err != nil {
		result.update(false, "VERIFICATION ERROR: Failed to decode TPM quote")
		return
	}

	sig, err := hex.DecodeString(tpmM.Signature)
	if err != nil {
		result.update(false, "VERIFICATION ERROR: Failed to decode TPM signature")
		return
	}

	tpmsAttest, err := tpm2.DecodeAttestationData(quote)
	if err != nil {
		result.update(false, "VERIFCATION ERROR: Failed to Decode TPM Attestation Data")
		return
	}

	// Verify nonce with nonce from TPM Quote
	if bytes.Compare(nonce, tpmsAttest.ExtraData) == 0 {
		msg := fmt.Sprintf("VERIFICATION SUCCESS: Nonces match (%v)", hex.EncodeToString(nonce))
		result.update(true, msg)
	} else {
		msg := fmt.Sprintf("VERIFICATION ERROR: Nonces do not match (%v vs. %v)", hex.EncodeToString(nonce), hex.EncodeToString(tpmsAttest.ExtraData))
		result.update(false, msg)
	}

	// Verify aggregated PCR against TPM Quote PCRDigest: Hash all verifications together then compare
	sum := make([]byte, 0)
	for i := range tpmM.HashChain {
		log.Trace(fmt.Sprintf("%v: Aggregating PCR[%v] = %v", i, tpmM.HashChain[i].Pcr, verifications[int(tpmM.HashChain[i].Pcr)]))
		sum = append(sum, verifications[int(tpmM.HashChain[i].Pcr)]...)
	}
	verPcr := sha256.Sum256(sum)
	if bytes.Compare(verPcr[:], tpmsAttest.AttestedQuoteInfo.PCRDigest) == 0 {
		msg := fmt.Sprintf("VERIFICATION SUCCESS: Aggregated PCR matches Quote PCR - %v", hex.EncodeToString(verPcr[:]))
		result.update(true, msg)
	} else {
		msg := fmt.Sprintf("VERIFICATION ERROR: Aggregated PCR does not match Quote PCR - %v", hex.EncodeToString(verPcr[:]))
		result.update(false, msg)
	}

	err = verifyTpmQuoteSignature(quote, sig, tpmM.Certs.AkCert)
	if err != nil {
		result.update(false, err.Error())
	} else {
		result.update(true, "VERIFICATION SUCCESS: Verify TPM quote signature")
	}

	err = verifyTpmCertChain(&tpmM.Certs)
	if err != nil {
		result.update(false, err.Error())
	} else {
		result.update(true, "VERIFICATION SUCCESS: Verify TPM certificate chain")
	}
}

func verifyTpmCertChain(certs *TpmCerts) error {

	intermediatesPool := x509.NewCertPool()
	for _, intermediate := range certs.Intermediates {
		ok := intermediatesPool.AppendCertsFromPEM([]byte(intermediate))
		if !ok {
			return fmt.Errorf("VERIFICATION ERROR: Failed to append certificate from PEM")
		}
	}
	log.Debugf("Added %v certificates to AK intermediates certificate pool", len(intermediatesPool.Subjects()))

	rootsPool := x509.NewCertPool()
	ok := rootsPool.AppendCertsFromPEM([]byte(certs.CaCert))
	if !ok {
		return fmt.Errorf("VERIFICATION ERROR: Failed to append certificate from PEM")
	}
	log.Debugf("Added %v certificate to root certificate pool", len(rootsPool.Subjects()))

	block, _ := pem.Decode([]byte(certs.AkCert))
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("VERIFICATION ERROR: Failed to parse AK certificate")
	}
	akCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("VERIFICATION ERROR: Failed to parse AK certificate - %v", err)
	}

	chain, err := akCert.Verify(x509.VerifyOptions{Roots: rootsPool, Intermediates: intermediatesPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return fmt.Errorf("VERIFICATION ERROR: Failed to verify AK cert chain - %v", err)
	}

	expectedLen := len(intermediatesPool.Subjects()) + len(rootsPool.Subjects()) + 1
	if len(chain[0]) != expectedLen {
		return fmt.Errorf("INTERNAL ERROR: Expected chain of length %v (got %v)", expectedLen, len(chain[0]))
	}

	log.Debugf("Successfully verified chain of %v elements", len(chain[0]))
	for i := range chain[0] {
		log.Tracef("\tCertificate CN='%v', Issuer CN='%v'", chain[0][i].Subject.CommonName, chain[0][i].Issuer.CommonName)
	}

	return nil
}

func verifyTpmQuoteSignature(quote, sig []byte, cert string) error {

	buf := new(bytes.Buffer)
	buf.Write((sig))
	tpmtSig, err := tpm2.DecodeSignature(buf)
	if err != nil {
		return errors.New("VERIFICATION ERROR: Failed to decode TPM signature")
	}

	if tpmtSig.Alg != tpm2.AlgRSASSA {
		return fmt.Errorf("INTERNAL ERROR: Hash algorithm %v not supported", tpmtSig.Alg)
	}

	log.Trace("Certificate: ", cert)

	// Extract public key from x509 certificate
	p, _ := pem.Decode([]byte(cert))
	if p == nil {
		return errors.New("VERIFICATION ERROR: Failed to decode certificate")
	}
	x509Cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return errors.New("VERIFICATION ERROR: Failed to parse certificate")
	}
	pubKey, ok := x509Cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("VERIFICATION ERROR: Failed to extract public key from certificate")
	}
	hashAlg, err := tpmtSig.RSA.HashAlg.Hash()
	if err != nil {
		return errors.New("INTERNAL ERROR: Hash algorithm not supported")
	}

	// Hash the quote and Verify the TPM Quote signature
	hashed := sha256.Sum256(quote)
	err = rsa.VerifyPKCS1v15(pubKey, hashAlg, hashed[:], tpmtSig.RSA.Signature)
	if err != nil {
		return fmt.Errorf("VERIFICATION ERROR: Failed to verify TPM quote signature: %v", err)
	}
	return nil
}

// Used for the JOSE Opaque Signer Interface. This enables signing
// the attestation report with hardware-based keys (such as TPM-based keys)
type hwSigner struct {
	pk     *jose.JSONWebKey
	signer crypto.Signer
	algs   []jose.SignatureAlgorithm
}

// Implements the JOSE Opaque Signer Interface. This enables signing
// the attestation report with hardware-based keys (such as TPM-based keys)
func (hws *hwSigner) Public() *jose.JSONWebKey {
	return hws.pk
}

// Implements the JOSE Opaque Signer Interface. This enables signing
// the attestation report with hardware-based keys (such as TPM-based keys)
func (hws *hwSigner) Algs() []jose.SignatureAlgorithm {
	return hws.algs
}

// Implements the JOSE Opaque Signer Interface. This enables signing
// the attestation report with hardware-based keys (such as TPM-based keys)
func (hws *hwSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {

	hash := crypto.SHA256
	hasher := hash.New()

	// According to documentation, Write() on hash never fails
	_, _ = hasher.Write(payload)
	hashed := hasher.Sum(nil)

	return hws.signer.Sign(rand.Reader, hashed, hash)
}

func contains(elem string, list []string) bool {
	for _, s := range list {
		if s == elem {
			return true
		}
	}
	return false
}
