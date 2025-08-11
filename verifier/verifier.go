// Copyright (c) 2021 - 2025 Fraunhofer AISEC
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

package verifier

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"

	"time"
)

type PolicyEngineSelect uint32

const (
	PolicyEngineSelect_None    PolicyEngineSelect = 0
	PolicyEngineSelect_JS      PolicyEngineSelect = 1
	PolicyEngineSelect_DukTape PolicyEngineSelect = 2
)

type PolicyValidator interface {
	Validate(policies []byte, result *ar.VerificationResult) bool
}

var (
	log = logrus.WithField("service", "ar")

	policyEngines = map[PolicyEngineSelect]PolicyValidator{}
)

// Verify verifies an attestation report in full serialized JWS
// format against the supplied nonce and CA certificates. Verifies the certificate
// chains of all attestation report elements as well as the measurements against
// the reference values and the compatibility of software artefacts.
func Verify(
	arRaw, nonce []byte,
	verifier interface{},
	metadataCas []*x509.Certificate,
	policies []byte,
	polEng PolicyEngineSelect,
	metadatamap map[string][]byte,
) *ar.VerificationResult {

	if len(metadatamap) == 0 {
		log.Warnf("No metadata specified")
	}

	result := &ar.VerificationResult{
		Version: ar.GetVersion(),
		Type:    "Verification Result",
		Prover:  "Unknown",
		Summary: ar.Result{
			Success: true,
		},
		CertLevel: 0,
	}

	// Detect serialization format
	log.Tracef("Detecting serialization format of attestation report length %v", len(arRaw))
	s, err := ar.DetectSerialization(arRaw)
	if err != nil {
		result.SetErr(ar.UnknownSerialization, err)
		return result
	}
	log.Tracef("Detected %v serialization", s.String())

	// Verify and unpack attestation report
	report, tr, code := verifyAr(arRaw, verifier, s)
	result.ReportSignature = tr.SignatureCheck
	if code != ar.NotSpecified {
		result.SetErr(code)
		return result
	}

	// Verify and unpack metadata from attestation report
	metaResults, ok := verifyMetadata(metadataCas, s, metadatamap)
	if !ok {
		result.SetErr(ar.VerifyMetadata)
	}
	result.Metadata = metaResults

	refVals, err := collectReferenceValues(metaResults.ManifestResults)
	if err != nil {
		result.SetErr(ar.RefValTypeNotSupported, err)
	}

	hwAttest := false
	for _, m := range report.Measurements {

		switch mtype := m.Type; mtype {

		case "TPM Measurement":
			r, ok := verifyTpmMeasurements(m, nonce, metadataCas,
				refVals["TPM Reference Value"], s)
			if !ok {
				result.SetErr(ar.VerifyMeasurement, errors.New("TPM measurement"))
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "SNP Measurement":
			r, ok := verifySnpMeasurements(m, nonce, &metaResults.ManifestResults[0],
				refVals["SNP Reference Value"])
			if !ok {
				result.SetErr(ar.VerifyMeasurement, errors.New("SNP measurement"))
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "TDX Measurement":
			r, ok := verifyTdxMeasurements(m, nonce, &metaResults.ManifestResults[0],
				refVals["TDX Reference Value"])
			if !ok {
				result.SetErr(ar.VerifyMeasurement, errors.New("TDX measurement"))
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "SGX Measurement":
			r, ok := verifySgxMeasurements(m, nonce, &metaResults.ManifestResults[0],
				refVals["SGX Reference Value"])
			if !ok {
				result.SetErr(ar.VerifyMeasurement, errors.New("SGX measurement"))
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "IAS Measurement":
			r, ok := verifyIasMeasurements(m, nonce, &metaResults.ManifestResults[0],
				refVals["IAS Reference Value"])
			if !ok {
				result.SetErr(ar.VerifyMeasurement, errors.New("IAS measurement"))
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "SW Measurement":
			r, ok := verifySwMeasurements(m, nonce, metadataCas,
				refVals["SW Reference Value"], s)
			if !ok {
				result.SetErr(ar.VerifyMeasurement, errors.New("SW measurement"))
			}
			result.Measurements = append(result.Measurements, *r)

		case "Azure TDX Measurement", "Azure SNP Measurement", "Azure vTPM Measurement":
			results, ok := verifyAzureMeasurements(report.Measurements, nonce, &metaResults.ManifestResults[0],
				refVals["TDX Reference Value"], refVals["SNP Reference Value"], refVals["TPM Reference Value"],
				s)
			if !ok {
				result.SetErr(ar.VerifyMeasurement, errors.New("azure measurements"))
			}
			result.Measurements = append(result.Measurements, results...)

		default:
			result.SetErr(ar.MeasurementTypeNotSupported, fmt.Errorf("unsupported measurement type %q", mtype))
		}
	}

	// The lowest certification level of all manifests determines the certification
	// level for the device's software stack
	aggCertLevel := 0
	levels := make([]int, 0)
	for _, m := range metaResults.ManifestResults {
		levels = append(levels, m.CertLevel)
	}
	if len(levels) > 0 {
		aggCertLevel = slices.Min(levels)
	}
	log.Debugf("Aggregated cert level: %v", aggCertLevel)
	// If no hardware trust anchor is present, the maximum certification level is 1
	// If there are reference values with a higher trust level present, the remote attestation
	// must fail
	if !hwAttest && aggCertLevel > 1 {
		result.SetErr(ar.InvalidCertLevel, fmt.Errorf("certification level %v requires hw trust anchor", aggCertLevel))
	}
	result.CertLevel = aggCertLevel

	// Validate policies if specified
	if policies != nil {
		p, ok := policyEngines[polEng]
		if !ok {
			result.SetErr(ar.PolicyEngineNotImplemented)
		} else {
			ok = p.Validate(policies, result)
			if !ok {
				result.SetErr(ar.VerifyPolicies)
			}
		}
	} else {
		log.Debugf("No custom policies specified")
	}

	// Add additional information
	result.Prover = metaResults.DevDescResult.Name
	if result.Prover == "" {
		result.Prover = "Unknown"
	}
	result.Created = time.Now().Format(time.RFC3339Nano)

	if result.Summary.Success {
		log.Infof("SUCCESS: Verification for Prover %v (%v)", result.Prover, result.Created)
	} else {
		log.Infof("FAILED: Verification for Prover %v (%v)", result.Prover, result.Created)
	}

	return result
}

func verifyAr(attestationReport []byte, verifier interface{}, s ar.Serializer,
) (*ar.AttestationReport, ar.MetadataResult, ar.ErrorCode) {

	report := ar.AttestationReport{}

	//Validate Attestation Report signature
	result, payload, ok := s.Verify(attestationReport, verifier)
	if !ok {
		log.Debug("Validation of Attestation Report failed")
		return nil, result, ar.VerifyAR
	}

	err := s.Unmarshal(payload, &report)
	if err != nil {
		log.Debugf("Parsing of Attestation Report failed: %v", err)
		return nil, result, ar.ParseAR
	}

	// Check version
	err = report.CheckVersion()
	if err != nil {
		log.Debug(err.Error())
		return nil, result, ar.InvalidVersion
	}

	return &report, result, ar.NotSpecified
}

// verifyMetadata takes the metadata map with keys being the hashes of the raw metadata items,
// a set of CAs and a serializer and performs a validity, signature and certificate chain validation
// as well as compatibility checks: The device description must reference all manifests, and
// starting from an inherently trusted root manifest, all manifests must have a compatible
// base layer.
func verifyMetadata(cas []*x509.Certificate, s ar.Serializer, metadatamap map[string][]byte,
) (ar.MetadataSummary, bool) {

	results := ar.MetadataSummary{}
	success := true
	var err error

	for hash, meta := range metadatamap {

		log.Debugf("Validating metadata item %v...", hash)

		result, payload, ok := s.Verify(meta, cas)
		if !ok {
			log.Debugf("Signature verification of metadata item %v failed", hash)
			success = false
			// Still unpack metadata item for validation-result diagnosis
			payload, err = s.GetPayload(meta)
			if err != nil {
				result.Summary.SetErr(ar.ExtractPayload, err)
			} else {
				log.Debug("Extracted unverified JWS payload")
			}
		} else {
			log.Debugf("Signature verification of metadata item %v successful", hash)
		}

		err := s.Unmarshal(payload, &result.Metadata)
		if err != nil {
			result.Summary.SetErr(ar.ParseMetadata, err)
			success = false
		} else {
			log.Debugf("Parse metadata %v: %v successful", result.Metadata.Type, result.Metadata.Name)
		}

		result.ValidityCheck = checkValidity(result.Metadata.Validity)
		if !result.ValidityCheck.Success {
			log.Debugf("Checking expiration of %v: %v failed (NotBefore: %v, NotAfter: %v)",
				result.Metadata.Type, result.Metadata.Name,
				result.Metadata.Validity.NotBefore, result.Metadata.Validity.NotAfter)
			result.Summary.Success = false
			success = false
		} else {
			log.Debugf("Checking expiration of %v: %v successful",
				result.Metadata.Type, result.Metadata.Name)
		}

		switch result.Metadata.Type {
		case "Device Description":
			results.DevDescResult = result
		case "Company Description":
			results.CompDescResult = &result
		case "Manifest":
			results.ManifestResults = append(results.ManifestResults, result)
		default:
			results.UnknownResults = append(results.UnknownResults, result)
			log.Debugf("Unknown manifest type %v", result.Metadata.Type)
			success = false
		}
		log.Debugf("Finished validation of metadata item %v: %v", hash, result.Summary.Success)
	}

	r := checkMetadataCompatibility(&results)
	if !r.Summary.Success {
		success = false
	}
	results.CompatibilityResult = *r

	return results, success
}

func checkMetadataCompatibility(metadata *ar.MetadataSummary) *ar.CompatibilityResult {

	result := &ar.CompatibilityResult{
		Summary: ar.Result{
			Success: true,
		},
	}

	// Check metadata compatibility and update device description result
	if metadata.DevDescResult.Name == "" {
		result.Summary.SetErr(ar.DeviceDescriptionNotPresent)
	}

	// Gather all manifest names referenced in the manifest descriptions
	descManifests := make([]string, 0, len(metadata.DevDescResult.Descriptions))
	for _, m := range metadata.DevDescResult.Descriptions {
		descManifests = append(descManifests, m.Manifest)
	}

	// Gather all manifest names from the manifests
	manifestNames := make([]string, 0, len(metadata.ManifestResults))
	for _, m := range metadata.ManifestResults {
		manifestNames = append(manifestNames, m.Name)
	}

	// Check that each manifest description has a corresponding manifest
	log.Debugf("Iterating manifest descriptions length %v", len(metadata.DevDescResult.Descriptions))
	descriptionMatch := make([]ar.Result, 0, len(metadata.DevDescResult.Descriptions))
	for _, desc := range metadata.DevDescResult.Descriptions {

		ok := internal.Contains(desc.Manifest, manifestNames)
		if !ok {
			log.Debugf("No manifest for manifest description: %v", desc.Manifest)
			result.Summary.SetErr(ar.NotSpecified)
		}

		r := ar.Result{
			Success:       ok,
			Got:           desc.Manifest,
			ExpectedOneOf: manifestNames,
		}
		descriptionMatch = append(descriptionMatch, r)

	}

	// Check that each manifest has a corresponding manifest description
	log.Debugf("Iterating manifests length %v", len(metadata.ManifestResults))
	manifestMatch := make([]ar.Result, 0, len(metadata.ManifestResults))
	for _, m := range metadata.ManifestResults {

		ok := internal.Contains(m.Name, descManifests)
		if !ok {
			log.Debugf("No manifest description for manifest: %v", m.Name)
			result.Summary.SetErr(ar.NotSpecified)
			r := ar.Result{
				Success:       false,
				Got:           m.Name,
				ExpectedOneOf: descManifests,
			}
			manifestMatch = append(manifestMatch, r)
		}
		// Found manifests have already been recorded, nothing to do
	}

	// Check that each manifest has a compatible base layer
	manifestResults, manifestCompatibility, errCode, ok := processManifests(metadata.ManifestResults)
	if !ok {
		result.Summary.SetErr(errCode)
	}
	metadata.ManifestResults = manifestResults

	result.DescriptionMatch = descriptionMatch
	result.ManifestMatch = manifestMatch
	result.ManifestCompatibility = manifestCompatibility

	return result
}

func processManifests(manifests []ar.MetadataResult) ([]ar.MetadataResult, []ar.Result, ar.ErrorCode, bool) {

	mm := make(map[string][]ar.MetadataResult)
	var root ar.MetadataResult
	results := make([]ar.Result, 0)
	success := true

	// Organize manifests by BaseLayer
	foundRoot := false
	for _, m := range manifests {
		if len(m.BaseLayers) == 1 && m.Name == m.BaseLayers[0] {
			// Check that there is exactly one root of trust manifest
			if foundRoot {
				log.Debugf("Found additional root of trust manifest %v (already got %v)", m.Name, root.Name)
				success = false
				return manifests, nil, ar.MultipleRootManifests, success
			}
			root = m
			foundRoot = true
		} else {
			for _, base := range m.BaseLayers {
				mm[base] = append(mm[base], m)
			}
		}
	}

	// Start the sorted list with the root
	var sorted []ar.MetadataResult
	var unplaced []ar.MetadataResult
	if !foundRoot || root.Name == "" {
		log.Debug("Did not find root manifest")
		unplaced = manifests
		success = false
		return manifests, nil, ar.NoRootManifest, success
	} else {
		sorted = append(sorted, root)
		results = append(results, ar.Result{
			Success: true,
			Got:     root.Name,
		})
	}

	// Track processed layers
	processed := map[string]bool{root.Name: true}

	// Iteratively add dependent layers
	for i := 0; i < len(sorted); i++ {
		current := sorted[i]
		for _, dependent := range mm[current.Name] {
			if !processed[dependent.Name] && hasCompatibleBaseLayer(dependent.BaseLayers, processed) {
				sorted = append(sorted, dependent)
				processed[dependent.Name] = true
				results = append(results, ar.Result{
					Success:       true,
					Got:           dependent.Name,
					ExpectedOneOf: dependent.BaseLayers,
				})
			}
		}
	}

	// Identify manifests with no compatible base layer
	for _, m := range manifests {
		if !processed[m.Name] {
			log.Debugf("%v has no compatible baselayer\n", m.Name)
			unplaced = append(unplaced, m)
			success = false
			results = append(results, ar.Result{
				Success:       false,
				Got:           m.Name,
				ExpectedOneOf: m.BaseLayers,
			})
		}
	}

	// Add unplaced manifests to the end of the list
	sorted = append(sorted, unplaced...)

	return sorted, results, ar.NotSpecified, success
}

func hasCompatibleBaseLayer(baseLayers []string, processed map[string]bool) bool {
	for _, base := range baseLayers {
		if processed[base] {
			return true
		}
	}
	return false
}

func checkValidity(val ar.Validity) ar.Result {
	result := ar.Result{}
	result.Success = true

	notBefore, err := time.Parse(time.RFC3339, val.NotBefore)
	if err != nil {
		result.SetErr(ar.ParseTime, err)
		return result
	}
	notAfter, err := time.Parse(time.RFC3339, val.NotAfter)
	if err != nil {
		result.SetErr(ar.ParseTime, err)
		return result
	}
	currentTime := time.Now()

	if notBefore.After(currentTime) {
		result.SetErr(ar.NotYetValid)
		result.Got = currentTime.String()
		result.ExpectedBetween = []string{notBefore.String(), notAfter.String()}
	}

	if currentTime.After(notAfter) {
		result.SetErr(ar.Expired)
		result.Got = currentTime.String()
		result.ExpectedBetween = []string{notBefore.String(), notAfter.String()}
	}

	return result
}

func collectReferenceValues(metadata []ar.MetadataResult) (map[string][]ar.ReferenceValue, error) {

	refmap := make(map[string][]ar.ReferenceValue)
	// Iterate over all manifests (iterator required)
	for i := range metadata {
		for _, r := range metadata[i].ReferenceValues {
			// Check reference value type
			if r.Type != "SNP Reference Value" &&
				r.Type != "SW Reference Value" &&
				r.Type != "TPM Reference Value" &&
				r.Type != "TDX Reference Value" &&
				r.Type != "SGX Reference Value" {
				return nil, fmt.Errorf("reference value of type %v is not supported", r.Type)
			}

			// Note: The indirection and iterator are required, otherwise the manifest reference
			// in the reference value would always point to the last element in the map
			m := metadata[i]
			// Add a reference to the corresponding manifest to each reference value
			r.SetManifest(&m.Metadata)

			// Collect all reference values, depending on type, independent of the manifest
			refmap[r.Type] = append(refmap[r.Type], r)
		}
	}

	return refmap, nil
}

func checkExtensionUint8(cert *x509.Certificate, oid string, value uint8) (ar.Result, bool) {

	for _, ext := range cert.Extensions {

		if ext.Id.String() == oid {
			log.Debugf("Found %v, length %v, values %v", oid, len(ext.Value), ext.Value)
			if len(ext.Value) != 3 && len(ext.Value) != 4 {
				result := ar.Result{}
				result.SetErr(ar.OidLength, fmt.Errorf("extension %v value unexpected length %v (expected 3 or 4)",
					oid, len(ext.Value)))
				return result, false
			}
			if ext.Value[0] != 0x2 {
				result := ar.Result{}
				result.SetErr(ar.OidTag, fmt.Errorf("extension %v value[0]: %v does not match expected value 2 (tag Integer)",
					oid, ext.Value[0]))
				return result, false
			}
			if ext.Value[1] == 0x1 {
				if ext.Value[2] != value {
					log.Debugf("extension %v value[2]: %v does not match expected value %v",
						oid, ext.Value[2], value)
					return ar.Result{
						Success:  false,
						Expected: fmt.Sprintf("%v: %v", oidDesc(oid), strconv.FormatUint(uint64(value), 10)),
						Got:      strconv.FormatUint(uint64(ext.Value[2]), 10),
					}, false
				}
			} else if ext.Value[1] == 0x2 {
				// Due to openssl, the sign bit must remain zero for positive integers
				// even though this field is defined as unsigned int in the AMD spec
				// Thus, if the most significant bit is required, one byte of additional 0x00 padding is added
				if ext.Value[2] != 0x00 || ext.Value[3] != value {
					log.Debugf("extension %v value = %v%v does not match expected value  %v",
						oid, ext.Value[2], ext.Value[3], value)
					return ar.Result{
						Success:  false,
						Expected: fmt.Sprintf("%v: %v", oidDesc(oid), strconv.FormatUint(uint64(value), 10)),
						Got:      strconv.FormatUint(uint64(ext.Value[3]), 10),
					}, false
				}
			} else {
				result := ar.Result{}
				result.SetErr(ar.OidLength, fmt.Errorf(
					"extension %v value[1]: %v does not match expected value 1 or 2 (length of integer)",
					oid, ext.Value[1]))
				return result, false
			}
			return ar.Result{
				Success: true,
				Got:     fmt.Sprintf("%v: %v", oidDesc(oid), strconv.FormatUint(uint64(value), 10)),
			}, true
		}
	}

	result := ar.Result{}
	result.SetErr(ar.OidNotPresent, fmt.Errorf("extension %v not present in certificate", oid))

	return result, false
}

func checkExtensionBuf(cert *x509.Certificate, oid string, buf []byte) (ar.Result, bool) {

	for _, ext := range cert.Extensions {

		if ext.Id.String() == oid {
			if cmp := bytes.Compare(ext.Value, buf); cmp != 0 {
				log.Debugf("extension %v value %v does not match expected value %v",
					oid, hex.EncodeToString(ext.Value), hex.EncodeToString(buf))
				return ar.Result{
					Success:  false,
					Expected: fmt.Sprintf("%v: %v", oidDesc(oid), hex.EncodeToString(buf)),
					Got:      hex.EncodeToString(ext.Value),
				}, false
			}
			return ar.Result{
				Success: true,
				Got:     fmt.Sprintf("%v: %v", oidDesc(oid), hex.EncodeToString(ext.Value)),
			}, true
		}
	}

	result := ar.Result{}
	result.SetErr(ar.OidNotPresent, fmt.Errorf("extension %v not present in certificate", oid))
	return result, false
}

func getExtensionString(cert *x509.Certificate, oid string) (string, bool) {

	for _, ext := range cert.Extensions {
		if ext.Id.String() == oid {
			return string(ext.Value), true
		}
	}
	log.Debugf("extension %v: %v not present in certificate", oid, oidDesc(oid))
	return "", false
}

func verifyCaFingerprint(ca *x509.Certificate, refFingerprints []string) ar.Result {

	result := ar.Result{}

	log.Debugf("Checking %v CA fingerprints", len(refFingerprints))

	caFingerprint := sha256.Sum256(ca.Raw)

	for _, fp := range refFingerprints {
		refFingerprint, err := hex.DecodeString(fp)
		if err != nil {
			log.Debugf("Failed to decode CA fingerprint %v: %v", fp, err)
			result.SetErr(ar.ParseCAFingerprint)
			return result
		}
		if bytes.Equal(refFingerprint, caFingerprint[:]) {
			log.Debugf("Found matching CA fingerprint %q", hex.EncodeToString(refFingerprint))
			result.Got = fp
			result.Success = true
			return result
		} else {
			log.Debugf("Root Manifest CA fingerprint %q does not match measurement CA fingerprint %q. Continue..",
				refFingerprint, hex.EncodeToString(caFingerprint[:]))
			continue
		}
	}

	log.Debug("Failed to find matching CA fingerprint")

	result.Success = false
	result.ExpectedOneOf = refFingerprints
	result.Got = hex.EncodeToString(caFingerprint[:])
	return result
}
