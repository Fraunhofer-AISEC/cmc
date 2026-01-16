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

type PolicyEngine interface {
	Validate(result *ar.VerificationResult, policies []byte, policyOverwrite bool) bool
}

var (
	log = logrus.WithField("service", "ar")

	policyEngines = map[PolicyEngineSelect]PolicyEngine{}
)

// Verify verifies an attestation report in full serialized JWS
// format against the supplied nonce and CA certificates. Verifies the certificate
// chains of all attestation report elements as well as the measurements against
// the reference values and the compatibility of software artefacts.
func Verify(
	arRaw, nonce []byte, verifier interface{},
	policies []byte, policyEngine PolicyEngineSelect, policyOverwrite bool,
	metadataCas []*x509.Certificate, metadataMap map[string][]byte,
) *ar.VerificationResult {
	return VerifyProvision(arRaw, nonce, verifier, policies, policyEngine, policyOverwrite, metadataCas,
		metadataMap, "")
}

// VerifyProvision provides the same functionality as Verify() and can be called during
// provisioning, where certificates are not yet enrolled yet, and thus the FQDN is
// provided by the provisioning server
func VerifyProvision(
	arRaw, nonce []byte, verifier interface{},
	policies []byte, policyEngine PolicyEngineSelect, policyOverwrite bool,
	metadataCas []*x509.Certificate, metadataMap map[string][]byte,
	fqdn string,
) *ar.VerificationResult {

	if len(metadataMap) == 0 {
		log.Warnf("No metadata specified")
	}

	result := &ar.VerificationResult{
		Version: ar.GetVersion(),
		Type:    "Verification Result",
		Prover:  "Unknown",
		Summary: ar.Result{
			Status: ar.StatusSuccess,
		},
		Measurements: []ar.MeasurementResult{},
		CertLevel:    0,
	}

	// Detect serialization format
	log.Tracef("Detecting serialization format of attestation report length %v", len(arRaw))
	s, err := ar.DetectSerialization(arRaw)
	if err != nil {
		result.Fail(ar.UnknownSerialization, err)
		return result
	}
	log.Tracef("Detected %v serialization", s.String())

	// Verify and unpack attestation report
	report, mr, code := verifyAr(arRaw, verifier, s)
	result.ReportSignature = mr.SignatureCheck
	if code != ar.NotSpecified {
		result.Fail(code)
		return result
	}

	// Verify and unpack metadata from attestation report
	metaResults, ok := verifyMetadata(metadataCas, s, metadataMap)
	if !ok {
		result.Fail(ar.VerifyMetadata)
	}
	result.Metadata = metaResults

	result.Prover = getProver(result.ReportSignature, fqdn)
	if result.Prover == "" {
		result.Prover = "Unknown"
	}
	log.Debugf("Decoded attestation report and metadata from prover %v", result.Prover)

	refVals, err := collectReferenceValues(metaResults.ManifestResults)
	if err != nil {
		result.Fail(ar.RefValTypeNotSupported, err)
		return result
	}

	hwAttest := false
Loop:
	for _, m := range report.Measurements {

		switch mtype := m.Type; mtype {

		case "TPM Measurement":
			r, ok := verifyTpmMeasurements(m, nonce, metadataCas,
				refVals["TPM Reference Value"], s)
			if !ok {
				result.Fail(ar.VerifyMeasurement, errors.New("TPM measurement"))
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "SNP Measurement":
			r, ok := verifySnpMeasurements(m, nonce, metaResults.ManifestResults,
				refVals["SNP Reference Value"])
			if !ok {
				result.Fail(ar.VerifyMeasurement, errors.New("SNP measurement"))
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "TDX Measurement":
			r, ok := verifyTdxMeasurements(m, nonce, metaResults.ManifestResults,
				refVals["TDX Reference Value"])
			if !ok {
				result.Fail(ar.VerifyMeasurement, errors.New("TDX measurement"))
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "SGX Measurement":
			r, ok := verifySgxMeasurements(m, nonce, metaResults.ManifestResults,
				refVals["SGX Reference Value"])
			if !ok {
				result.Fail(ar.VerifyMeasurement, errors.New("SGX measurement"))
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "IAS Measurement":
			r, ok := verifyIasMeasurements(m, nonce, metaResults.ManifestResults,
				refVals["IAS Reference Value"])
			if !ok {
				result.Fail(ar.VerifyMeasurement, errors.New("IAS measurement"))
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case "SW Measurement":
			r, ok := verifySwMeasurements(m, nonce, metadataCas,
				refVals["SW Reference Value"], s)
			if !ok {
				result.Fail(ar.VerifyMeasurement, errors.New("SW measurement"))
			}
			result.Measurements = append(result.Measurements, *r)

		case "Azure TDX Measurement", "Azure SNP Measurement", "Azure vTPM Measurement":
			results, ok := verifyAzureMeasurements(report.Measurements, nonce, metaResults.ManifestResults,
				refVals["TDX Reference Value"], refVals["SNP Reference Value"], refVals["TPM Reference Value"],
				s)
			if !ok {
				result.Fail(ar.VerifyMeasurement, errors.New("azure measurements"))
			}
			result.Measurements = append(result.Measurements, results...)
			hwAttest = true
			break Loop

		default:
			result.Fail(ar.MeasurementTypeNotSupported, fmt.Errorf("unsupported measurement type %q", mtype))
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
		result.Fail(ar.InvalidCertLevel, fmt.Errorf("certification level %v requires hw trust anchor", aggCertLevel))
	}
	result.CertLevel = aggCertLevel

	// Add additional information
	result.Created = time.Now().Format(time.RFC3339Nano)

	// Validate policies if specified
	if policies != nil {
		p, ok := policyEngines[policyEngine]
		if !ok {
			result.Fail(ar.PolicyEngineNotImplemented)
		} else {
			ok = p.Validate(result, policies, policyOverwrite)
			if !ok {
				result.Fail(ar.VerifyPolicies)
			}
		}
	} else {
		log.Debugf("No custom policies specified")
	}

	switch result.Summary.Status {
	case ar.StatusSuccess:
		log.Infof("SUCCESS: Verification for Prover %v (%v)", result.Prover, result.Created)
	case ar.StatusWarn:
		log.Infof("WARN: Verification for Prover %v (%v)", result.Prover, result.Created)
	case ar.StatusFail:
		log.Infof("FAILED: Verification for Prover %v (%v)", result.Prover, result.Created)
	default:
		log.Infof("FAILED UNKNOWN: Verification for Prover %v (%v)", result.Prover, result.Created)
		result.Summary.Status = ar.StatusFail
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
// as well as compatibility checks: The image description must reference all manifests, and
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
				result.Summary.Fail(ar.ExtractPayload, err)
			} else {
				log.Debug("Extracted unverified JWS payload")
			}
		} else {
			log.Debugf("Signature verification of metadata item %v successful", hash)
		}

		err := s.Unmarshal(payload, &result.Metadata)
		if err != nil {
			result.Summary.Fail(ar.ParseMetadata, err)
			success = false
		} else {
			log.Debugf("Parse metadata %v: %v successful", result.Metadata.Type, result.Metadata.Name)
		}

		result.ValidityCheck = checkValidity(result.Metadata.Validity)
		if result.ValidityCheck.Status == ar.StatusFail {
			log.Debugf("Checking expiration of %v: %v failed (NotBefore: %v, NotAfter: %v)",
				result.Metadata.Type, result.Metadata.Name,
				result.Metadata.Validity.NotBefore, result.Metadata.Validity.NotAfter)
			result.Summary.Status = ar.StatusFail
			success = false
		} else {
			log.Debugf("Checking expiration of %v: %v successful",
				result.Metadata.Type, result.Metadata.Name)
		}

		switch result.Metadata.Type {
		case "Image Description":
			results.ImageDescriptionResult = result
		case "Company Description":
			results.CompanyDescriptionResult = &result
		case "Manifest":
			results.ManifestResults = append(results.ManifestResults, result)
		default:
			results.UnknownResults = append(results.UnknownResults, result)
			log.Debugf("Unknown manifest type %v", result.Metadata.Type)
			success = false
		}
		log.Debugf("Finished validation of metadata item %v: %v", hash, result.Summary.Status)
	}

	r := checkMetadataCompatibility(&results)
	if r.Summary.Status != ar.StatusSuccess {
		success = false
	}
	results.CompatibilityResult = *r

	return results, success
}

func checkMetadataCompatibility(metadata *ar.MetadataSummary) *ar.CompatibilityResult {

	result := &ar.CompatibilityResult{
		Summary: ar.Result{
			Status: ar.StatusSuccess,
		},
	}

	// Check metadata compatibility and update image description result
	if metadata.ImageDescriptionResult.Name == "" {
		result.Summary.Fail(ar.ImageDescriptionNotPresent)
	}

	// Gather all manifest names referenced in the manifest descriptions
	descManifests := make([]string, 0, len(metadata.ImageDescriptionResult.Descriptions))
	for _, m := range metadata.ImageDescriptionResult.Descriptions {
		descManifests = append(descManifests, m.Manifest)
	}

	// Gather all manifest names from the manifests
	manifestNames := make([]string, 0, len(metadata.ManifestResults))
	for _, m := range metadata.ManifestResults {
		manifestNames = append(manifestNames, m.Name)
	}

	// Check that each manifest description has a corresponding manifest
	log.Debugf("Iterating manifest descriptions length %v", len(metadata.ImageDescriptionResult.Descriptions))
	descriptionMatch := make([]ar.Result, 0, len(metadata.ImageDescriptionResult.Descriptions))
	for _, desc := range metadata.ImageDescriptionResult.Descriptions {

		ok := internal.Contains(desc.Manifest, manifestNames)
		if !ok {
			log.Debugf("No manifest for manifest description: %v", desc.Manifest)
			result.Summary.Status = ar.StatusFail
		}

		r := ar.Result{
			Status:        ar.StatusFromBool(ok),
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
			result.Summary.Status = ar.StatusFail
			r := ar.Result{
				Status:        ar.StatusFail,
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
		result.Summary.Fail(errCode)
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
			Status: ar.StatusSuccess,
			Got:    root.Name,
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
					Status:        ar.StatusSuccess,
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
				Status:        ar.StatusFail,
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
	result := ar.Result{
		Status: ar.StatusSuccess,
	}

	notBefore, err := time.Parse(time.RFC3339, val.NotBefore)
	if err != nil {
		result.Fail(ar.ParseTime, err)
		return result
	}
	notAfter, err := time.Parse(time.RFC3339, val.NotAfter)
	if err != nil {
		result.Fail(ar.ParseTime, err)
		return result
	}
	currentTime := time.Now()

	if notBefore.After(currentTime) {
		result.Fail(ar.NotYetValid)
		result.Got = currentTime.String()
		result.ExpectedBetween = []string{notBefore.String(), notAfter.String()}
	}

	if currentTime.After(notAfter) {
		result.Fail(ar.Expired)
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

func verifyCaFingerprint(ca *x509.Certificate, refFingerprints []string) ar.Result {

	result := ar.Result{}

	log.Debugf("Checking %v CA fingerprints", len(refFingerprints))

	caFingerprint := sha256.Sum256(ca.Raw)

	for _, fp := range refFingerprints {
		refFingerprint, err := hex.DecodeString(fp)
		if err != nil {
			log.Debugf("Failed to decode CA fingerprint %v: %v", fp, err)
			result.Fail(ar.ParseCAFingerprint)
			return result
		}
		if bytes.Equal(refFingerprint, caFingerprint[:]) {
			log.Debugf("Found matching CA fingerprint %x", refFingerprint)
			result.Got = fp
			result.Status = ar.StatusSuccess
			return result
		} else {
			log.Tracef("Root Manifest CA fingerprint %x does not match measurement CA fingerprint %x. Continue..",
				refFingerprint, caFingerprint[:])
			continue
		}
	}

	log.Debug("Failed to find matching CA fingerprint")

	result.Status = ar.StatusFail
	result.ExpectedOneOf = refFingerprints
	result.Got = hex.EncodeToString(caFingerprint[:])
	return result
}

// Extract the Common Name from the leaf certificate if report was signed by
// certificate. If not (i.e., during initial provisioning), use the provided name
func getProver(r []ar.SignatureResult, optionalProver string) string {

	if len(r) > 0 &&
		len(r[0].Certs) > 0 &&
		len(r[0].Certs[0]) > 0 {
		return r[0].Certs[0][0].Subject.CommonName
	}
	return optionalProver
}
