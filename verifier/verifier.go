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
	"github.com/Fraunhofer-AISEC/cmc/peercache"
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
	Validate(result *ar.AttestationResult, policies []byte, policyOverwrite bool) bool
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
	metadataCas []*x509.Certificate, peerCache *peercache.Cache,
	peer string,
) *ar.AttestationResult {

	result := &ar.AttestationResult{
		Version: ar.GetResultVersion(),
		Type:    ar.TYPE_ATTESTATION_RESULT,
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

	// Unmarshal the attestation report
	report := new(ar.AttestationReport)
	err = s.Unmarshal(arRaw, &report)
	if err != nil {
		result.Fail(ar.UnknownSerialization, err)
		return result
	}

	// Check attestation report version for compatibility
	err = report.CheckVersion()
	if err != nil {
		result.Fail(ar.InvalidVersion, fmt.Errorf("expected version %v, got %v", ar.GetReportVersion(),
			report.Version))
		return result
	}

	// Retrieve cached metadata items for peer if configured
	var cachedMetadata map[string][]byte
	if peerCache != nil {
		cachedMetadata = peerCache.Get(peer)
	}

	// Iterate over report metadata digests and retrieve metadata items from report and peer cache
	collectedMetadata, err := collectMetadata(report.Context, cachedMetadata)
	if err != nil {
		result.Fail(ar.VerifyMetadata, err)
	}

	// A failed update of the peer cache only means that we need to send more
	// data during the next attestation
	if peerCache != nil {
		err = peerCache.Update(peer, collectedMetadata)
		if err != nil {
			log.Warnf("Failed to update peer cache: %v", err)
		}
	}

	// Verify and unpack metadata from attestation report
	metaResults, ok := verifyMetadata(metadataCas, collectedMetadata)
	if !ok {
		result.Fail(ar.VerifyMetadata)
	}
	result.Metadata = metaResults
	result.Prover = report.Name

	log.Debugf("Decoded attestation report and metadata from prover %v", result.Prover)

	// Verify the supplied nonce and construct the evidence nonce for context integrity verification
	// NONCE_USER = Context.Nonce
	// NONCE_EVIDENCE = HASH(Context)
	result.Freshness.Expected = hex.EncodeToString(nonce)
	result.Freshness.Got = hex.EncodeToString(report.Context.Nonce)
	if !bytes.Equal(nonce, report.Context.Nonce) {
		result.Freshness.Status = ar.StatusFail
		result.Fail(ar.Freshness)
	} else {
		log.Debugf("Successfully verified user supplied nonce: %x", nonce)
		result.Freshness.Status = ar.StatusSuccess
	}
	alg, err := internal.HashFromString(report.Context.Alg)
	if err != nil {
		result.Fail(ar.UnsupportedContextHashAlg, err)
	}
	evidenceNonce, err := internal.Hash(alg, report.GetEncodedContext())
	if err != nil {
		result.Fail(ar.CalculateContextHash, err)
	}
	log.Tracef("Recalculated %v context hash %x for encoded context with user nonce %x and length %v",
		alg.String(), evidenceNonce, report.Context.Nonce, len(report.GetEncodedContext()))

	refVals, err := collectComponents(metaResults.ManifestResults)
	if err != nil {
		result.Fail(ar.RefValTypeNotSupported, err)
		return result
	}

	hwAttest := false

	// Collect evidence collateral into a map for combined processing with evidences
	collateral := make(map[string]ar.Collateral)
	for _, em := range report.Context.Collateral {
		collateral[em.Type] = em
	}

	// Required because we process multiple measurements for azure in one go
Loop:
	for _, ev := range report.Evidences {

		// Retrieve the collateral corresponding to the evidence
		col, ok := collateral[ev.Type]
		if !ok {
			result.Fail(ar.VerifyMeasurement, fmt.Errorf("no collateral for evidence %v", ev.Type))
			continue
		}

		switch evtype := ev.Type; evtype {

		case ar.TYPE_EVIDENCE_TPM:
			r, ok := VerifyTpm(ev, col, evidenceNonce, metadataCas, refVals[ar.TYPE_REFVAL_TPM], s)
			if !ok {
				result.Fail(ar.VerifyMeasurement, errors.New("TPM measurement"))
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case ar.TYPE_EVIDENCE_SNP:
			var snpPolicy *ar.SnpPolicy
			var caFingerprints []string
			if len(metaResults.ManifestResults) > 0 {
				snpPolicy = metaResults.ManifestResults[0].SnpPolicy
				caFingerprints = metaResults.ManifestResults[0].CaFingerprints
			}
			r, ok := VerifySnp(ev, col, evidenceNonce, snpPolicy, caFingerprints,
				refVals[ar.TYPE_REFVAL_SNP])
			if !ok {
				result.Fail(ar.VerifyMeasurement, errors.New("SNP measurement"))
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case ar.TYPE_EVIDENCE_TDX:
			var tdxPolicy *ar.TdxPolicy
			var caFingerprints []string
			if len(metaResults.ManifestResults) > 0 {
				tdxPolicy = metaResults.ManifestResults[0].TdxPolicy
				caFingerprints = metaResults.ManifestResults[0].CaFingerprints
			}
			r, ok := VerifyTdx(ev, col, evidenceNonce, tdxPolicy, caFingerprints,
				refVals[ar.TYPE_REFVAL_TDX])
			if !ok {
				result.Fail(ar.VerifyMeasurement, errors.New("TDX measurement"))
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case ar.TYPE_EVIDENCE_SGX:
			var sgxPolicy *ar.SgxPolicy
			var caFingerprints []string
			if len(metaResults.ManifestResults) > 0 {
				sgxPolicy = metaResults.ManifestResults[0].SgxPolicy
				caFingerprints = metaResults.ManifestResults[0].CaFingerprints
			}
			r, ok := VerifySgx(ev, col, evidenceNonce, sgxPolicy, caFingerprints,
				refVals[ar.TYPE_REFVAL_SGX])
			if !ok {
				result.Fail(ar.VerifyMeasurement, errors.New("SGX measurement"))
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case ar.TYPE_EVIDENCE_IAS:
			var caFingerprints []string
			if len(metaResults.ManifestResults) > 0 {
				caFingerprints = metaResults.ManifestResults[0].CaFingerprints
			}
			r, ok := VerifyIas(ev, col, evidenceNonce, caFingerprints,
				refVals[ar.TYPE_REFVAL_IAS])
			if !ok {
				result.Fail(ar.VerifyMeasurement, errors.New("IAS measurement"))
			}
			result.Measurements = append(result.Measurements, *r)
			hwAttest = true

		case ar.TYPE_EVIDENCE_SW:
			r, ok := VerifySw(ev, col, evidenceNonce, refVals[ar.TYPE_REFVAL_SW])
			if !ok {
				result.Fail(ar.VerifyMeasurement, errors.New("SW measurement"))
			}
			result.Measurements = append(result.Measurements, *r)

		case ar.TYPE_EVIDENCE_AZURE_SNP, ar.TYPE_EVIDENCE_AZURE_TDX, ar.TYPE_EVIDENCE_AZURE_TPM:
			var tdxPolicy *ar.TdxPolicy
			var snpPolicy *ar.SnpPolicy
			var caFingerprints []string
			if len(metaResults.ManifestResults) > 0 {
				tdxPolicy = metaResults.ManifestResults[0].TdxPolicy
				snpPolicy = metaResults.ManifestResults[0].SnpPolicy
				caFingerprints = metaResults.ManifestResults[0].CaFingerprints
			}
			results, ok := VerifyAzure(report.Evidences, report.Context.Collateral, evidenceNonce,
				tdxPolicy, snpPolicy, caFingerprints, refVals[ar.TYPE_REFVAL_TDX],
				refVals[ar.TYPE_REFVAL_SNP], refVals[ar.TYPE_REFVAL_TPM], s)
			if !ok {
				result.Fail(ar.VerifyMeasurement, errors.New("azure measurements"))
			}
			result.Measurements = append(result.Measurements, results...)
			hwAttest = true

			// Required because we process multiple measurements for azure
			break Loop

		default:
			result.Fail(ar.MeasurementTypeNotSupported,
				fmt.Errorf("unsupported measurement type %q", evtype))
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

// verifyMetadata takes the metadata map with keys being the hashes of the raw metadata items,
// a set of CAs and a serializer and performs a validity, signature and certificate chain validation
// as well as compatibility checks: The image description must reference all manifests, and
// starting from an inherently trusted root manifest, all manifests must have a compatible
// base layer.
func verifyMetadata(cas []*x509.Certificate, metadatamap map[string][]byte,
) (ar.MetadataSummary, bool) {

	results := ar.MetadataSummary{}
	success := true

	for hash, meta := range metadatamap {

		log.Debugf("Validating metadata item %v...", hash)

		s, err := ar.DetectSerialization(meta)
		if err != nil {
			result := ar.MetadataResult{}
			result.Summary.Fail(ar.ExtractPayload, err)
			results.UnknownResults = append(results.UnknownResults, result)
			continue
		}
		log.Tracef("Detected %v serialization", s.String())

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

		err = s.Unmarshal(payload, &result.Metadata)
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
		case ar.TYPE_IMAGE_DESCRIPTION:
			results.ImageDescriptionResult = result
		case ar.TYPE_COMPANY_DESCRIPTION:
			results.CompanyDescriptionResult = &result
		case ar.TYPE_MANIFEST:
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

func collectComponents(metadata []ar.MetadataResult) (map[string][]ar.Component, error) {

	refmap := make(map[string][]ar.Component)
	// Iterate over all manifest reference values
	log.Tracef("Collecting reference values from %v manifests", len(metadata))
	for _, m := range metadata {
		if m.Sbom == nil {
			log.Tracef("Manifest does not contain sbom. Continue")
			continue
		}
		log.Tracef("Manifest contains %v reference values", len(m.Sbom.Components))
		for _, r := range m.Sbom.Components {
			// Check reference value type
			if r.Type != ar.TYPE_REFVAL_SNP &&
				r.Type != ar.TYPE_REFVAL_SW &&
				r.Type != ar.TYPE_REFVAL_TPM &&
				r.Type != ar.TYPE_REFVAL_TDX &&
				r.Type != ar.TYPE_REFVAL_SGX {
				return nil, fmt.Errorf("reference value of type %q is not supported", r.Type)
			}

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

func collectMetadata(context ar.Context, cached map[string][]byte) (map[string][]byte, error) {

	collectedMetadata := make(map[string][]byte, len(context.Digests))

	notFound := 0
	for _, digest := range context.Digests {
		// Check if item is in report
		if item, ok := context.Metadata[digest]; ok {
			collectedMetadata[digest] = item
			continue
		}
		// Check if item is cached
		if item, ok := cached[digest]; ok {
			collectedMetadata[digest] = item
			continue
		}
		notFound++
	}

	if notFound > 0 {
		return collectedMetadata, fmt.Errorf("failed to find %v metadata items", notFound)
	}
	return collectedMetadata, nil
}
