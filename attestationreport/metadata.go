// Copyright (c) 2026 Fraunhofer AISEC
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
	"crypto/x509"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// MetadataSet holds the parsed metadata of an image, manifests ordered root first
type MetadataSet struct {
	ImageDescription   Metadata
	Manifests          []Metadata
	CompanyDescription *Metadata
}

// metadataEntry pairs a parsed metadata item with its verification result
type metadataEntry struct {
	meta   Metadata
	result MetadataResult
}

// ParseAndVerifyMetadata takes the metadata map with keys being the digests of the raw metadata
// items and a set of CAs and performs a validity, signature and certificate chain validation, as
// well as compatibility checks: The image description must reference all manifests, and starting
// from an inherently trusted root manifest, all manifests must have a compatible base layer.
// It optionally also checks that none of the manifests have been revoked based on the OMSP response.
// Multiple image descriptions, company descriptions or OMSP responses for the same server are
// rejected and recorded in the unknown results.
//
// The returned error is non-nil if and only if the summary status is fail. The set is always
// returned for diagnosis, but its content must not be trusted if the error is non-nil.
func ParseAndVerifyMetadata(cas []*x509.Certificate, items map[string][]byte, checkOmsp bool,
) (*MetadataSet, MetadataSummary, error) {

	set := &MetadataSet{}
	summary := MetadataSummary{}
	status := StatusSuccess

	var imageDescriptions, companyDescriptions, manifests []metadataEntry
	omspResponses := make(map[string][]metadataEntry)

	for _, digest := range slices.Sorted(maps.Keys(items)) {

		meta, result := ParseAndVerifyMetadataItem(digest, items[digest], cas)
		if result.Summary.Status != StatusSuccess {
			status = StatusFail
		}
		log.Tracef("Finished validation of metadata item %v: %v", digest, result.Summary.Status)

		if meta == nil {
			summary.UnknownResults = append(summary.UnknownResults, result)
			status = StatusFail
			continue
		}
		e := metadataEntry{meta: *meta, result: result}

		switch meta.Type {
		case TYPE_IMAGE_DESCRIPTION:
			imageDescriptions = append(imageDescriptions, e)
		case TYPE_COMPANY_DESCRIPTION:
			companyDescriptions = append(companyDescriptions, e)
		case TYPE_MANIFEST:
			manifests = append(manifests, e)
		case TYPE_OMSP_RESPONSE:
			omspResponses[meta.Server] = append(omspResponses[meta.Server], e)
		default:
			summary.UnknownResults = append(summary.UnknownResults, result)
			log.Warnf("Unknown manifest type %v", meta.Type)
			status = StatusFail
		}
	}

	if unique, ok := summary.selectUnique(imageDescriptions, MultipleImageDescriptions); ok {
		if unique != nil {
			set.ImageDescription = unique.meta
			summary.ImageDescriptionResult = unique.result
		}
	} else {
		status = StatusFail
	}

	if unique, ok := summary.selectUnique(companyDescriptions, MultipleCompanyDescriptions); ok {
		if unique != nil {
			set.CompanyDescription = &unique.meta
			summary.CompanyDescriptionResult = &unique.result
		}
	} else {
		status = StatusFail
	}

	omspMap := make(map[string]Metadata)
	for _, server := range slices.Sorted(maps.Keys(omspResponses)) {
		unique, ok := summary.selectUnique(omspResponses[server], MultipleOmspResponses)
		if !ok {
			status = StatusFail
			continue
		}
		omspMap[server] = unique.meta
		summary.OmspResults = append(summary.OmspResults, unique.result)
	}

	if checkOmsp {
		status = status.Worse(checkManifestRevocation(manifests, omspMap))
	}

	compatibility, manifests := checkMetadataCompatibility(set.ImageDescription, manifests)
	if compatibility.Summary.Status != StatusSuccess {
		status = StatusFail
	}
	summary.CompatibilityResult = compatibility

	for _, m := range manifests {
		set.Manifests = append(set.Manifests, m.meta)
		summary.ManifestResults = append(summary.ManifestResults, m.result)
	}

	summary.Summary.Status = status
	if status == StatusFail {
		return set, summary, fmt.Errorf("metadata verification failed")
	}
	return set, summary, nil
}

// selectUnique returns the only item of candidates, or nil if there is none. If there are multiple
// items, all of them fail with the given error code and are moved to the unknown results.
func (s *MetadataSummary) selectUnique(candidates []metadataEntry, code ErrorCode,
) (*metadataEntry, bool) {
	switch len(candidates) {
	case 0:
		return nil, true
	case 1:
		return &candidates[0], true
	}
	for _, c := range candidates {
		log.Warnf("Found multiple %v items: %v (digest %v)", c.meta.Type, c.meta.Name,
			c.result.Digest)
		c.result.Summary.Fail(code)
		s.UnknownResults = append(s.UnknownResults, c.result)
	}
	return nil, false
}

// newMetadataResult creates a result holding the display fields of the metadata item
func newMetadataResult(m *Metadata) MetadataResult {
	return MetadataResult{
		MetaInfo:   m.MetaInfo,
		BaseLayers: m.BaseLayers,
		Details:    m.Details,
		Location:   m.Location,
	}
}

// ParseAndVerifyMetadataItem detects the serialization of a single raw metadata item, verifies its
// signature against the CAs, unpacks it and checks its validity period. Failures are recorded in
// the returned result, which also records the digest of the item. The returned metadata is nil if
// the item could not be parsed. If the result status is not success, the metadata is unverified
// and only returned for diagnosis.
func ParseAndVerifyMetadataItem(digest string, raw []byte, cas []*x509.Certificate,
) (*Metadata, MetadataResult) {
	log.Tracef("Validating metadata item %v...", digest)

	s, err := DetectSerialization(raw)
	if err != nil {
		result := MetadataResult{Digest: digest}
		result.Summary.Fail(ExtractPayload, err)
		return nil, result
	}
	log.Tracef("Detected %v serialization", s.String())

	payload, sigs, sigResult := s.Verify(raw, cas)
	if sigResult.Status != StatusSuccess {
		log.Warnf("Signature verification of metadata item %v failed", digest)
		// Still unpack metadata item for validation-result diagnosis
		payload, err = s.GetPayload(raw)
		if err != nil {
			sigResult.Fail(ExtractPayload, err)
		} else {
			log.Trace("Extracted unverified JWS payload")
		}
	} else {
		log.Tracef("Signature verification of metadata item %v successful", digest)
	}

	meta := new(Metadata)
	if err = s.Unmarshal(payload, meta); err != nil {
		result := MetadataResult{
			Digest:         digest,
			Summary:        sigResult,
			SignatureCheck: sigs,
		}
		result.Summary.Fail(ParseMetadata, err)
		return nil, result
	}
	log.Tracef("Parse metadata %v: %v successful", meta.Type, meta.Name)

	result := newMetadataResult(meta)
	result.Digest = digest
	result.Summary = sigResult
	result.SignatureCheck = sigs

	if meta.Type == TYPE_OMSP_RESPONSE {
		log.Tracef("Checking validity of OMSP response...")
		currentTime := time.Now()
		notBefore, err := time.Parse(time.RFC3339, meta.ProducedAt)
		if err != nil {
			result.Summary.Status = StatusFail
			result.ValidityCheck.Fail(ParseTime, err)
		} else if notBefore.After(currentTime) {
			result.Summary.Status = StatusFail
			result.ValidityCheck.Fail(NotYetValid)
			result.ValidityCheck.Got = currentTime.String()
			result.ValidityCheck.ExpectedBetween = []string{notBefore.String(), "-"}
			log.Warn("OMSP Response invalid since ProducedAt lies in the future")
		} else {
			result.ValidityCheck.Status = StatusSuccess
			log.Trace("OMSP Response valid")
		}
	} else {
		log.Trace("Checking validity of metadata item...")
		if meta.Validity == nil {
			log.Warnf("Manifest %v: %v is missing validity information", meta.Type, meta.Name)
			result.Summary.Status = StatusFail
		} else {
			result.ValidityCheck = checkValidity(meta.Validity)
			if result.ValidityCheck.Status == StatusFail {
				log.Warnf("Checking expiration of %v: %v failed (NotBefore: %v, NotAfter: %v)",
					meta.Type, meta.Name, meta.Validity.NotBefore, meta.Validity.NotAfter)
				result.Summary.Status = StatusFail
			} else {
				log.Tracef("Checking expiration of %v: %v successful", meta.Type, meta.Name)
			}
		}
	}
	return meta, result
}

// checkMetadataCompatibility checks that the image description and the manifests reference each
// other and that all manifests have a compatible base layer starting from the root manifest. It
// returns the manifests reordered with the root manifest first, followed by its dependents.
func checkMetadataCompatibility(imageDescription Metadata, manifests []metadataEntry,
) (CompatibilityResult, []metadataEntry) {

	result := CompatibilityResult{
		Summary: Result{
			Status: StatusSuccess,
		},
	}

	if imageDescription.Name == "" {
		result.Summary.Fail(ImageDescriptionNotPresent)
	}

	// Gather all manifest names referenced in the manifest descriptions
	descManifests := make([]string, 0, len(imageDescription.Descriptions))
	for _, m := range imageDescription.Descriptions {
		descManifests = append(descManifests, m.Manifest)
	}

	// Gather all manifest names from the manifests
	manifestNames := make([]string, 0, len(manifests))
	for _, m := range manifests {
		manifestNames = append(manifestNames, m.meta.Name)
	}

	// Check that each manifest description has a corresponding manifest
	log.Tracef("Iterating manifest descriptions length %v", len(imageDescription.Descriptions))
	descriptionMatch := make([]Result, 0, len(imageDescription.Descriptions))
	for _, desc := range imageDescription.Descriptions {

		ok := internal.Contains(desc.Manifest, manifestNames)
		if !ok {
			log.Warnf("No manifest for manifest description: %v", desc.Manifest)
			result.Summary.Status = StatusFail
		}

		descriptionMatch = append(descriptionMatch, Result{
			Status:        StatusFromBool(ok),
			Got:           desc.Manifest,
			ExpectedOneOf: manifestNames,
		})
	}

	// Check that each manifest has a corresponding manifest description
	log.Tracef("Iterating manifests length %v", len(manifests))
	manifestMatch := make([]Result, 0, len(manifests))
	for _, m := range manifests {
		// Found manifests have already been recorded, only record missing ones
		if !internal.Contains(m.meta.Name, descManifests) {
			log.Warnf("No manifest description for manifest: %v", m.meta.Name)
			result.Summary.Status = StatusFail
			manifestMatch = append(manifestMatch, Result{
				Status:        StatusFail,
				Got:           m.meta.Name,
				ExpectedOneOf: descManifests,
			})
		}
	}

	// Check that each manifest has a compatible base layer
	sorted, manifestCompatibility, errCode, ok := processManifests(manifests)
	if !ok {
		result.Summary.Fail(errCode)
	}

	result.DescriptionMatch = descriptionMatch
	result.ManifestMatch = manifestMatch
	result.ManifestCompatibility = manifestCompatibility

	return result, sorted
}

// CollectComponents gathers the reference value components of all manifests grouped by trust
// anchor and attaches the OCI rules of the corresponding manifest descriptions.
func CollectComponents(manifests []Metadata, descriptions []ManifestDescription,
) (map[string][]Component, error) {

	// SwVerify only: Build manifest-name: OciRules lookup from descriptions for
	log.Tracef("Collecting OCI rules for %v descriptions", len(descriptions))
	rulesLookup := make(map[string]map[string]interface{})
	for _, desc := range descriptions {
		if desc.OciRules != nil {
			rulesLookup[desc.Manifest] = desc.OciRules
		}
	}

	refmap := make(map[string][]Component)
	// Iterate over all manifest reference values
	log.Tracef("Collecting reference values from %v manifests", len(manifests))
	for _, m := range manifests {
		if m.Sbom == nil {
			log.Tracef("Manifest does not contain sbom. Continue")
			continue
		}
		log.Tracef("Manifest contains %v reference values", len(m.Sbom.Components))
		for _, r := range m.Sbom.Components {
			ta, err := r.GetTrustAnchor()
			if err != nil {
				return nil, fmt.Errorf("component %q: %w", r.Name, err)
			}

			switch ta {
			case TRUST_ANCHOR_TPM, TRUST_ANCHOR_TDX, TRUST_ANCHOR_SNP,
				TRUST_ANCHOR_SGX, TRUST_ANCHOR_IAS, TRUST_ANCHOR_SW,
				TRUST_ANCHOR_SWIMA:
			default:
				return nil, fmt.Errorf("unsupported trust anchor %q", ta)
			}

			// SwVerify only: Add rules
			if rules, ok := rulesLookup[m.Name]; ok {
				log.Tracef("Adding rules for %q", m.Name)
				r.OciRules = rules
			}

			// Collect all reference values by trust anchor
			refmap[ta] = append(refmap[ta], r)
		}
	}

	return refmap, nil
}

// CollectMetadata retrieves the raw metadata items for all digests of the report context, either
// from the report itself or from the cached items. It returns an error if items are missing.
func CollectMetadata(context Context, cached map[string][]byte) (map[string][]byte, error) {

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

// IsRootManifest reports whether the manifest is a root of trust manifest, i.e., its only
// base layer is itself
func IsRootManifest(m Metadata) bool {
	return len(m.BaseLayers) == 1 && m.Name == m.BaseLayers[0]
}

// RootManifest returns the first root of trust manifest or an empty manifest if there is none.
// Multiple root manifests are rejected during metadata verification.
func RootManifest(manifests []Metadata) Metadata {
	for _, m := range manifests {
		if IsRootManifest(m) {
			return m
		}
	}
	return Metadata{}
}

// processManifests sorts the manifests starting with the root manifest, followed by the manifests
// with a compatible base layer. Manifests without compatible base layer are appended at the end.
func processManifests(manifests []metadataEntry) ([]metadataEntry, []Result, ErrorCode, bool) {

	mm := make(map[string][]metadataEntry)
	var root *metadataEntry
	results := make([]Result, 0)
	success := true

	// Organize manifests by BaseLayer
	for i := range manifests {
		m := &manifests[i]
		if IsRootManifest(m.meta) {
			// Check that there is exactly one root of trust manifest
			if root != nil {
				log.Warnf("Found additional root of trust manifest %v (already got %v)",
					m.meta.Name, root.meta.Name)
				return manifests, nil, MultipleRootManifests, false
			}
			root = m
		} else {
			for _, base := range m.meta.BaseLayers {
				mm[base] = append(mm[base], *m)
			}
		}
	}

	if root == nil || root.meta.Name == "" {
		log.Warn("Did not find root manifest")
		return manifests, nil, NoRootManifest, false
	}

	// Start the sorted list with the root
	sorted := []metadataEntry{*root}
	results = append(results, Result{
		Status: StatusSuccess,
		Got:    root.meta.Name,
	})

	// Track processed layers
	processed := map[string]bool{root.meta.Name: true}

	// Iteratively add dependent layers
	for i := 0; i < len(sorted); i++ {
		for _, dependent := range mm[sorted[i].meta.Name] {
			name := dependent.meta.Name
			if !processed[name] && hasCompatibleBaseLayer(dependent.meta.BaseLayers, processed) {
				sorted = append(sorted, dependent)
				processed[name] = true
				results = append(results, Result{
					Status:        StatusSuccess,
					Got:           name,
					ExpectedOneOf: dependent.meta.BaseLayers,
				})
			}
		}
	}

	// Add manifests with no compatible base layer to the end of the list
	for _, m := range manifests {
		if !processed[m.meta.Name] {
			log.Warnf("%v has no compatible baselayer", m.meta.Name)
			sorted = append(sorted, m)
			success = false
			results = append(results, Result{
				Status:        StatusFail,
				Got:           m.meta.Name,
				ExpectedOneOf: m.meta.BaseLayers,
			})
		}
	}

	return sorted, results, NotSpecified, success
}

func hasCompatibleBaseLayer(baseLayers []string, processed map[string]bool) bool {
	for _, base := range baseLayers {
		if processed[base] {
			return true
		}
	}
	return false
}

func checkValidity(val *Validity) Result {
	result := Result{
		Status: StatusSuccess,
	}

	notBefore, err := time.Parse(time.RFC3339, val.NotBefore)
	if err != nil {
		result.Fail(ParseTime, err)
		return result
	}
	notAfter, err := time.Parse(time.RFC3339, val.NotAfter)
	if err != nil {
		result.Fail(ParseTime, err)
		return result
	}
	currentTime := time.Now()

	if notBefore.After(currentTime) {
		result.Fail(NotYetValid)
		result.Got = currentTime.String()
		result.ExpectedBetween = []string{notBefore.String(), notAfter.String()}
	}

	if currentTime.After(notAfter) {
		result.Fail(Expired)
		result.Got = currentTime.String()
		result.ExpectedBetween = []string{notBefore.String(), notAfter.String()}
	}

	return result
}

func checkManifestRevocation(manifests []metadataEntry, omspMap map[string]Metadata) Status {

	success := StatusSuccess

	log.Debug("Checking revocation status of manifests...")
	for i := range manifests {
		elem := &manifests[i].result
		omspServer := manifests[i].meta.OmspServer
		if omspServer == "" {
			log.Debugf("Manifest %v with digest %v does not contain omsp request URL. Ignore",
				elem.Name, elem.Digest)
			elem.Summary.appendDetails(
				"Revocation check for manifest was not possible, because manifest contains no OmspServer URL")
			continue
		}

		omspFound := false
		for _, resp := range omspMap[omspServer].Responses {

			if resp.ManifestHash == elem.Digest {
				omspFound = true

				log.Debugf("Found OMSP Response for Manifest %v (%v)", elem.Name, elem.Digest)
				elem.OmspValidity = checkOmspValidity(resp.ThisUpdate, resp.NextUpdate)
				if elem.OmspValidity.Status == StatusFail {
					log.Debugf("Check for validity of the omsp response failed with error code(s) %v", elem.OmspValidity.ErrorCodes)
				} else {
					log.Debugf("omsp response is valid")
				}

				elem.OmspStatus = &Result{}
				elem.OmspStatus.Got = string(resp.Status)
				switch resp.Status {
				case OmspStatusGood:
					log.Debugf("%v is still valid (not revoked)", elem.Name)
					elem.OmspStatus.Status = StatusSuccess
				case OmspStatusOutdated:
					log.Debugf("%v is outdated (but not revoked)", elem.Name)
					elem.OmspStatus.Warn(ManifestOutdated)
				case OmspStatusRevoked:
					log.Debugf("%v is revoked", elem.Name)
					elem.OmspStatus.Fail(ManifestRevoked)
					elem.RevocationTime = resp.RevocationTime
					elem.RevocationReason = resp.RevocationReason
				case OmspStatusUnknown:
					log.Debugf("For %v the OMSP provider had no revocation information", elem.Name)
					elem.OmspStatus.Fail(ManifestRevocationUnknown)
				default:
					log.Debugf("%v has an unknown revocation status assigned %v", elem.Name, resp.Status)
					elem.OmspStatus.Fail(ManifestRevocationUnknown)
				}
				break
			}
		}
		if !omspFound {
			log.Debugf("For %v (digest: %v) no revocation information was provided", elem.Name, elem.Digest)
			elem.OmspStatus = &Result{}
			elem.OmspStatus.Fail(ManifestRevocationUnknown)
		}

		omspStatus := elem.OmspStatus.Status
		if elem.OmspValidity != nil {
			omspStatus = omspStatus.Worse(elem.OmspValidity.Status)
		}
		elem.Summary.Status = elem.Summary.Status.Worse(omspStatus)
		success = success.Worse(omspStatus)
	}
	return success
}

func checkOmspValidity(thisUpdate string, nextUpdate string) *Result {
	result := &Result{
		Status: StatusSuccess,
	}

	notBefore, err := time.Parse(time.RFC3339, thisUpdate)
	if err != nil {
		result.Fail(ParseTime, err)
		return result
	}
	currentTime := time.Now()

	if notBefore.After(currentTime) {
		result.Fail(NotYetValid)
		result.Got = currentTime.String()
		result.ExpectedBetween = []string{thisUpdate, nextUpdate}
	}

	if nextUpdate != "" {
		notAfter, err := time.Parse(time.RFC3339, nextUpdate)
		if err != nil {
			result.Fail(ParseTime, err)
			return result
		}

		if currentTime.After(notAfter) {
			result.Fail(Expired)
			result.Got = currentTime.String()
			result.ExpectedBetween = []string{thisUpdate, nextUpdate}
		}
	}

	return result
}
