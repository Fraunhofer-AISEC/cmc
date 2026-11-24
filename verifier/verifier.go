// Copyright (c) 2021 - 2026 Fraunhofer AISEC
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
	"fmt"
	"maps"
	"slices"
	"sort"

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

	policyEngineNames = map[string]PolicyEngineSelect{
		"js":      PolicyEngineSelect_JS,
		"duktape": PolicyEngineSelect_DukTape,
	}
)

// PolicyEngines returns the names of the policy engines compiled into the binary
func PolicyEngines() []string {
	var names []string
	for name, sel := range policyEngineNames {
		if _, ok := policyEngines[sel]; ok {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// ParsePolicyEngine returns the policy engine with the given name, if compiled into the binary
func ParsePolicyEngine(name string) (PolicyEngineSelect, error) {
	sel, ok := policyEngineNames[name]
	if !ok {
		return PolicyEngineSelect_None, fmt.Errorf("unknown policy engine %q", name)
	}
	if _, ok := policyEngines[sel]; !ok {
		return PolicyEngineSelect_None, fmt.Errorf("policy engine %q not compiled in", name)
	}
	return sel, nil
}

// VerifyOptions configures the verification of an attestation report
type VerifyOptions struct {
	// Policies are optional custom policies validated by PolicyEngine
	Policies        []byte
	PolicyEngine    PolicyEngineSelect
	PolicyOverwrite bool
	// MetadataCas are the trusted CAs for the metadata signatures
	MetadataCas []*x509.Certificate
	// PeerCache optionally caches the metadata of Peer
	PeerCache *peercache.Cache
	Peer      string
	PeerAddr  string
	CheckOmsp bool
	// LocalRole is the role of the verifier used for peer authorization
	LocalRole string
	// SkipPeerAuth disables the peer authorization, e.g. for bootstrap attestation during
	// certificate enrollment
	SkipPeerAuth bool
}

// Verify verifies an attestation report in full serialized JWS or COSE
// format against the supplied nonce. This includes verifying the integrity of the overall
// report, which is bound to the hardware nonce, verifying the certificate
// chains of all attestation report elements as well as verifying the measurements against
// the reference values and the compatibility of software artefacts. Unless disabled, it also
// enforces the peer authorization from the signed metadata based on the provided local role
func Verify(arRaw, nonce []byte, opts VerifyOptions) *ar.AttestationResult {
	log.Debugf("Verifying attestation report")

	result := &ar.AttestationResult{
		Version: ar.GetResultVersion(),
		Type:    ar.TYPE_ATTESTATION_RESULT,
		Prover: ar.Endpoint{
			PeerId: opts.Peer,
		},
		Summary: ar.Result{
			Status: ar.StatusSuccess,
		},
		Measurements: []ar.MeasurementResult{},
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
	log.Debugf("Unmarshalling attestation report")
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
	log.Debugf("Successfully unmarshalled attestation report")

	// Retrieve cached metadata items for peer if configured
	var cachedMetadata map[string][]byte
	if opts.PeerCache != nil {
		cachedMetadata = opts.PeerCache.Get(opts.Peer)
	}

	// Iterate over report metadata digests and retrieve metadata items from report and peer cache
	collectedMetadata, err := ar.CollectMetadata(report.Context, cachedMetadata)
	if err != nil {
		result.Fail(ar.VerifyMetadata, err)
	}

	// A failed update of the peer cache only means that we need to send more
	// data during the next attestation
	if opts.PeerCache != nil {
		err = opts.PeerCache.Update(opts.Peer, collectedMetadata)
		if err != nil {
			log.Warnf("Failed to update peer cache: %v", err)
		}
	}

	// Verify and unpack metadata from attestation report
	log.Debugf("Verifying metadata from prover %v", result.Prover.Hostname)
	metaResults, status := ar.ParseAndVerifyMetadata(opts.MetadataCas, collectedMetadata, opts.CheckOmsp)
	switch status {
	case ar.StatusSuccess:
		log.Debug("Successfully verified metadata")
	case ar.StatusFail:
		result.Fail(ar.VerifyMetadata)
	case ar.StatusWarn:
		result.Warn(ar.VerifyMetadata)
	}

	result.Metadata = metaResults
	result.Name = metaResults.ImageDescriptionResult.Name
	if report.Name != "" {
		result.Prover.Hostname = report.Name
	} else {
		result.Prover.Hostname = "unknown"
	}
	if opts.PeerAddr != "" {
		result.Prover.Ip = opts.PeerAddr
	}

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

	// Add the prover's claims. They need no separate check, as they are part of the hashed context
	if len(report.Context.Claims) > 0 {
		result.Claims = report.Context.Claims
		log.Debugf("Report carries %v prover-asserted claim(s)", len(report.Context.Claims))
	}

	refVals, err := ar.CollectComponents(metaResults.ManifestResults, metaResults.ImageDescriptionResult.Descriptions)
	if err != nil {
		result.Fail(ar.RefValTypeNotSupported, err)
		return result
	}

	// Hardware policies and CA fingerprints are taken from the root manifest
	root := ar.RootManifest(metaResults.ManifestResults)

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
			tpmCas, requireAkEku := tpmAkTrust(report.Evidences, col, opts.MetadataCas)
			addMeasurements(result, "TPM", *VerifyTpm(ev, col, evidenceNonce, tpmCas, requireAkEku,
				refVals[ar.TRUST_ANCHOR_TPM], s))

		case ar.TYPE_EVIDENCE_SNP:
			addMeasurements(result, "SNP", *VerifySnp(ev, col, evidenceNonce, root.SnpPolicy,
				root.CaFingerprints, refVals[ar.TRUST_ANCHOR_SNP]))

		case ar.TYPE_EVIDENCE_TDX:
			addMeasurements(result, "TDX", *VerifyTdx(ev, col, evidenceNonce, root.TdxPolicy,
				root.CaFingerprints, refVals[ar.TRUST_ANCHOR_TDX]))

		case ar.TYPE_EVIDENCE_SGX:
			addMeasurements(result, "SGX", *VerifySgx(ev, col, evidenceNonce, root.SgxPolicy,
				root.CaFingerprints, refVals[ar.TRUST_ANCHOR_SGX]))

		case ar.TYPE_EVIDENCE_IAS:
			addMeasurements(result, "IAS", *VerifyIas(ev, col, evidenceNonce, root.CaFingerprints,
				refVals[ar.TRUST_ANCHOR_IAS]))

		case ar.TYPE_EVIDENCE_SW:
			addMeasurements(result, "SW", *VerifySw(ev, col, evidenceNonce, refVals[ar.TRUST_ANCHOR_SW]))

		case ar.TYPE_EVIDENCE_SWIMA:
			addMeasurements(result, "IMA", *VerifySwima(ev, col, evidenceNonce,
				refVals[ar.TRUST_ANCHOR_SWIMA]))

		case ar.TYPE_EVIDENCE_AZURE_SNP, ar.TYPE_EVIDENCE_AZURE_TDX, ar.TYPE_EVIDENCE_AZURE_TPM:
			addMeasurements(result, "azure", VerifyAzure(report.Evidences, report.Context.Collateral,
				evidenceNonce, root.TdxPolicy, root.SnpPolicy, root.CaFingerprints,
				refVals[ar.TRUST_ANCHOR_TDX], refVals[ar.TRUST_ANCHOR_SNP],
				refVals[ar.TRUST_ANCHOR_TPM], s)...)

			// Required because we process multiple measurements for azure
			break Loop

		default:
			result.Fail(ar.MeasurementTypeNotSupported,
				fmt.Errorf("unsupported measurement type %q", evtype))
		}
	}

	sortArtifacts(result.Measurements)

	// Reference values and hardware policies are only enforced if the report contains the
	// evidence of their trust anchor, so a report must not omit required evidence
	covered := coveredTrustAnchors(report.Evidences)
	for _, ta := range requiredTrustAnchors(refVals, root) {
		if !covered[ta] {
			result.Fail(ar.EvidenceMissing, fmt.Errorf(
				"metadata requires %v evidence, but the attestation report does not contain it", ta))
		}
	}
	result.AttestLevel = attestLevel(covered)
	log.Debugf("Attestation level: %v", result.AttestLevel)

	// Check if we are allowed to establish a connection with this peer in case peer policies are
	// provided
	if !opts.SkipPeerAuth {
		result.PeerAuth = verifyPeerAuthorization(opts.LocalRole, &result.Metadata)
		result.Summary.Status = result.Summary.Status.Worse(result.PeerAuth.Status)
	}

	// Add additional information
	result.Created = time.Now().Format(time.RFC3339Nano)

	// Validate policies if specified
	if opts.Policies != nil {
		p, ok := policyEngines[opts.PolicyEngine]
		if !ok {
			result.Fail(ar.PolicyEngineNotImplemented)
		} else {
			ok = p.Validate(result, opts.Policies, opts.PolicyOverwrite)
			if !ok {
				result.Fail(ar.VerifyPolicies)
			}
		}
	} else {
		log.Debugf("No custom policies specified")
	}

	switch result.Summary.Status {
	case ar.StatusSuccess:
		log.Infof("SUCCESS: Verification for Prover %v (%v)", result.Prover.Hostname, result.Created)
	case ar.StatusWarn:
		log.Infof("WARN: Verification for Prover %v (%v)", result.Prover.Hostname, result.Created)
	case ar.StatusFail:
		log.Infof("FAILED: Verification for Prover %v (%v)", result.Prover.Hostname, result.Created)
	default:
		log.Infof("FAILED UNKNOWN: Verification for Prover %v (%v)", result.Prover.Hostname, result.Created)
		result.Summary.Status = ar.StatusFail
	}

	return result
}

// addMeasurements appends measurement results and propagates their status to the attestation
// result
func addMeasurements(result *ar.AttestationResult, name string, ms ...ar.MeasurementResult) {
	for _, m := range ms {
		switch m.Summary.Status {
		case ar.StatusSuccess:
		case ar.StatusWarn:
			result.Warn(ar.VerifyMeasurement, fmt.Errorf("%v measurement", name))
		default:
			result.Fail(ar.VerifyMeasurement, fmt.Errorf("%v measurement", name))
		}
		result.Measurements = append(result.Measurements, m)
	}
}

// verifyNonce compares a measured nonce against an expected nonce and populates the
// freshness result accordingly. Returns true if the nonces match.
func verifyNonce(measured, expected []byte) ar.Result {

	if bytes.Equal(measured, expected) {
		log.Debugf("Successfully verified evidence nonce %x", expected)
		return ar.Result{
			Status: ar.StatusSuccess,
			Got:    hex.EncodeToString(expected),
		}
	}

	log.Warnf("Nonces mismatch: expected %v, got %v",
		hex.EncodeToString(expected), hex.EncodeToString(measured))
	return ar.Result{
		Status:   ar.StatusFail,
		Expected: hex.EncodeToString(expected),
		Got:      hex.EncodeToString(measured),
	}
}

// evidenceTrustAnchors maps the evidence types to the trust anchors whose reference values they
// verify
var evidenceTrustAnchors = map[string][]string{
	ar.TYPE_EVIDENCE_TPM:       {ar.TRUST_ANCHOR_TPM},
	ar.TYPE_EVIDENCE_SNP:       {ar.TRUST_ANCHOR_SNP},
	ar.TYPE_EVIDENCE_TDX:       {ar.TRUST_ANCHOR_TDX},
	ar.TYPE_EVIDENCE_SGX:       {ar.TRUST_ANCHOR_SGX},
	ar.TYPE_EVIDENCE_IAS:       {ar.TRUST_ANCHOR_IAS},
	ar.TYPE_EVIDENCE_SW:        {ar.TRUST_ANCHOR_SW},
	ar.TYPE_EVIDENCE_SWIMA:     {ar.TRUST_ANCHOR_SWIMA},
	ar.TYPE_EVIDENCE_AZURE_SNP: {ar.TRUST_ANCHOR_SNP},
	ar.TYPE_EVIDENCE_AZURE_TDX: {ar.TRUST_ANCHOR_TDX},
	ar.TYPE_EVIDENCE_AZURE_TPM: {ar.TRUST_ANCHOR_TPM},
}

// hardwareTrustAnchors are the trust anchors whose evidence is signed by hardware
var hardwareTrustAnchors = []string{
	ar.TRUST_ANCHOR_TPM, ar.TRUST_ANCHOR_SNP, ar.TRUST_ANCHOR_TDX, ar.TRUST_ANCHOR_SGX,
	ar.TRUST_ANCHOR_IAS,
}

// coveredTrustAnchors returns the trust anchors the evidences of a report provide
func coveredTrustAnchors(evidences []ar.Evidence) map[string]bool {
	covered := make(map[string]bool)
	for _, ev := range evidences {
		for _, ta := range evidenceTrustAnchors[ev.Type] {
			covered[ta] = true
		}
	}
	return covered
}

// requiredTrustAnchors returns the sorted trust anchors with mandatory reference values or a
// hardware policy in the root manifest
func requiredTrustAnchors(refVals map[string][]ar.Component, root ar.MetadataResult) []string {
	required := make(map[string]bool)
	for ta, components := range refVals {
		if slices.ContainsFunc(components, func(c ar.Component) bool { return !c.Optional }) {
			required[ta] = true
		}
	}
	if root.SnpPolicy != nil {
		required[ar.TRUST_ANCHOR_SNP] = true
	}
	if root.TdxPolicy != nil {
		required[ar.TRUST_ANCHOR_TDX] = true
	}
	if root.SgxPolicy != nil {
		required[ar.TRUST_ANCHOR_SGX] = true
	}
	return slices.Sorted(maps.Keys(required))
}

// attestLevel returns the level reached by the evidence of the covered trust anchors
func attestLevel(covered map[string]bool) ar.AttestLevel {
	switch {
	case slices.ContainsFunc(hardwareTrustAnchors, func(ta string) bool { return covered[ta] }):
		return ar.LevelHardware
	case len(covered) > 0:
		return ar.LevelSoftware
	}
	return ar.LevelNone
}

// reportHasCvmAnchor reports whether the attestation report contains a hardware
// CVM evidence type that binds the whole Context and thus the TPM AK cert.
func reportHasCvmAnchor(evidences []ar.Evidence) bool {
	for _, ev := range evidences {
		switch ev.Type {
		case ar.TYPE_EVIDENCE_SNP, ar.TYPE_EVIDENCE_TDX, ar.TYPE_EVIDENCE_SGX:
			return true
		}
	}
	return false
}

// tpmAkTrust returns the CAs to verify the TPM AK certificate chain against and whether the AK
// certificate must carry tcg-kp-AIKCertificate. If the TPM acts as a primary trust anchor, the
// metadata CAs (privacy CA) are used, as the TPM EK is not allowed to sign, and the AK extended
// key usage is required. If the vTPM acts as a secondary trust anchor, integrity is verified
// through the binding of the self-signed vTPM AK certificate with the hardware report
func tpmAkTrust(evidences []ar.Evidence, col ar.Collateral, metadataCas []*x509.Certificate,
) ([]*x509.Certificate, bool) {
	if reportHasCvmAnchor(evidences) {
		ak, err := selfSignedAkFromCollateral(col)
		if err == nil && ak != nil {
			log.Debug("Use self-signed AK cert: report includes hardware CVM binding")
			return []*x509.Certificate{ak}, false
		}
	}
	return metadataCas, true
}

// selfSignedAkFromCollateral returns the AK certificate from the vTPM collateral
// if it is self-signed.
func selfSignedAkFromCollateral(col ar.Collateral) (*x509.Certificate, error) {
	if len(col.Certs) == 0 {
		return nil, nil
	}
	cert, err := x509.ParseCertificate(col.Certs[0])
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return nil, nil
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return nil, nil
	}
	return cert, nil
}

// extractX509Chains converts verified x509 certificate chains into the
// serializable X509CertExtracted format used in attestation results.
func extractX509Chains(chains [][]*x509.Certificate) [][]ar.X509CertExtracted {
	var result [][]ar.X509CertExtracted
	for _, chain := range chains {
		extracted := make([]ar.X509CertExtracted, 0, len(chain))
		for _, cert := range chain {
			extracted = append(extracted, ar.ExtractX509Infos(cert))
		}
		result = append(result, extracted)
	}
	return result
}

func verifyCaFingerprint(ca *x509.Certificate, refFingerprints []string) ar.Result {

	result := ar.Result{}

	log.Debugf("Checking %v CA fingerprints", len(refFingerprints))

	caFingerprint := sha256.Sum256(ca.Raw)

	for _, fp := range refFingerprints {
		refFingerprint, err := hex.DecodeString(fp)
		if err != nil {
			log.Warnf("Failed to decode CA fingerprint %v: %v", fp, err)
			result.Fail(ar.ParseCAFingerprint)
			return result
		}
		if bytes.Equal(refFingerprint, caFingerprint[:]) {
			log.Debugf("Found matching CA fingerprint %x", refFingerprint)
			result.Got = fp
			result.Status = ar.StatusSuccess
			return result
		} else {
			log.Warnf("Root Manifest CA fingerprint %x does not match measurement CA fingerprint %x. Continue..",
				refFingerprint, caFingerprint[:])
			continue
		}
	}

	log.Warn("Failed to find matching CA fingerprint")

	result.Status = ar.StatusFail
	result.ExpectedOneOf = refFingerprints
	result.Got = hex.EncodeToString(caFingerprint[:])
	return result
}

// sortArtifacts sorts the artifacts of each measurement by measurement register index.
func sortArtifacts(measurements []ar.MeasurementResult) {
	for i := range measurements {
		artifacts := measurements[i].Artifacts
		sort.SliceStable(artifacts, func(a, b int) bool {
			return artifacts[a].Index < artifacts[b].Index
		})
	}
}
