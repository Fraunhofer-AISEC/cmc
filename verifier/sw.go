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
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	jcs "github.com/Fraunhofer-AISEC/cmc/jsoncanonicalizer"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func VerifySw(
	evidence ar.Evidence,
	collateral ar.Collateral,
	nonce []byte,
	refComponents []ar.Component,
) (*ar.MeasurementResult, bool) {

	log.Debug("Verifying SW measurements")

	result := &ar.MeasurementResult{
		Type: "SW Result",
	}
	ok := true

	// SW Evidence is always JSON serialized, as OCI specs are JSON
	s, err := ar.NewJsonSerializer()
	if err != nil {
		result.Summary.Fail(ar.Internal, err)
		return result, false
	}

	// Verify signature against the public key from the collateral. The collateral is
	// hashed and its digest is part of the hardware-evidence nonce, thus binding the
	// software evidence to the hardware evidence
	pub, err := internal.ParsePublicKey(collateral.Key)
	if err != nil {
		result.Summary.Fail(ar.VerifyEvidence, err)
		return result, false
	}
	tr, payload, ok := s.Verify(evidence.Data, pub)
	if !ok {
		log.Debugf("Failed to verify sw evidence")
		result.Summary.Fail(ar.VerifyEvidence)
		return result, false
	}
	result.Signature = tr.SignatureCheck[0]
	log.Debug("Successfully verified SW measurement signature")

	// Unmarshal evidence
	swEvidence := new(ar.SwEvidence)
	err = s.Unmarshal(payload, swEvidence)
	if err != nil {
		log.Debugf("Failed to unmarshal sw swEvidence")
		result.Summary.Fail(ar.ParseEvidence)
		return result, false
	}

	// Verify nonce
	result.Freshness = verifyNonce(swEvidence.Nonce, nonce)
	if result.Freshness.Status != ar.StatusSuccess {
		ok = false
	}

	// Check that reference values are reflected by mandatory measurements
	log.Debugf("Validating %v reference value(s) against measurements..", len(refComponents))

	for _, ref := range refComponents {
		found := false
		for _, swm := range collateral.Artifacts {
			for _, event := range swm.Events {
				if bytes.Equal(event.CtrData.RootfsSha256, ref.GetHash(crypto.SHA256)) {

					// Calculate the measurement template hash
					templateHash, ok, err := ValidateTemplateHash(s, &ref, event.CtrData)
					if err != nil {
						log.Errorf("Internal error: calculate template hash: %v", err)
						result.Summary.Fail(ar.Internal)
						ok = false
						continue
					}
					if !ok {
						log.Debugf("Rootfs matches but config validation failed. Continue search")
						continue
					}
					if bytes.Equal(event.GetHash(crypto.SHA256), templateHash) {
						found = true
						break
					}
				}
			}
			if found {
				break
			}
		}
		if !found {
			res := ar.DigestResult{
				Type:       ar.TYPE_REFVAL_IAS,
				Success:    ref.Optional, // Only fail attestation if component is mandatory
				Launched:   false,
				Name:       ref.Name,
				Digest:     ref.GetHash(crypto.SHA256),
				CtrDetails: ref.CtrData,
				PackageUrl: ref.PackageUrl,
				HashAlg:    crypto.SHA256.String(),
			}
			result.Artifacts = append(result.Artifacts, res)

			// Only fail attestation if component is mandatory
			if !ref.Optional {
				log.Debugf("no SW Measurement found for mandatory SW reference value %v (hash: %x)", ref.Name, ref.GetHash(crypto.SHA256))
				ok = false
			}
		}
	}
	log.Debugf("Finished validating reference values")

	// Check that every measurement is reflected by a reference value
	log.Debugf("Validating %v artifact(s)..", len(collateral.Artifacts))
	aggregatedHash := make([]byte, 32)
	for _, swm := range collateral.Artifacts {
		log.Debugf("Validating %v measurement(s)..", len(swm.Events))
		for _, event := range swm.Events {
			found := false
			for _, ref := range refComponents {
				if bytes.Equal(event.CtrData.RootfsSha256, ref.GetHash(crypto.SHA256)) {

					log.Tracef("Found matching rootfs hash %x", ref.GetHash(crypto.SHA256))

					// Calculate the measurement template hash
					templateHash, validateOk, err := ValidateTemplateHash(s, &ref, event.CtrData)
					if err != nil {
						log.Errorf("Internal error: validate template hash: %v", err)
						result.Summary.Fail(ar.Internal)
						ok = false
						continue
					}
					if !validateOk {
						log.Tracef("Rootfs matches but config validation failed. Continue search")
						continue
					}

					if !bytes.Equal(event.GetHash(crypto.SHA256), templateHash) {
						validateOk = false
						ok = false
						log.Debugf("Failed to match measured hash (%x) with reference template hash (%x)",
							event.GetHash(crypto.SHA256), templateHash)
					} else {
						log.Tracef("Calculated template hash matches measured hash: %x", templateHash)
					}

					found = true
					nameInfo := ref.Name
					if event.Name != "" && !strings.EqualFold(ref.Name, event.Name) {
						nameInfo += ": " + event.Name
					}
					r := ar.DigestResult{
						Success:    validateOk,
						Launched:   true,
						Name:       nameInfo,
						Digest:     event.GetHash(crypto.SHA256),
						CtrDetails: event.CtrData,
						PackageUrl: ref.PackageUrl,
						HashAlg:    crypto.SHA256.String(),
					}
					result.Artifacts = append(result.Artifacts, r)

					// Recalculate aggregated hash
					aggregatedHash = internal.ExtendSha256(aggregatedHash, templateHash)

					break
				}
			}
			if !found {
				r := ar.DigestResult{
					Type:       "Measurement",
					Success:    false,
					Launched:   true,
					Name:       event.Name,
					Digest:     event.GetHash(crypto.SHA256),
					CtrDetails: event.CtrData,
					PackageUrl: event.PackageUrl,
					HashAlg:    crypto.SHA256.String(),
				}
				result.Artifacts = append(result.Artifacts, r)
				log.Debugf("no SW reference value found for SW measurement: %v", hex.EncodeToString(event.GetHash(crypto.SHA256)))
				ok = false
			}
		}
	}
	log.Debugf("Finished validating artifacts")

	// Verify recalculated aggregated hash against swEvidence hash
	if !bytes.Equal(aggregatedHash, swEvidence.Sha256) {
		log.Debugf("Aggregated hash does not match evidence hash (%v vs %v)",
			hex.EncodeToString(aggregatedHash), hex.EncodeToString(swEvidence.Sha256))
		ok = false
		result.Summary.Fail(ar.VerifyAggregatedSwHash)
	} else {
		log.Debugf("Aggregated SW measurement hash matches evidence hash")
	}

	result.Summary.Status = ar.StatusFromBool(ok)

	log.Debugf("Finished verifying SW measurements. Success: %v", ok)

	return result, ok
}

func ValidateTemplateHash(s ar.Serializer, ref *ar.Component, measured *ar.CtrData) ([]byte, bool, error) {

	if ref == nil || ref.CtrData == nil {
		return nil, false, fmt.Errorf("internal error: container data or spec is nil")
	}
	spec := ref.CtrData.OciSpec

	// Hash manifest config
	refSpecHash, err := CalculateSpecHash(spec)
	if err != nil {
		return nil, false, fmt.Errorf("internal error: failed to calculate OCI config hash: %w", err)
	}

	// Compare with reference value
	if !bytes.Equal(measured.ConfigSha256, refSpecHash) {

		log.Tracef("Measured config hash (%x) does not match reference hash (%x). "+
			"Running rules-based validation", measured.ConfigSha256, refSpecHash)

		// If no match: perform rule-based validation
		refConvSpec, err := ConvertSpec(s, spec)
		if err != nil {
			return nil, false, fmt.Errorf("failed to convert reference spec: %w", err)
		}
		measConvSpec, err := ConvertSpec(s, measured.OciSpec)
		if err != nil {
			return nil, false, fmt.Errorf("failed to convert measurement spec: %w", err)
		}

		// TODO load rules
		err = ValidateConfig(refConvSpec, measConvSpec, map[string]interface{}{})
		if err != nil {
			log.Debugf("Failed to validate OCI config: %v", err)
			return nil, false, nil
		}

		log.Tracef("Rules-base validation successful")

		// use measured hash, as rule-based config validation was successful
		refSpecHash = measured.ConfigSha256
	} else {
		log.Tracef("Measured config hash matches reference hash: %x", refSpecHash)
	}

	log.Tracef("Using config hash %x to recalculate template hash", refSpecHash)

	// Recalculate template hash
	tbh := append(refSpecHash, ref.GetHash(crypto.SHA256)...)
	hasher := sha256.New()
	hasher.Write(tbh)
	templateHash := hasher.Sum(nil)

	return templateHash, true, nil
}

func CalculateSpecHash(spec *specs.Spec) ([]byte, error) {

	data, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	// Transform to RFC 8785 canonical JSON form for reproducible hashing
	tbh, err := jcs.Transform(data)
	if err != nil {
		return nil, fmt.Errorf("failed to cannonicalize json: %w", err)
	}

	hash := sha256.Sum256(tbh)

	return hash[:], nil
}
