// Copyright (c) 2021 - 2024 Fraunhofer AISEC
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
	"encoding/json"
	"fmt"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	jcs "github.com/Fraunhofer-AISEC/cmc/jsoncanonicalizer"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func verifySwMeasurements(swMeasurement ar.Measurement, nonce []byte, cas []*x509.Certificate,
	s ar.Serializer, refVals []ar.ReferenceValue) (*ar.MeasurementResult, bool,
) {

	log.Debug("Verifying SW measurements")

	result := &ar.MeasurementResult{
		Type: "SW Result",
	}
	ok := true

	// Verify signature and extract evidence
	tr, payload, ok := s.Verify(swMeasurement.Evidence, cas)
	if !ok {
		log.Debugf("Failed to verify sw evidence")
		result.Summary.SetErr(ar.VerifyEvidence)
		return result, false
	}
	result.Signature = tr.SignatureCheck[0]
	log.Debug("Successfully verified SW measurement signature")

	// Unmarshal evidence
	evidence := new(ar.SwEvidence)
	err := s.Unmarshal(payload, evidence)
	if err != nil {
		log.Debugf("Failed to unmarshal sw evidence")
		result.Summary.SetErr(ar.ParseEvidence)
	}

	// Verify nonce
	if !bytes.Equal(evidence.Nonce, nonce) {
		log.Debugf("Nonces mismatch: supplied nonce: %v, report nonce = %v",
			hex.EncodeToString(nonce), hex.EncodeToString(evidence.Nonce))
		ok = false
		result.Freshness.Success = false
		result.Freshness.Expected = hex.EncodeToString(evidence.Nonce)
		result.Freshness.Got = hex.EncodeToString(nonce)
	} else {
		result.Freshness.Success = true
		log.Debugf("Successfully verified nonce %v", hex.EncodeToString(nonce))
	}

	// Check that reference values are reflected by mandatory measurements
	for _, ref := range refVals {
		found := false
		for _, swm := range swMeasurement.Artifacts {
			for _, event := range swm.Events {
				if bytes.Equal(event.CtrData.RootfsSha256, ref.Sha256) {

					// Calculate the measurement template hash
					templateHash, ok, err := CalculateTemplateHash(&ref, event.CtrData.ConfigSha256)
					if err != nil {
						log.Errorf("Internal error: calculate template hash: %v", err)
						result.Summary.SetErr(ar.Internal)
						ok = false
						continue
					}
					if !ok {
						log.Debugf("Rootfs matches but config does not. Detailed comparison not yet implemented")
						continue
					}
					if bytes.Equal(event.Sha256, templateHash) {
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
				Type:       "Reference Value",
				Success:    ref.Optional, // Only fail attestation if component is mandatory
				Launched:   false,
				Name:       ref.Name,
				Digest:     hex.EncodeToString(ref.Sha256),
				CtrDetails: ar.GetCtrDetailsFromRefVal(&ref, s),
			}
			result.Artifacts = append(result.Artifacts, res)

			// Only fail attestation if component is mandatory
			if !ref.Optional {
				log.Debugf("no SW Measurement found for mandatory SW reference value %v (hash: %v)", ref.Name, hex.EncodeToString(ref.Sha256))
				ok = false
			}
		}
	}

	// Check that every measurement is reflected by a reference value
	aggregatedHash := make([]byte, 32)
	for _, swm := range swMeasurement.Artifacts {
		for _, event := range swm.Events {
			found := false
			for _, ref := range refVals {
				if bytes.Equal(event.CtrData.RootfsSha256, ref.Sha256) {

					// Calculate the measurement template hash
					templateHash, ok, err := CalculateTemplateHash(&ref, event.CtrData.ConfigSha256)
					if err != nil {
						log.Errorf("Internal error: calculate template hash: %v", err)
						result.Summary.SetErr(ar.Internal)
						ok = false
						continue
					}
					if !ok {
						log.Debugf("Rootfs matches but config does not. Detailed comparison not yet implemented")
						continue
					}

					if !bytes.Equal(event.Sha256, templateHash) {
						// No need to set error, as aggregated hash will fail
						log.Debugf("Failed to match template hash")
					} else {
						log.Debugf("Calculated template hash matches measured hash: %v", hex.EncodeToString(templateHash))
					}

					found = true
					nameInfo := ref.Name
					if event.EventName != "" && !strings.EqualFold(ref.Name, event.EventName) {
						nameInfo += ": " + event.EventName
					}
					r := ar.DigestResult{
						Success:    true,
						Launched:   true,
						Name:       nameInfo,
						Digest:     hex.EncodeToString(event.Sha256),
						CtrDetails: event.CtrData,
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
					Name:       event.EventName,
					Digest:     hex.EncodeToString(event.Sha256),
					CtrDetails: event.CtrData,
				}
				result.Artifacts = append(result.Artifacts, r)
				log.Debugf("no SW reference value found for SW measurement: %v", hex.EncodeToString(event.Sha256))
				ok = false
			}
		}
	}

	// Verify recalculated aggregated hash against evidence hash
	if !bytes.Equal(aggregatedHash, evidence.Sha256) {
		log.Debugf("Aggregated hash does not match evidence hash (%v vs %v)",
			hex.EncodeToString(aggregatedHash), hex.EncodeToString(evidence.Sha256))
		ok = false
		result.Summary.SetErr(ar.VerifyAggregatedSwHash)
	} else {
		log.Debugf("Aggregated SW measurement hash matches evidence hash")
	}

	result.Summary.Success = ok

	log.Debugf("Finished verifying SW measurements. Success: %v", ok)

	return result, ok
}

func CalculateTemplateHash(ref *ar.ReferenceValue, measuredHash []byte) ([]byte, bool, error) {

	// Fetch manifest config
	m, err := ref.GetManifest()
	if err != nil {
		return nil, false, fmt.Errorf("internal error: failed to get manifest: %w", err)
	}

	// Hash manifest config
	specHash, err := CalculateSpecHash(m.OciSpec)
	if err != nil {
		return nil, false, fmt.Errorf("internal error: failed to calculate OCI config hash: %w", err)
	}

	// Compare with reference value
	if !bytes.Equal(measuredHash, specHash) {
		// TODO If no match: compare configs value by value
		return nil, false, nil
	}

	// Recalculate template hash
	tbh := []byte(specHash)
	tbh = append(tbh, ref.Sha256...)
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
