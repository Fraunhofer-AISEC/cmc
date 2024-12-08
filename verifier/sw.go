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

package verifier

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

func verifySwMeasurements(swMeasurement ar.Measurement, nonce []byte, cas []*x509.Certificate,
	s ar.Serializer, refVals []ar.ReferenceValue) (*ar.MeasurementResult, bool,
) {

	log.Trace("Verifying SW measurements")

	result := &ar.MeasurementResult{
		Type: "SW Result",
	}
	ok := true

	// Verify signature and extract evidence, which is just the nonce for the sw driver
	tr, evidenceNonce, ok := s.Verify(swMeasurement.Evidence, cas)
	if !ok {
		log.Tracef("Failed to verify sw evidence")
		result.Summary.SetErr(ar.ParseEvidence)
		return result, false
	}
	result.Signature = tr.SignatureCheck[0]

	// Verify nonce
	if res := bytes.Compare(evidenceNonce, nonce); res != 0 {
		log.Tracef("Nonces mismatch: supplied nonce: %v, report nonce = %v",
			hex.EncodeToString(nonce), hex.EncodeToString(evidenceNonce))
		ok = false
		result.Freshness.Success = false
		result.Freshness.Expected = hex.EncodeToString(evidenceNonce)
		result.Freshness.Got = hex.EncodeToString(nonce)
	} else {
		result.Freshness.Success = true
	}

	// Check that reference values are reflected by mandatory measurements
	for _, r := range refVals {
		found := false
		for _, swm := range swMeasurement.Artifacts {
			for _, event := range swm.Events {
				if bytes.Equal(event.Sha256, r.Sha256) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			res := ar.DigestResult{
				Type:       "Reference Value",
				Success:    r.Optional, // Only fail attestation if component is mandatory
				Launched:   false,
				Name:       r.Name,
				Digest:     hex.EncodeToString(r.Sha256),
				CtrDetails: ar.GetCtrDetailsFromRefVal(&r, s),
			}
			result.Artifacts = append(result.Artifacts, res)

			// Only fail attestation if component is mandatory
			if !r.Optional {
				log.Tracef("no SW Measurement found for mandatory SW reference value %v (hash: %v)", r.Name, hex.EncodeToString(r.Sha256))
				ok = false
			}
		}
	}

	// Check that every measurement is reflected by a reference value
	for _, swm := range swMeasurement.Artifacts {
		for _, event := range swm.Events {
			found := false
			for _, ref := range refVals {
				if bytes.Equal(event.Sha256, ref.Sha256) {
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
						CtrDetails: ar.GetCtrDetailsFromMeasureEvent(&event, s),
					}
					result.Artifacts = append(result.Artifacts, r)
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
					CtrDetails: ar.GetCtrDetailsFromMeasureEvent(&event, s),
				}
				result.Artifacts = append(result.Artifacts, r)
				log.Tracef("no SW reference value found for SW measurement: %v", hex.EncodeToString(event.Sha256))
				ok = false
			}
		}
	}

	result.Summary.Success = ok

	log.Tracef("Finished verifying SW measurements. Success: %v", ok)

	return result, ok
}
