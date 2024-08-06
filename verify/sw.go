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

package verify

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
	tr, evidenceNonce, ok := s.VerifyToken(swMeasurement.Evidence, cas)
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
	for _, v := range refVals {
		found := false
		for _, swm := range swMeasurement.Artifacts {
			for _, event := range swm.Events {
				if bytes.Equal(event.Sha256, v.Sha256) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found && !v.Optional {
			log.Tracef("no SW Measurement found for SW Reference Value %v (hash: %v)", v.Name, hex.EncodeToString(v.Sha256))
			r := ar.DigestResult{
				Type:    "Reference Value",
				Success: false,
				Name:    v.Name,
				Digest:  hex.EncodeToString(v.Sha256),
			}
			result.Artifacts = append(result.Artifacts, r)
			ok = false
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
						Success: true,
						Name:    nameInfo,
						Digest:  hex.EncodeToString(event.Sha256),
					}
					result.Artifacts = append(result.Artifacts, r)
					break
				}
			}
			if !found {
				r := ar.DigestResult{
					Type:    "Measurement",
					Success: false,
					Name:    event.EventName,
					Digest:  hex.EncodeToString(event.Sha256),
				}
				result.Artifacts = append(result.Artifacts, r)
				log.Tracef("no SW Reference Value found for SW Measurement: %v", hex.EncodeToString(event.Sha256))
				ok = false
			}
		}
	}

	result.Summary.Success = ok

	return result, ok
}
