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

package verifier

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// VerifySwima verifies a standalone software-signed IMA measurement list. The evidence is a
// JSON-serialized SwEvidence signed with the IMA driver's AK
func VerifySwima(
	evidence ar.Evidence,
	collateral ar.Collateral,
	nonce []byte,
	refComponents []ar.Component,
) (*ar.MeasurementResult, bool) {

	log.Debug("Verifying IMA measurements")

	result := &ar.MeasurementResult{
		Type: "IMA Result",
	}
	ok := true

	s, err := ar.NewJsonSerializer()
	if err != nil {
		result.Summary.Fail(ar.Internal, err)
		return result, false
	}

	pub, err := internal.ParsePublicKey(collateral.Key)
	if err != nil {
		result.Summary.Fail(ar.VerifyEvidence, err)
		return result, false
	}
	tr, payload, ok := s.Verify(evidence.Data, pub)
	if !ok {
		log.Warnf("Failed to verify ima evidence")
		result.Summary.Fail(ar.VerifyEvidence)
		return result, false
	}
	result.Signature = tr.SignatureCheck[0]
	log.Debug("Successfully verified IMA measurement signature")

	imaEvidence := new(ar.SwEvidence)
	if err := s.Unmarshal(payload, imaEvidence); err != nil {
		log.Warnf("Failed to unmarshal ima evidence")
		result.Summary.Fail(ar.ParseEvidence)
		return result, false
	}

	result.Freshness = verifyNonce(imaEvidence.Nonce, nonce)
	if result.Freshness.Status != ar.StatusSuccess {
		ok = false
	}

	// Match the reference values against the measured events, order-insensitive
	log.Debugf("Validating %v reference value(s) against measurements..", len(refComponents))
	for _, ref := range refComponents {
		refHash := ref.GetHash(crypto.SHA256)
		refIdx, err := ref.GetIndex()
		if err != nil {
			log.Warnf("reference value %v missing index: %v", ref.Name, err)
			result.Summary.Fail(ar.Internal, err)
			ok = false
			continue
		}
		found := false
		for _, art := range collateral.Artifacts {
			for _, event := range art.Events {
				if art.Index == refIdx && bytes.Equal(event.GetHash(crypto.SHA256), refHash) {
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
				Type:    ar.TRUST_ANCHOR_SWIMA,
				Success: ref.Optional,
				Name:    ref.Name,
				Index:   refIdx,
				Digest:  refHash,
				HashAlg: crypto.SHA256.String(),
			}
			result.Artifacts = append(result.Artifacts, res)
			if !ref.Optional {
				log.Warnf("no IMA measurement found for mandatory reference value %v (hash: %x)", ref.Name, refHash)
				ok = false
			}
		}
	}

	// Every measurement must be reflected by a reference value and the aggregated hash chain over
	// the template hashes must match the signed evidence
	log.Debugf("Validating %v artifact(s)..", len(collateral.Artifacts))
	aggregatedHash := make([]byte, 32)
	for _, art := range collateral.Artifacts {
		log.Debugf("Validating %v measurement(s) at index %v", len(art.Events), art.Index)
		for _, event := range art.Events {
			eventHash := event.GetHash(crypto.SHA256)
			found := false
			for _, ref := range refComponents {
				refIdx, err := ref.GetIndex()
				if err != nil {
					continue
				}
				if refIdx == art.Index && bytes.Equal(ref.GetHash(crypto.SHA256), eventHash) {
					found = true
					r := ar.DigestResult{
						Type:     "Verified",
						Name:     ref.Name,
						Success:  true,
						Launched: true,
						Index:    art.Index,
						Digest:   eventHash,
						HashAlg:  crypto.SHA256.String(),
					}
					result.Artifacts = append(result.Artifacts, r)
					break
				}
			}
			if !found {
				r := ar.DigestResult{
					Type:     "Measurement",
					Success:  false,
					Launched: true,
					Name:     event.Name,
					Index:    art.Index,
					Digest:   eventHash,
					HashAlg:  crypto.SHA256.String(),
				}
				result.Artifacts = append(result.Artifacts, r)
				log.Warnf("no IMA reference value found for measurement: %v", hex.EncodeToString(eventHash))
				ok = false
			}
			aggregatedHash = internal.ExtendSha256(aggregatedHash, eventHash)
		}
	}

	if !bytes.Equal(aggregatedHash, imaEvidence.Sha256) {
		log.Warnf("Aggregated IMA hash does not match evidence hash (%v vs %v)",
			hex.EncodeToString(aggregatedHash), hex.EncodeToString(imaEvidence.Sha256))
		ok = false
		result.Summary.Fail(ar.VerifyAggregatedSwHash,
			fmt.Errorf("aggregated hash %x does not match evidence %x", aggregatedHash, imaEvidence.Sha256))
	} else {
		log.Debugf("Aggregated IMA measurement hash matches evidence hash")
	}

	result.Summary.Status = ar.StatusFromBool(ok)

	log.Debugf("Finished verifying IMA measurements. Success: %v", ok)

	return result, ok
}
