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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/google/go-tpm/legacy/tpm2"
)

func verifyTpmMeasurements(
	measurement ar.Measurement,
	nonce []byte,
	cas []*x509.Certificate,
	referenceValues []ar.ReferenceValue,
	s ar.Serializer,
) (*ar.MeasurementResult, bool) {

	result := &ar.MeasurementResult{
		Type: "TPM Result",
		Summary: ar.Result{
			Status: ar.StatusSuccess,
		},
		TpmResult: &ar.TpmResult{},
	}

	log.Debug("Verifying TPM measurements...")

	// Extract TPM Quote (TPMS ATTEST) and signature
	tpmsAttest, err := tpm2.DecodeAttestationData(measurement.Evidence)
	if err != nil {
		log.Debugf("Failed to decode TPM attestation data: %v", err)
		result.Summary.Fail(ar.ParseEvidence)
		return result, false
	}

	// Verify nonce with nonce from TPM Quote
	if bytes.Equal(nonce, tpmsAttest.ExtraData) {
		result.Freshness.Status = ar.StatusSuccess
		result.Freshness.Got = hex.EncodeToString(nonce)
		log.Debugf("Successfully verified nonce %v", hex.EncodeToString(nonce))
	} else {
		log.Debugf("Nonces mismatch: Supplied Nonce = %v, TPM Quote Nonce = %v)",
			hex.EncodeToString(nonce), hex.EncodeToString(tpmsAttest.ExtraData))
		result.Summary.Status = ar.StatusFail
		result.Freshness.Status = ar.StatusFail
		result.Freshness.Expected = hex.EncodeToString(nonce)
		result.Freshness.Got = hex.EncodeToString(tpmsAttest.ExtraData)
	}

	// Extend the reference values to re-calculate the PCR value and evaluate it against the measured
	// PCR value. In case of a measurement list, also extend the measured values to re-calculate
	// the measured PCR value
	tpmResult, artifacts, ok := verifyPcrs(s, measurement, tpmsAttest.AttestedQuoteInfo.PCRDigest,
		referenceValues)
	if !ok {
		log.Debug("failed to recalculate PCRs")
		result.Summary.Status = ar.StatusFail
	}
	result.TpmResult = tpmResult
	result.Artifacts = artifacts

	mCerts, err := internal.ParseCertsDer(measurement.Certs)
	if err != nil {
		log.Debugf("Failed to parse measurement certs: %v", err)
		result.Signature.CertChainCheck.Fail(ar.ParseCert)
		result.Summary.Status = ar.StatusFail
		return result, false
	}

	result.Signature.SignCheck = VerifyTpmQuoteSignature(measurement.Evidence, measurement.Signature, mCerts[0])
	if result.Signature.SignCheck.Status != ar.StatusSuccess {
		result.Summary.Status = ar.StatusFail
	}

	x509Chains, err := internal.VerifyCertChain(mCerts, cas)
	if err != nil {
		log.Debugf("Failed to verify TPM quote certificate chain: %v", err)
		result.Summary.Status = ar.StatusFail
		result.Signature.CertChainCheck.Fail(ar.VerifyCertChain)
	} else {
		result.Signature.CertChainCheck.Status = ar.StatusSuccess
	}
	log.Debug("Successfully verified TPM certificate chain")

	//Store details from (all) validated certificate chain(s) in the report
	for _, chain := range x509Chains {
		chainExtracted := []ar.X509CertExtracted{}
		for _, cert := range chain {
			chainExtracted = append(chainExtracted, ar.ExtractX509Infos(cert))
		}
		result.Signature.Certs = append(result.Signature.Certs, chainExtracted)
	}

	if result.Summary.Status == ar.StatusSuccess {
		log.Debugf("Successfully verified TPM measurements")
	} else {
		log.Debugf("Failed to verify TPM measurements")
	}

	return result, result.Summary.Status == ar.StatusSuccess
}

func verifyPcrs(s ar.Serializer, measurement ar.Measurement,
	aggregatedQuotePcr []byte, referenceValues []ar.ReferenceValue,
) (*ar.TpmResult, []ar.DigestResult, bool) {
	success := true
	pcrResults := make([]ar.DigestResult, 0)
	detailedResults := make([]ar.DigestResult, 0)
	calculatedPcrs := make(map[int][]byte)

	// Iterate over the provided measurement
	log.Debugf("Recalculating PCRs with %v measurement artifacts...", len(measurement.Artifacts))
	for _, measuredPcr := range measurement.Artifacts {

		pcrResult := ar.DigestResult{
			Index:   measuredPcr.Index,
			Success: true,
		}

		pcr := measuredPcr.Index

		// Initialize calculated PCR if not yet initialized, afterwards extend
		// reference values
		if _, ok := calculatedPcrs[pcr]; !ok {
			calculatedPcrs[pcr] = make([]byte, 32)
		}

		if measuredPcr.Type == ar.ARTIFACT_TYPE_PCR_EVENTLOG {
			// measurement contains a detailed measurement list (e.g. retrieved from bios
			// measurement logs or ima runtime measurement logs)
			measuredSummary := make([]byte, 32)
			for _, event := range measuredPcr.Events {
				//first event could be a TPM_PCR_INIT_VALUE ()
				if event.EventName == "TPM_PCR_INIT_VALUE" {
					calculatedPcrs[pcr] = event.Sha256
					measuredSummary = event.Sha256
					continue
				}

				// Extend measurement summary unconditionally...
				measuredSummary = internal.ExtendSha256(measuredSummary, event.Sha256)

				// Check for every event that a corresponding reference value exists
				ref := getReferenceValue(event.Sha256, pcr, referenceValues)
				if ref == nil {
					measResult := ar.DigestResult{
						Type:        "Measurement",
						Index:       pcr,
						Digest:      hex.EncodeToString(event.Sha256),
						Success:     false,
						Launched:    true,
						SubType:     event.EventName,
						EventData:   event.EventData,
						CtrDetails:  event.CtrData,
						Description: event.Description,
					}
					detailedResults = append(detailedResults, measResult)
					log.Debugf("Failed to find PCR%v measurement %v: %v in reference values",
						measuredPcr.Index, event.EventName, hex.EncodeToString(event.Sha256))
					success = false
					pcrResult.Success = false
					continue
				}

				// ...Extent calculated summary only if reference value was found
				calculatedPcrs[pcr] = internal.ExtendSha256(calculatedPcrs[pcr],
					event.Sha256)

				nameInfo := ref.SubType
				if event.EventName != "" && !strings.EqualFold(ref.SubType, event.EventName) {
					nameInfo += ": " + event.EventName
				}

				measResult := ar.DigestResult{
					Type:        "Verified",
					Index:       pcr,
					Digest:      hex.EncodeToString(event.Sha256),
					Success:     true,
					Launched:    true,
					SubType:     nameInfo,
					Description: ref.Description,
					CtrDetails:  event.CtrData,
				}
				detailedResults = append(detailedResults, measResult)

				log.Tracef("Found refval for PCR%v measurement %v: %v",
					pcr, nameInfo, hex.EncodeToString(event.Sha256))
			}
			pcrResult.Digest = hex.EncodeToString(calculatedPcrs[pcr])
			if !bytes.Equal(measuredSummary, calculatedPcrs[pcr]) {
				pcrResult.Measured = hex.EncodeToString(measuredSummary)
			}

		} else if measuredPcr.Type == ar.ARTIFACT_TYPE_PCR_SUMMARY {
			// measurement contains just the summary PCR value
			// We therefore unconditionally extend every reference value for this PCR
			if len(measuredPcr.Events) != 1 {
				log.Debugf("Expected exactly one event for artifact type %q, got %v",
					ar.ARTIFACT_TYPE_PCR_SUMMARY, len(measuredPcr.Events))
				success = false
				continue
			}
			for _, ref := range referenceValues {
				if ref.Index == pcr {
					if ref.SubType == "TPM_PCR_INIT_VALUE" {
						calculatedPcrs[pcr] = ref.Sha256 //the Sha256 should contain the init value
						continue                         //break the loop iteration and continue with the next event
					}
					calculatedPcrs[pcr] = internal.ExtendSha256(calculatedPcrs[pcr], ref.Sha256)

					// As we only have the PCR summary, we will later set all reference values
					// to true/false depending on whether the calculation matches the PCR summary
					measResult := ar.DigestResult{
						Index:       pcr,
						Digest:      hex.EncodeToString(ref.Sha256),
						SubType:     ref.SubType,
						Description: ref.Description,
					}
					detailedResults = append(detailedResults, measResult)
				}

			}
			// Then we compare the calculated value with the PCR measurement summary
			equal := bytes.Equal(calculatedPcrs[pcr], measuredPcr.Events[0].Sha256)
			if equal {
				pcrResult.Digest = hex.EncodeToString(calculatedPcrs[pcr])
				pcrResult.Success = true
			} else {
				log.Debugf("PCR%v mismatch: measured: %v, calculated: %v", pcr,
					hex.EncodeToString(measuredPcr.Events[0].Sha256),
					hex.EncodeToString(calculatedPcrs[pcr]))
				pcrResult.Digest = hex.EncodeToString(calculatedPcrs[pcr])
				pcrResult.Measured = hex.EncodeToString(measuredPcr.Events[0].Sha256)
				pcrResult.Success = false
				success = false
			}
			// If the measurement only contains the final PCR value, set all reference values
			// for this PCR to the according value, as we cannot determine which ones
			// were good or potentially failed
			for i, elem := range detailedResults {
				if elem.Index == pcr && measuredPcr.Type != ar.ARTIFACT_TYPE_PCR_EVENTLOG {
					detailedResults[i].Success = equal
					detailedResults[i].Launched = equal
				}
			}

		} else {
			success = false
			pcrResult.Success = false
			log.Debugf("Unknown measurement PCR type %v", measuredPcr.Type)
		}

		pcrResults = append(pcrResults, pcrResult)

	}

	// Sort the results in ascending order
	sort.Slice(pcrResults, func(i, j int) bool {
		return pcrResults[i].Index < pcrResults[j].Index
	})

	// Finally, iterate over the reference values to find reference values with no
	// matching PCR or required reference values which are not present in the measurement
	// in case of detailed measurement logs
	for _, ref := range referenceValues {

		// Check if measurement contains the reference value PCR
		foundPcr := false
		for _, measuredPcr := range measurement.Artifacts {

			if measuredPcr.Index == ref.Index {
				foundPcr = true
			} else {
				continue
			}

			// Check if the reference value is present (only possible if detailed
			// measurement logs were provided. In case of summary, every reference value is
			// extended expected)
			if measuredPcr.Type != ar.ARTIFACT_TYPE_PCR_SUMMARY {
				foundEvent := false
				for _, event := range measuredPcr.Events {
					if bytes.Equal(event.Sha256, ref.Sha256) {
						foundEvent = true
					}
				}
				if !foundEvent {
					result := ar.DigestResult{
						Type:        "Reference Value",
						SubType:     ref.SubType,
						Index:       ref.Index,
						Success:     ref.Optional, // Only fail attestation if component is mandatory
						Launched:    false,
						Digest:      hex.EncodeToString(ref.Sha256),
						Description: ref.Description,
						CtrDetails:  ar.GetCtrDetailsFromRefVal(&ref, s),
						EventData:   ref.EventData,
					}
					if !ref.Optional {
						detailedResults = append(detailedResults, result)
						success = false
						log.Debugf("Failed to find required PCR%v reference value %v: %v in measurements",
							ref.Index, ref.SubType, hex.EncodeToString(ref.Sha256))
					}
					continue
				}
			}
		}
		if !foundPcr {
			log.Debugf("Failed to find required PCR%v reference value %v: %v in measurements",
				ref.Index, ref.SubType, hex.EncodeToString(ref.Sha256))
			result := ar.DigestResult{
				Type:        "Reference Value",
				SubType:     ref.SubType,
				Index:       ref.Index,
				Success:     ref.Optional,
				Launched:    false,
				Digest:      hex.EncodeToString(ref.Sha256),
				Description: ref.Description,
			}
			detailedResults = append(detailedResults, result)
			success = false
			continue
		}
	}

	// Calculate aggregated quote PCR: Hash all reference values together
	sum := make([]byte, 0)
	for i := range measurement.Artifacts {
		pcr := measurement.Artifacts[i].Index
		_, ok := calculatedPcrs[pcr]
		if !ok {
			continue
		}
		sum = append(sum, calculatedPcrs[pcr]...)
	}
	verPcr := sha256.Sum256(sum)

	// Verify calculated aggregated PCR value against quote PCR value
	aggPcrQuoteMatch := ar.Result{}
	if bytes.Equal(verPcr[:], aggregatedQuotePcr) {
		log.Debug("Aggregated PCR matches quote PCR")
		aggPcrQuoteMatch.Status = ar.StatusSuccess
	} else {
		log.Debugf("Aggregated PCR does not match Quote PCR: %v vs. %v",
			hex.EncodeToString(verPcr[:]),
			hex.EncodeToString(aggregatedQuotePcr))
		aggPcrQuoteMatch.Status = ar.StatusFail
		aggPcrQuoteMatch.Expected = hex.EncodeToString(verPcr[:])
		aggPcrQuoteMatch.Got = hex.EncodeToString(aggregatedQuotePcr)
		success = false
	}

	tpmResult := &ar.TpmResult{
		PcrMatch:         pcrResults,
		AggPcrQuoteMatch: aggPcrQuoteMatch,
	}

	return tpmResult, detailedResults, success
}

func VerifyTpmQuoteSignature(quote, sig []byte, cert *x509.Certificate) ar.Result {

	log.Debugf("Verifying TPM quote (length %v) signature (length %v) against certificate %v...",
		len(quote), len(sig), cert.Subject.CommonName)

	buf := new(bytes.Buffer)
	buf.Write((sig))
	tpmtSig, err := tpm2.DecodeSignature(buf)
	if err != nil {
		result := ar.Result{}
		result.Fail(ar.Parse, fmt.Errorf("failed to decode quote signature: %w", err))
		return result
	}

	if tpmtSig.Alg != tpm2.AlgRSASSA {
		result := ar.Result{}
		result.Fail(ar.UnsupportedAlgorithm, fmt.Errorf("hash algorithm %v not supported", tpmtSig.Alg))
		return result
	}

	// Extract public key from x509 certificate
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		result := ar.Result{}
		result.Fail(ar.ExtractPubKey, fmt.Errorf("failed to extract public key from certificate"))
		return result
	}
	hashAlg, err := tpmtSig.RSA.HashAlg.Hash()
	if err != nil {
		result := ar.Result{}
		result.Fail(ar.UnsupportedAlgorithm, fmt.Errorf("hash algorithm not supported"))
		return result
	}

	// Hash the quote and Verify the TPM Quote signature
	hashed := sha256.Sum256(quote)
	err = rsa.VerifyPKCS1v15(pubKey, hashAlg, hashed[:], tpmtSig.RSA.Signature)
	if err != nil {
		result := ar.Result{}
		result.Fail(ar.VerifySignature, err)
		return result
	}

	log.Debugf("Successfully verified TPM quote signature")

	return ar.Result{Status: ar.StatusSuccess}
}

// Searches for a specific hash value in the reference values for RTM and OS
func getReferenceValue(hash []byte, pcr int, refVals []ar.ReferenceValue) *ar.ReferenceValue {
	for _, ref := range refVals {
		if ref.Index == pcr && bytes.Equal(ref.Sha256, hash) {
			return &ref
		}
	}
	return nil
}
