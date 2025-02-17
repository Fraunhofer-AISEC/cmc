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
	"sort"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/google/go-tpm/legacy/tpm2"
)

func verifyTpmMeasurements(
	tpmM ar.Measurement,
	nonce []byte,
	cas []*x509.Certificate,
	s ar.Serializer,
	referenceValues []ar.ReferenceValue,
) (*ar.MeasurementResult, bool) {

	result := &ar.MeasurementResult{
		Type:      "TPM Result",
		TpmResult: &ar.TpmResult{},
	}

	log.Debug("Verifying TPM measurements")

	// Extend the reference values to re-calculate the PCR value and evaluate it against the measured
	// PCR value. In case of a measurement list, also extend the measured values to re-calculate
	// the measured PCR value
	calculatedPcrs, pcrResult, artifacts, ok := recalculatePcrs(s, tpmM, referenceValues)
	if !ok {
		log.Debug("failed to recalculate PCRs")
	}
	result.TpmResult.PcrMatch = pcrResult
	result.Artifacts = artifacts

	// Extract TPM Quote (TPMS ATTEST) and signature
	tpmsAttest, err := tpm2.DecodeAttestationData(tpmM.Evidence)
	if err != nil {
		log.Debugf("Failed to decode TPM attestation data: %v", err)
		result.Summary.SetErr(ar.ParseEvidence)
		return result, false
	}

	// Verify nonce with nonce from TPM Quote
	if bytes.Equal(nonce, tpmsAttest.ExtraData) {
		result.Freshness.Success = true
		log.Debugf("Successfully verified nonce %v", hex.EncodeToString(nonce))
	} else {
		log.Debugf("Nonces mismatch: Supplied Nonce = %v, TPM Quote Nonce = %v)",
			hex.EncodeToString(nonce), hex.EncodeToString(tpmsAttest.ExtraData))
		result.Freshness.Success = false
		result.Freshness.Expected = hex.EncodeToString(nonce)
		result.Freshness.Got = hex.EncodeToString(tpmsAttest.ExtraData)
		ok = false
	}

	// Verify aggregated PCR against TPM Quote PCRDigest: Hash all reference values
	// together then compare
	sum := make([]byte, 0)
	for i := range tpmM.Artifacts {
		if tpmM.Artifacts[i].Pcr == nil {
			log.Debugf("PCR not specified")
			result.Summary.SetErr(ar.PcrNotSpecified)
			return result, false
		}
		pcr := *tpmM.Artifacts[i].Pcr
		_, ok := calculatedPcrs[pcr]
		if !ok {
			continue
		}
		sum = append(sum, calculatedPcrs[pcr]...)
	}
	verPcr := sha256.Sum256(sum)
	if bytes.Equal(verPcr[:], tpmsAttest.AttestedQuoteInfo.PCRDigest) {
		log.Debug("Aggregated PCR matches quote PCR")
		result.TpmResult.AggPcrQuoteMatch.Success = true
	} else {
		log.Debugf("Aggregated PCR does not match Quote PCR: %v vs. %v",
			hex.EncodeToString(verPcr[:]),
			hex.EncodeToString(tpmsAttest.AttestedQuoteInfo.PCRDigest))
		result.TpmResult.AggPcrQuoteMatch.Success = false
		result.TpmResult.AggPcrQuoteMatch.Expected = hex.EncodeToString(verPcr[:])
		result.TpmResult.AggPcrQuoteMatch.Got = hex.EncodeToString(tpmsAttest.AttestedQuoteInfo.PCRDigest)
		ok = false
	}

	mCerts, err := internal.ParseCertsDer(tpmM.Certs)
	if err != nil {
		log.Debugf("Failed to parse measurement certs: %v", err)
		result.Signature.CertChainCheck.SetErr(ar.ParseCert)
		result.Summary.Success = false
		return result, false
	}

	result.Signature.SignCheck = verifyTpmQuoteSignature(tpmM.Evidence, tpmM.Signature, mCerts[0])
	if !result.Signature.SignCheck.Success {
		ok = false
	}
	log.Debug("Successfully verified TPM quote signature")

	x509Chains, err := internal.VerifyCertChain(mCerts, cas)
	if err != nil {
		log.Debugf("Failed to verify certificate chain: %v", err)
		result.Signature.CertChainCheck.SetErr(ar.VerifyCertChain)
		ok = false
	} else {
		result.Signature.CertChainCheck.Success = true
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

	result.Summary.Success = ok

	return result, ok
}

func recalculatePcrs(s ar.Serializer, measurement ar.Measurement, referenceValues []ar.ReferenceValue,
) (map[int][]byte, []ar.PcrResult, []ar.DigestResult, bool) {
	ok := true
	pcrResults := make([]ar.PcrResult, 0)
	detailedResults := make([]ar.DigestResult, 0)
	calculatedPcrs := make(map[int][]byte)

	// Iterate over the provided measurement
	for _, measuredPcr := range measurement.Artifacts {

		pcrResult := ar.PcrResult{
			Pcr:     *measuredPcr.Pcr,
			Success: true,
		}

		if measuredPcr.Pcr == nil {
			log.Debug("PCR not specified")
			ok = false
			pcrResult.Success = false
			continue
		}
		pcr := *measuredPcr.Pcr

		// Initialize calculated PCR if not yet initialized, afterwards extend
		// reference values
		if _, ok := calculatedPcrs[pcr]; !ok {
			calculatedPcrs[pcr] = make([]byte, 32)
		}

		if measuredPcr.Type == "PCR Eventlog" {
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
						Type:       "Measurement",
						Pcr:        &pcr,
						Digest:     hex.EncodeToString(event.Sha256),
						Success:    false,
						Launched:   true,
						Name:       event.EventName,
						EventData:  event.EventData,
						CtrDetails: event.CtrData,
					}
					detailedResults = append(detailedResults, measResult)
					log.Debugf("Failed to find PCR%v measurement %v: %v in reference values",
						*measuredPcr.Pcr, event.EventName, hex.EncodeToString(event.Sha256))
					ok = false
					pcrResult.Success = false
					continue
				}

				// ...Extent calculated summary only if reference value was found
				calculatedPcrs[pcr] = internal.ExtendSha256(calculatedPcrs[pcr],
					event.Sha256)

				nameInfo := ref.Name
				if event.EventName != "" && !strings.EqualFold(ref.Name, event.EventName) {
					nameInfo += ": " + event.EventName
				}

				measResult := ar.DigestResult{
					Pcr:         &pcr,
					Digest:      hex.EncodeToString(event.Sha256),
					Success:     true,
					Launched:    true,
					Name:        nameInfo,
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

		} else if measuredPcr.Type == "PCR Summary" {
			// measurement contains just the summary PCR value
			// We therefore unconditionally extend every reference value for this PCR
			if len(measuredPcr.Events) != 1 {
				log.Debugf("Expected exactly one event for artifact type 'PCR Summary', got %v", len(measuredPcr.Events))
				ok = false
				continue
			}
			for _, ref := range referenceValues {
				if ref.Pcr == nil {
					log.Debugf("No PCR set in TPM Reference Value %v (hash: %v)", ref.Name, hex.EncodeToString(ref.Sha256))
					ok = false
					continue
				}
				if *ref.Pcr == pcr {
					if ref.Name == "TPM_PCR_INIT_VALUE" {
						calculatedPcrs[pcr] = ref.Sha256 //the Sha256 should contain the init value
						continue                         //break the loop iteration and continue with the next event
					}
					calculatedPcrs[pcr] = internal.ExtendSha256(calculatedPcrs[pcr], ref.Sha256)

					// As we only have the PCR summary, we will later  set all reference values
					// to true/false depending on whether the calculation matches the PCR summary
					measResult := ar.DigestResult{
						Pcr:         &pcr,
						Digest:      hex.EncodeToString(ref.Sha256),
						Name:        ref.Name,
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
				ok = false
			}
			// If the measurement only contains the final PCR value, set all reference values
			// for this PCR to the according value, as we cannot determine which ones
			// were good or potentially failed
			for i, elem := range detailedResults {
				if *elem.Pcr == pcr && measuredPcr.Type != "PCR Eventlog" {
					detailedResults[i].Success = equal
					detailedResults[i].Launched = equal
				}
			}

		} else {
			ok = false
			pcrResult.Success = false
			log.Debugf("Unknown measurement PCR type %v", measuredPcr.Type)
		}

		pcrResults = append(pcrResults, pcrResult)

	}

	// Sort the results in ascending order
	sort.Slice(pcrResults, func(i, j int) bool {
		return pcrResults[i].Pcr < pcrResults[j].Pcr
	})

	// Finally, iterate over the reference values to find reference values with no
	// matching PCR or required reference values which are not present in the measurement
	// in case of detailed measurement logs
	for _, ref := range referenceValues {

		if ref.Pcr == nil {
			result := ar.DigestResult{
				Type:        "Reference Value",
				Success:     false,
				Launched:    false,
				Name:        ref.Name,
				Digest:      hex.EncodeToString(ref.Sha256),
				Description: ref.Description,
				CtrDetails:  ar.GetCtrDetailsFromRefVal(&ref, s),
			}
			detailedResults = append(detailedResults, result)
			ok = false
			log.Debugf("Reference value %v does not contain PCR", ref.Name)
			continue
		}

		// Check if measurement contains the reference value PCR
		foundPcr := false
		for _, measuredPcr := range measurement.Artifacts {

			if measuredPcr.Pcr == nil {
				log.Debug("PCR not specified")
				ok = false
				continue
			}

			if *measuredPcr.Pcr == *ref.Pcr {
				foundPcr = true
			} else {
				continue
			}

			// Check if the reference value is present (only possible if detailed
			// measurement logs were provided. In case of summary, every reference value is
			// extended expected)
			if measuredPcr.Type != "PCR Summary" {
				foundEvent := false
				for _, event := range measuredPcr.Events {
					if bytes.Equal(event.Sha256, ref.Sha256) {
						foundEvent = true
					}
				}
				if !foundEvent {
					result := ar.DigestResult{
						Type:        "Reference Value",
						Pcr:         ref.Pcr,
						Success:     ref.Optional, // Only fail attestation if component is mandatory
						Launched:    false,
						Name:        ref.Name,
						Digest:      hex.EncodeToString(ref.Sha256),
						Description: ref.Description,
						CtrDetails:  ar.GetCtrDetailsFromRefVal(&ref, s),
					}
					detailedResults = append(detailedResults, result)
					if !ref.Optional {
						ok = false
						log.Debugf("Failed to find required PCR%v reference value %v: %v in measurements",
							*ref.Pcr, ref.Name, hex.EncodeToString(ref.Sha256))
					}
					continue
				}
			}
		}
		if !foundPcr {
			result := ar.DigestResult{
				Type:        "Reference Value",
				Pcr:         ref.Pcr,
				Success:     ref.Optional,
				Launched:    false,
				Name:        ref.Name,
				Digest:      hex.EncodeToString(ref.Sha256),
				Description: ref.Description,
			}
			detailedResults = append(detailedResults, result)
			ok = false
			continue
		}
	}

	return calculatedPcrs, pcrResults, detailedResults, ok
}

func verifyTpmQuoteSignature(quote, sig []byte, cert *x509.Certificate) ar.Result {

	buf := new(bytes.Buffer)
	buf.Write((sig))
	tpmtSig, err := tpm2.DecodeSignature(buf)
	if err != nil {
		log.Debugf("Failed to decode TPM signature: %v", err)
		return ar.Result{Success: false, ErrorCode: ar.Parse}
	}

	if tpmtSig.Alg != tpm2.AlgRSASSA {
		log.Debugf("Hash algorithm %v not supported", tpmtSig.Alg)
		return ar.Result{Success: false, ErrorCode: ar.UnsupportedAlgorithm}
	}

	// Extract public key from x509 certificate
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		log.Debugf("Failed to extract public key from certificate")
		return ar.Result{Success: false, ErrorCode: ar.ExtractPubKey}
	}
	hashAlg, err := tpmtSig.RSA.HashAlg.Hash()
	if err != nil {
		log.Debugf("Hash algorithm not supported")
		return ar.Result{Success: false, ErrorCode: ar.UnsupportedAlgorithm}
	}

	// Hash the quote and Verify the TPM Quote signature
	hashed := sha256.Sum256(quote)
	err = rsa.VerifyPKCS1v15(pubKey, hashAlg, hashed[:], tpmtSig.RSA.Signature)
	if err != nil {
		log.Debugf("Failed to verify TPM quote signature: %v", err)
		return ar.Result{Success: false, ErrorCode: ar.VerifySignature}
	}
	return ar.Result{Success: true}
}

// Searches for a specific hash value in the reference values for RTM and OS
func getReferenceValue(hash []byte, pcr int, refVals []ar.ReferenceValue) *ar.ReferenceValue {
	for _, ref := range refVals {
		if *ref.Pcr == pcr && bytes.Equal(ref.Sha256, hash) {
			return &ref
		}
	}
	return nil
}
