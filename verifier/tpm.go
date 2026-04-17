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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/google/go-tpm/legacy/tpm2"
)

func VerifyTpm(
	evidence ar.Evidence,
	collateral ar.Collateral,
	nonce []byte,
	cas []*x509.Certificate,
	refComponents []ar.Component,
	s ar.Serializer,
) (*ar.MeasurementResult, bool) {

	result := &ar.MeasurementResult{
		Type: "TPM Result",
		Summary: ar.Result{
			Status: ar.StatusSuccess,
		},
		TpmResult: &ar.TpmResult{},
	}

	log.Debugf("Verifying TPM measurements against %v reference values...", len(refComponents))

	// Extract TPM Quote (TPMS ATTEST) and signature
	tpmsAttest, err := tpm2.DecodeAttestationData(evidence.Data)
	if err != nil {
		result.Summary.Fail(ar.ParseEvidence, err)
		return result, false
	}
	log.Tracef("Decoded quote PCR with hash %v and PCR selection %v",
		tpmsAttest.AttestedQuoteInfo.PCRSelection.Hash,
		tpmsAttest.AttestedQuoteInfo.PCRSelection.PCRs)

	// Retrieve hash algorithm from quote
	quoteHashAlg, err := tpmAlgoToHash(tpmsAttest.AttestedQuoteInfo.PCRSelection.Hash)
	if err != nil {
		result.Summary.Fail(ar.ParseEvidence, err)
		return result, false
	}
	log.Tracef("Detected %v quote hash algorithm", quoteHashAlg.String())

	// Verify nonce with nonce from TPM Quote
	result.Freshness = verifyNonce(tpmsAttest.ExtraData, nonce)
	if result.Freshness.Status != ar.StatusSuccess {
		result.Summary.Status = ar.StatusFail
	}

	// Extend the reference values to re-calculate the PCR value and evaluate it against the measured
	// PCR value. In case of a measurement list, also extend the measured values to re-calculate
	// the measured PCR value
	tpmResult, artifacts, ok := verifyPcrs(s, collateral.Artifacts,
		tpmsAttest.AttestedQuoteInfo.PCRDigest, refComponents, quoteHashAlg)
	if !ok {
		log.Debug("failed to recalculate PCRs")
		result.Summary.Status = ar.StatusFail
	}
	result.TpmResult = tpmResult
	result.Artifacts = artifacts

	mCerts, err := internal.ParseCertsDer(collateral.Certs)
	if err != nil {
		log.Debugf("Failed to parse measurement certs: %v", err)
		result.Signature.CertChainCheck.Fail(ar.ParseCert)
		result.Summary.Status = ar.StatusFail
		return result, false
	}

	result.Signature.SignCheck = VerifyTpmQuoteSignature(evidence.Data, evidence.Signature, mCerts[0])
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
	result.Signature.Certs = append(result.Signature.Certs, extractX509Chains(x509Chains)...)

	if result.Summary.Status == ar.StatusSuccess {
		log.Debugf("Successfully verified TPM measurements")
	} else {
		log.Debugf("Failed to verify TPM measurements")
	}

	return result, result.Summary.Status == ar.StatusSuccess
}

func verifyPcrs(s ar.Serializer, artifacts []ar.Artifact,
	aggregatedQuotePcr []byte, refComponents []ar.Component, quoteHashAlg crypto.Hash,
) (*ar.TpmResult, []ar.DigestResult, bool) {
	success := true
	pcrResults := make([]ar.DigestResult, 0)
	detailedResults := make([]ar.DigestResult, 0)
	calculatedPcrs := make(map[int][]byte)

	// Iterate over the provided measurement
	log.Debugf("Recalculating PCRs with %v measurement artifacts...", len(artifacts))
	for _, artifact := range artifacts {

		pcrResult := ar.DigestResult{
			Index:   artifact.Index,
			Success: true,
		}

		pcr := artifact.Index

		// Initialize calculated PCR if not yet initialized, afterwards extend
		// reference values
		if _, ok := calculatedPcrs[pcr]; !ok {
			calculatedPcrs[pcr] = make([]byte, 32)
		}

		if artifact.Type == ar.TYPE_PCR_EVENTLOG {
			// Measurement contains a detailed measurement list (e.g. retrieved from bios
			// measurement logs or ima runtime measurement logs)
			log.Tracef("PCR%v measurement contains event log", artifact.Index)
			measuredSummary := make([]byte, 32)
			for _, event := range artifact.Events {

				eventHash := event.GetHash(quoteHashAlg)

				// First event could be a TPM_PCR_INIT_VALUE
				if event.Name == "TPM_PCR_INIT_VALUE" {
					calculatedPcrs[pcr] = eventHash
					measuredSummary = eventHash
					continue
				}

				// Extend measurement summary unconditionally...
				var err error
				measuredSummary, err = internal.Extend(quoteHashAlg, measuredSummary, eventHash)
				if err != nil {
					log.Debugf("Failed to extend: %v", err)
					success = false
				}

				// Check for every event that a corresponding reference value exists
				ref := getReferenceValue(quoteHashAlg, eventHash, pcr, refComponents)
				if ref == nil {
					measResult := ar.DigestResult{
						Type:        "Measurement",
						Index:       pcr,
						Digest:      eventHash,
						Success:     false,
						Launched:    true,
						Name:        event.Name,
						EventData:   event.EventData,
						CtrDetails:  event.CtrData,
						Description: event.Description,
						PackageUrl:  event.PackageUrl,
					}
					detailedResults = append(detailedResults, measResult)
					log.Debugf("Failed to find refval for PCR%v measurement %v: %v",
						artifact.Index, event.Name, hex.EncodeToString(eventHash))
					success = false
					pcrResult.Success = false
					continue
				}

				// ...Extent calculated summary only if reference value was found
				calculatedPcrs[pcr], err = internal.Extend(quoteHashAlg, calculatedPcrs[pcr], eventHash)
				if err != nil {
					log.Debugf("Failed to extend: %v", err)
					success = false
				}

				nameInfo := ref.Name
				if event.Name != "" && !strings.EqualFold(ref.Name, event.Name) {
					nameInfo += ": " + event.Name
				}

				log.Tracef("Found refval for PCR%v measurement %v: %v",
					pcr, nameInfo, hex.EncodeToString(eventHash))

				measResult := ar.DigestResult{
					Type:        "Verified",
					Index:       pcr,
					Digest:      eventHash,
					Success:     true,
					Launched:    true,
					Name:        nameInfo,
					Description: ref.Description,
					CtrDetails:  event.CtrData,
					PackageUrl:  ref.PackageUrl,
				}
				detailedResults = append(detailedResults, measResult)
			}
			pcrResult.Digest = calculatedPcrs[pcr]
			if !bytes.Equal(measuredSummary, calculatedPcrs[pcr]) {
				pcrResult.Measured = hex.EncodeToString(measuredSummary)
			}

		} else if artifact.Type == ar.TYPE_PCR_SUMMARY {
			// Measurement contains just the summary PCR value
			log.Tracef("PCR%v measurement contains PCR summary", artifact.Index)
			if len(artifact.Events) != 1 {
				log.Debugf("Expected exactly one event for artifact type %q, got %v",
					ar.TYPE_PCR_SUMMARY, len(artifact.Events))
				success = false
				continue
			}
			for _, ref := range refComponents {
				if ref.Index == pcr {

					refHash := ref.GetHash(quoteHashAlg)

					if ref.Name == "TPM_PCR_INIT_VALUE" {
						calculatedPcrs[pcr] = refHash
						continue
					}

					if ref.Name == ar.TYPE_PCR_SUMMARY {
						log.Tracef("PCR%v refval is PCR summary", artifact.Index)

						// Check if calculatedPcrs is uninitialized, as only one reference
						// value summary is allowed
						if !bytes.Equal(calculatedPcrs[pcr], make([]byte, len(calculatedPcrs[pcr]))) {
							log.Debugf("Fail: PCR%v multiple reference values type %q",
								pcr, ar.TYPE_PCR_SUMMARY)
							success = false
						}

						// Also the reference value is a PCR summary, set the calculated value
						calculatedPcrs[pcr] = refHash
					} else {
						// As we only have the measured final value, but reference values for
						// each artifact, unconditionally extend the reference value
						var err error
						calculatedPcrs[pcr], err = internal.Extend(quoteHashAlg, calculatedPcrs[pcr], refHash)
						if err != nil {
							log.Debugf("Failed to extend: %v", err)
							success = false
						}

						log.Tracef("Extended refval for PCR%v %v: %v",
							pcr, ref.Name, hex.EncodeToString(refHash))
					}

					// As we only have the PCR summary, we will later set all reference values
					// to true/false depending on whether the calculation matches the PCR summary
					r := ar.DigestResult{
						Index:       pcr,
						Digest:      refHash,
						Name:        ref.Name,
						Description: ref.Description,
						PackageUrl:  ref.PackageUrl,
					}
					detailedResults = append(detailedResults, r)
				}

			}
			// Then we compare the calculated value with the PCR measurement summary
			eventHash := artifact.Events[0].GetHash(quoteHashAlg)
			equal := bytes.Equal(calculatedPcrs[pcr], eventHash)
			if equal {
				pcrResult.Digest = calculatedPcrs[pcr]
				pcrResult.Success = true
				log.Tracef("PCR%v match: %x", pcr, calculatedPcrs[pcr])
			} else {
				log.Debugf("PCR%v mismatch: measured: %v, calculated: %v", pcr,
					hex.EncodeToString(eventHash),
					hex.EncodeToString(calculatedPcrs[pcr]))
				pcrResult.Digest = calculatedPcrs[pcr]
				pcrResult.Measured = hex.EncodeToString(eventHash)
				pcrResult.Success = false
				success = false
			}
			// If the measurement only contains the final PCR value, set all reference values
			// for this PCR to the according value, as we cannot determine which ones
			// were good or potentially failed
			for i, elem := range detailedResults {
				if elem.Index == pcr && artifact.Type != ar.TYPE_PCR_EVENTLOG {
					detailedResults[i].Success = equal
					detailedResults[i].Launched = equal
				}
			}

		} else {
			success = false
			pcrResult.Success = false
			log.Debugf("Unknown measurement PCR type %v", artifact.Type)
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
	for _, ref := range refComponents {

		refHash := ref.GetHash(quoteHashAlg)

		// Check if measurement contains the reference value PCR
		foundPcr := false
		for _, measuredPcr := range artifacts {

			if measuredPcr.Index == ref.Index {
				foundPcr = true
			} else {
				continue
			}

			// Check if the reference value is present (only possible if detailed
			// measurement logs were provided. In case of summary, every reference value is
			// extended expected)
			if measuredPcr.Type != ar.TYPE_PCR_SUMMARY {
				foundEvent := false
				for _, event := range measuredPcr.Events {
					if bytes.Equal(event.GetHash(quoteHashAlg), refHash) {
						foundEvent = true
					}
				}
				if !foundEvent {
					result := ar.DigestResult{
						Type:        ar.TYPE_REFVAL_IAS,
						Name:        ref.Name,
						Index:       ref.Index,
						Success:     ref.Optional, // Only fail attestation if component is mandatory
						Launched:    false,
						Digest:      refHash,
						Description: ref.Description,
						CtrDetails:  ref.CtrData,
						EventData:   ref.EventData,
						PackageUrl:  ref.PackageUrl,
					}
					if !ref.Optional {
						detailedResults = append(detailedResults, result)
						success = false
						log.Debugf("Failed to find measurement for required PCR%v reference value %v: %v",
							ref.Index, ref.Name, hex.EncodeToString(refHash))
					}
					continue
				}
			}
		}
		if !foundPcr {
			log.Debugf("Failed to find measurement for required PCR%v reference value %v: %v",
				ref.Index, ref.Name, hex.EncodeToString(refHash))
			result := ar.DigestResult{
				Type:        ar.TYPE_REFVAL_IAS,
				Name:        ref.Name,
				Index:       ref.Index,
				Success:     ref.Optional,
				Launched:    false,
				Digest:      refHash,
				Description: ref.Description,
				PackageUrl:  ref.PackageUrl,
			}
			detailedResults = append(detailedResults, result)
			success = false
			continue
		}
	}

	// Calculate aggregated quote PCR: Hash all reference values together
	log.Debugf("Calculating aggregated quote PCR")
	sum := make([]byte, 0)
	for i := range artifacts {
		pcr := artifacts[i].Index
		_, ok := calculatedPcrs[pcr]
		if !ok {
			continue
		}
		log.Tracef("Aggregating PCR %v: %x", pcr, calculatedPcrs[pcr])
		sum = append(sum, calculatedPcrs[pcr]...)
	}
	verPcr, err := internal.Hash(quoteHashAlg, sum)
	if err != nil {
		log.Debugf("Failed to hash aggregated quote PCR: %v", err)
		success = false
	}

	// Verify calculated aggregated PCR value against quote PCR value
	aggPcrQuoteMatch := ar.Result{}
	if bytes.Equal(verPcr[:], aggregatedQuotePcr) {
		log.Debugf("Aggregated PCR matches quote PCR: %x", verPcr[:])
		aggPcrQuoteMatch.Status = ar.StatusSuccess
	} else {
		log.Debugf("Aggregated PCR does not match Quote PCR: %x vs. %x", verPcr[:], aggregatedQuotePcr)
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

	switch tpmtSig.Alg {
	case tpm2.AlgRSASSA:
		return verifyQuoteRSA(quote, tpmtSig, cert)
	case tpm2.AlgECDSA:
		return verifyQuoteECDSA(quote, tpmtSig, cert)
	default:
		result := ar.Result{}
		result.Fail(ar.UnsupportedAlgorithm, fmt.Errorf("hash algorithm %v not supported", tpmtSig.Alg))
		return result
	}
}

func verifyQuoteRSA(quote []byte, sig *tpm2.Signature, cert *x509.Certificate) ar.Result {
	// Extract public key from x509 certificate
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		result := ar.Result{}
		result.Fail(ar.ExtractPubKey, fmt.Errorf("failed to extract public key from certificate"))
		return result
	}
	hashAlg, err := sig.RSA.HashAlg.Hash()
	if err != nil {
		result := ar.Result{}
		result.Fail(ar.UnsupportedAlgorithm, fmt.Errorf("hash algorithm not supported"))
		return result
	}

	// Hash the quote with the given algorithm
	hashed, err := internal.Hash(hashAlg, quote)
	if err != nil {
		result := ar.Result{}
		result.Fail(ar.VerifySignature, err)
		return result
	}

	// The used driver libraries currently only support RSA signatures
	err = rsa.VerifyPKCS1v15(pubKey, hashAlg, hashed[:], sig.RSA.Signature)
	if err != nil {
		result := ar.Result{}
		result.Fail(ar.VerifySignature, err)
		return result
	}

	log.Debugf("Successfully verified TPM quote RSA signature")

	return ar.Result{Status: ar.StatusSuccess}
}

func verifyQuoteECDSA(quote []byte, sig *tpm2.Signature, cert *x509.Certificate) ar.Result {
	// Extract public key from x509 certificate
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		result := ar.Result{}
		result.Fail(ar.ExtractPubKey, fmt.Errorf("failed to extract public key from certificate"))
		return result
	}
	hashAlg, err := sig.ECC.HashAlg.Hash()
	if err != nil {
		result := ar.Result{}
		result.Fail(ar.UnsupportedAlgorithm, fmt.Errorf("hash algorithm not supported"))
		return result
	}

	// Hash the quote with the given algorithm
	hashed, err := internal.Hash(hashAlg, quote)
	if err != nil {
		result := ar.Result{}
		result.Fail(ar.VerifySignature, err)
		return result
	}

	// TPM ECDSA signature is (R, S), not ASN.1
	if !ecdsa.Verify(pubKey, hashed, sig.ECC.R, sig.ECC.S) {
		result := ar.Result{}
		result.Fail(ar.VerifySignature, fmt.Errorf("ecdsa signature verification failed"))
		return result
	}

	log.Debugf("Successfully verified TPM quote ECDSA signature")

	return ar.Result{Status: ar.StatusSuccess}
}

// Searches for a specific hash value in the reference values
func getReferenceValue(alg crypto.Hash, hash []byte, pcr int, refVals []ar.Component) *ar.Component {
	for _, ref := range refVals {
		refHash := ref.GetHash(alg)
		if ref.Index == pcr && bytes.Equal(refHash, hash) {
			return &ref
		}
	}
	return nil
}

func tpmAlgoToHash(in tpm2.Algorithm) (crypto.Hash, error) {

	switch in {
	case tpm2.AlgSHA1:
		return crypto.SHA1, nil
	case tpm2.AlgSHA256:
		return crypto.SHA256, nil
	case tpm2.AlgSHA384:
		return crypto.SHA384, nil
	case tpm2.AlgSHA512:
		return crypto.SHA512, nil
	}

	return 0, fmt.Errorf("unsupported TPM hash alg %v", in)
}
