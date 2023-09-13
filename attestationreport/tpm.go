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

package attestationreport

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/google/go-tpm/legacy/tpm2"
)

func verifyTpmMeasurements(tpmM *TpmMeasurement, nonce []byte, referenceValues []ReferenceValue, cas []*x509.Certificate) (*TpmMeasurementResult, bool) {
	result := &TpmMeasurementResult{}

	log.Trace("Verifying TPM measurements")

	// If the attestationreport does contain neither TPM measurements, nor TPM Reference Values
	// there is nothing to do
	if tpmM == nil && len(referenceValues) == 0 {
		return nil, true
	}

	// If the attestationreport contains TPM Reference Values, but no TPM measurement, the
	// attestation must fail
	if tpmM == nil {
		for _, v := range referenceValues {
			result.Artifacts = append(result.Artifacts,
				DigestResult{
					Name:    v.Name,
					Digest:  hex.EncodeToString(v.Sha256),
					Success: false,
					Type:    "Reference Value",
				})
		}
		msg := "TPM Measurement not present"
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Extend the reference values to re-calculate the PCR value and evaluate it against the measured
	// PCR value. In case of a measurement list, also extend the measured values to re-calculate
	// the measured PCR value
	calculatedPcrs, pcrResult, artifacts, ok := recalculatePcrs(tpmM, referenceValues)
	if !ok {
		log.Trace("failed to recalculate PCRs")
	}
	result.PcrMatch = pcrResult
	result.Artifacts = artifacts

	// Extract TPM Quote (TPMS ATTEST) and signature
	tpmsAttest, err := tpm2.DecodeAttestationData(tpmM.Message)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode TPM attestation data: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Verify nonce with nonce from TPM Quote
	if bytes.Equal(nonce, tpmsAttest.ExtraData) {
		result.QuoteFreshness.Success = true
	} else {
		msg := fmt.Sprintf("Nonces mismatch: Supplied Nonce = %v, TPM Quote Nonce = %v)",
			hex.EncodeToString(nonce), hex.EncodeToString(tpmsAttest.ExtraData))
		result.QuoteFreshness.setFalse(&msg)
		ok = false
	}

	// Verify aggregated PCR against TPM Quote PCRDigest: Hash all reference values
	// together then compare
	sum := make([]byte, 0)
	for i := range tpmM.HashChain {
		_, ok := calculatedPcrs[int(tpmM.HashChain[i].Pcr)]
		if !ok {
			continue
		}
		sum = append(sum, calculatedPcrs[int(tpmM.HashChain[i].Pcr)]...)
	}
	verPcr := sha256.Sum256(sum)
	if bytes.Equal(verPcr[:], tpmsAttest.AttestedQuoteInfo.PCRDigest) {
		log.Trace("Aggregated PCR matches quote PCR")
		result.AggPcrQuoteMatch.Success = true
	} else {
		msg := fmt.Sprintf("Aggregated PCR does not match Quote PCR: %v vs. %v",
			hex.EncodeToString(verPcr[:]),
			hex.EncodeToString(tpmsAttest.AttestedQuoteInfo.PCRDigest))
		result.AggPcrQuoteMatch.setFalse(&msg)
		ok = false
	}

	mCerts, err := internal.ParseCertsDer(tpmM.Certs)
	if err != nil {
		msg := fmt.Sprintf("Failed to load measurement certs: %v", err)
		result.QuoteSignature.CertChainCheck.setFalse(&msg)
		result.Summary.Success = false
		return result, false
	}

	result.QuoteSignature.SignCheck = verifyTpmQuoteSignature(tpmM.Message, tpmM.Signature, mCerts[0])
	if !result.QuoteSignature.SignCheck.Success {
		ok = false
	}

	x509Chains, err := internal.VerifyCertChain(mCerts, cas)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify certificate chain: %v", err)
		result.QuoteSignature.CertChainCheck.setFalse(&msg)
		ok = false
	} else {
		result.QuoteSignature.CertChainCheck.Success = true
	}

	//Store details from (all) validated certificate chain(s) in the report
	for _, chain := range x509Chains {
		chainExtracted := []X509CertExtracted{}
		for _, cert := range chain {
			chainExtracted = append(chainExtracted, ExtractX509Infos(cert))
		}
		result.QuoteSignature.ValidatedCerts = append(result.QuoteSignature.ValidatedCerts, chainExtracted)
	}

	result.Summary.Success = ok

	return result, ok
}

func recalculatePcrs(tpmM *TpmMeasurement, referenceValues []ReferenceValue) (map[int][]byte, []PcrResult, []DigestResult, bool) {
	ok := true
	pcrResult := make([]PcrResult, 0)
	artifacts := make([]DigestResult, 0)
	calculatedPcrs := make(map[int][]byte)

	for _, ref := range referenceValues {

		if ref.Pcr == nil {
			log.Warnf("No PCR set in TPM Reference Value %v (hash: %v)", ref.Name, hex.EncodeToString(ref.Sha256))
			ok = false
			continue
		}

		// Initialize calculated PCR if not yet initialized, afterwards extend
		// reference values
		if _, ok := calculatedPcrs[*ref.Pcr]; !ok {
			calculatedPcrs[*ref.Pcr] = make([]byte, 32)
		}
		calculatedPcrs[*ref.Pcr] = extendHash(calculatedPcrs[*ref.Pcr], ref.Sha256)
		refResult := DigestResult{
			Pcr:         ref.Pcr,
			Name:        ref.Name,
			Digest:      hex.EncodeToString(ref.Sha256),
			Description: ref.Description,
		}

		// Only if the measurement contains the hashes of the individual software artifacts,
		// (e.g.,  provided through BIOS or IMA  measurement lists), we can check the
		// reference values directly
		for _, hce := range tpmM.HashChain {
			if hce.Pcr == int32(*ref.Pcr) && !hce.Summary {
				found := false
				for _, sha256 := range hce.Sha256 {
					if bytes.Equal(sha256, ref.Sha256) {
						found = true
						refResult.Success = true
						break
					}
				}
				if !found {
					ok = false
					refResult.Success = false
					refResult.Type = "Reference Value"
				}
			}
		}

		artifacts = append(artifacts, refResult)
	}

	// Compare the calculated pcr values from the reference values with the measurement list
	// pcr values to provide a detailed report
	for pcrNum, calculatedHash := range calculatedPcrs {
		pcrRes := PcrResult{}
		pcrRes.Pcr = int(pcrNum)
		// Find PCR in measurements
		found := false
		for _, hce := range tpmM.HashChain {
			if hce.Pcr == int32(pcrNum) {
				found = true

				var measurement []byte
				if hce.Summary {
					// Measurement contains only final PCR value, so we can simply compare
					measurement = hce.Sha256[0]
				} else {
					// Measurement contains individual values which must be extended to result in
					// the final PCR value for comparison
					measurement = make([]byte, 32)
					for _, sha256 := range hce.Sha256 {
						measurement = extendHash(measurement, sha256)

						// Check, if a reference value exists for the measured value
						v := getReferenceValue(sha256, referenceValues)
						if v == nil {
							pcr := int(hce.Pcr)
							measResult := DigestResult{
								Pcr:     &pcr,
								Digest:  hex.EncodeToString(sha256),
								Success: false,
								Type:    "Measurement",
							}
							artifacts = append(artifacts, measResult)
							ok = false
						}
					}
				}

				// Compare the calculated hash for the current PCR with the measured hash
				equal := bytes.Equal(calculatedHash, measurement)
				if equal {
					pcrRes.Success = true
					pcrRes.Calculated = hex.EncodeToString(measurement)
				} else {
					pcrRes.Success = false
					pcrRes.Calculated = hex.EncodeToString(calculatedHash)
					pcrRes.Measured = hex.EncodeToString(measurement)
					ok = false
				}
				// If the measurement only contains the final PCR value, set all reference values
				// for this PCR to to the according value, as we cannot determine which ones
				// were good or potentially failed
				for i, elem := range artifacts {
					if *elem.Pcr == pcrNum && hce.Summary {
						artifacts[i].Success = equal
					}
				}

				pcrResult = append(pcrResult, pcrRes)
			}
		}
		if !found {
			// Set all reference values for this PCR to false, as the measurement did not
			// contain this PCR
			for i, elem := range artifacts {
				if *elem.Pcr == pcrNum {
					artifacts[i].Success = false
				}
			}
			ok = false
		}
	}

	// Sort the PCRs in ascending order
	sort.Slice(pcrResult, func(i, j int) bool {
		return pcrResult[i].Pcr < pcrResult[j].Pcr
	})

	// Finally, iterate over measurements to also include measured PCRs, that do not
	// contain matching reference values in the report
	for _, hce := range tpmM.HashChain {
		found := false
		for pcrNum := range calculatedPcrs {
			if hce.Pcr == int32(pcrNum) {
				found = true
			}
		}
		if !found {

			// Calculate the measurement value for this PCR
			var measurement []byte
			if hce.Summary {
				// Measurement contains only final PCR value, so we can simply compare
				measurement = hce.Sha256[0]
			} else {
				// Measurement contains individual values which must be extended to result in
				// the final PCR value for comparison
				measurement = make([]byte, 32)
				for _, sha256 := range hce.Sha256 {
					measurement = extendHash(measurement, sha256)
				}
			}

			pcrRes := PcrResult{
				Pcr:      int(hce.Pcr),
				Measured: hex.EncodeToString(measurement),
				Success:  false,
			}

			pcrResult = append(pcrResult, pcrRes)
			ok = false
		}
	}

	return calculatedPcrs, pcrResult, artifacts, ok
}

func verifyTpmQuoteSignature(quote, sig []byte, cert *x509.Certificate) Result {
	result := Result{}
	result.Success = true

	buf := new(bytes.Buffer)
	buf.Write((sig))
	tpmtSig, err := tpm2.DecodeSignature(buf)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode TPM signature: %v", err)
		result.setFalse(&msg)
		return result
	}

	if tpmtSig.Alg != tpm2.AlgRSASSA {
		msg := fmt.Sprintf("Hash algorithm %v not supported", tpmtSig.Alg)
		result.setFalse(&msg)
		return result
	}

	// Extract public key from x509 certificate
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		msg := "Failed to extract public key from certificate"
		result.setFalse(&msg)
		return result
	}
	hashAlg, err := tpmtSig.RSA.HashAlg.Hash()
	if err != nil {
		msg := "Hash algorithm not supported"
		result.setFalse(&msg)
		return result
	}

	// Hash the quote and Verify the TPM Quote signature
	hashed := sha256.Sum256(quote)
	err = rsa.VerifyPKCS1v15(pubKey, hashAlg, hashed[:], tpmtSig.RSA.Signature)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify TPM quote signature: %v", err)
		result.setFalse(&msg)
		return result
	}
	return result
}
