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
	"github.com/google/go-tpm/tpm2"
)

func verifyTpmMeasurements(tpmM *TpmMeasurement, nonce []byte, referenceValues []ReferenceValue, cas []*x509.Certificate) (*TpmMeasurementResult, bool) {
	result := &TpmMeasurementResult{}

	log.Trace("Verifying TPM measurements")

	// If the attestationreport does contain neither TPM measurements, nor TPM Reference Values
	// there is nothing to do
	if tpmM == nil && len(referenceValues) == 0 {
		log.Trace("Attestation report does not contain TPM measurements or TPM reference values")
		return nil, true
	}

	// If the attestationreport contains TPM Reference Values, but no TPM measurement, the
	// attestation must fail
	if tpmM == nil {
		for _, v := range referenceValues {
			msg := fmt.Sprintf("TPM Measurement not present. Cannot verify TPM Reference Value %v (hash: %v)",
				v.Name, hex.EncodeToString(v.Sha256))
			result.Extends.Summary.setFalseMulti(&msg)
		}
		result.Summary.Success = false
		return result, false
	}

	// Extend the reference values to re-calculate the PCR value and evaluate it against the measured
	// PCR value. In case of a measurement list, also extend the measured values to re-calculate
	// the measured PCR value
	calculatedPcrs, pcrResult, extends, ok := recalculatePcrs(tpmM, referenceValues)
	result.PcrMatch = pcrResult
	result.Extends = extends

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

func recalculatePcrs(tpmM *TpmMeasurement, referenceValues []ReferenceValue) (map[int][]byte, []PcrResult, DigestResult, bool) {
	ok := true
	pcrResult := make([]PcrResult, 0)
	extends := DigestResult{
		Summary: ResultMulti{
			Success: true,
		},
	}
	calculatedPcrs := make(map[int][]byte)
	for _, ref := range referenceValues {

		if ref.Pcr == nil {
			msg := fmt.Sprintf("No PCR set in TPM Reference Value %v (hash: %v)", ref.Name, hex.EncodeToString(ref.Sha256))
			extends.Summary.setFalseMulti(&msg)
			ok = false
			continue
		}

		// Initialize calculated PCR if not yet initialized, afterwards extend
		// reference values
		if _, ok := calculatedPcrs[*ref.Pcr]; !ok {
			calculatedPcrs[*ref.Pcr] = make([]byte, 32)
		}
		calculatedPcrs[*ref.Pcr] = extendHash(calculatedPcrs[*ref.Pcr], ref.Sha256)
		extends.Digests = append(extends.Digests, Digest{
			Pcr:         ref.Pcr,
			Name:        ref.Name,
			Digest:      hex.EncodeToString(ref.Sha256),
			Description: ref.Description,
		})

		// Only if the measurement contains the hashes of the individual software artifacts, (e.g.
		// provided through BIOS or IMA  measurement lists), we can check the reference values directly
		for _, hce := range tpmM.HashChain {
			if hce.Pcr == int32(*ref.Pcr) && len(hce.Sha256) > 1 {
				found := false
				for _, sha256 := range hce.Sha256 {
					if bytes.Equal(sha256, ref.Sha256) {
						found = true
						break
					}
				}
				if !found {
					msg := fmt.Sprintf("No TPM Measurement found for TPM Reference Value %v (hash: %v)", ref.Name, ref.Sha256)
					extends.Summary.setFalseMulti(&msg)
					ok = false
				}
			}
		}
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
				if len(hce.Sha256) == 1 {
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
							msg := fmt.Sprintf("No TPM Reference Value found for TPM measurement: %v", sha256)
							pcrRes.Validation.setFalseMulti(&msg)
							ok = false
						}
					}
				}

				if cmp := bytes.Compare(calculatedHash, measurement); cmp == 0 {
					pcrRes.Validation.Success = true
				} else {
					msg := fmt.Sprintf("PCR%v calculation does not match: %v",
						hce.Pcr, hex.EncodeToString(calculatedHash))
					pcrRes.Validation.setFalseMulti(&msg)
					ok = false
				}
				pcrRes.Digest = hex.EncodeToString(measurement)
				pcrResult = append(pcrResult, pcrRes)
			}
		}
		if !found {
			msg := fmt.Sprintf("No TPM Measurement found for TPM Reference Values of PCR %v", pcrNum)
			extends.Summary.setFalseMulti(&msg)
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
			pcrRes := PcrResult{}
			pcrRes.Pcr = int(hce.Pcr)
			msg := fmt.Sprintf("No TPM Reference Values found for TPM measurement PCR: %v", hce.Pcr)
			pcrRes.Validation.setFalseMulti(&msg)
			pcrResult = append(pcrResult, pcrRes)
			ok = false
		}
	}

	extends.Summary.Success = ok

	return calculatedPcrs, pcrResult, extends, ok
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
