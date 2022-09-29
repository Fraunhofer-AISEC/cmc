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
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/google/go-tpm/tpm2"
)

func verifyTpmMeasurements(tpmM *TpmMeasurement, nonce []byte, verifications []Verification, casPem []byte) (*TpmMeasurementResult, bool) {
	result := &TpmMeasurementResult{}

	// If the attestationreport does contain neither TPM measurements, nor TPM verifications
	// there is nothing to do
	if tpmM == nil && len(verifications) == 0 {
		return nil, true
	}

	// If the attestationreport contains TPM verifications, but no TPM measurement, the
	// attestation must fail
	if tpmM == nil {
		for _, v := range verifications {
			msg := fmt.Sprintf("TPM Measurement not present. Cannot verify TPM verification %v (hash: %v)", v.Name, v.Sha256)
			result.VerificationsCheck.setFalseMulti(&msg)
		}
		result.Summary.Success = false
		return result, false
	}

	// Extend the verifications to re-calculate the PCR value and evaluate it against the measured
	// PCR value. In case of a measurement list, also extend the measured values to re-calculate
	// the measured PCR value
	calculatedPcrs, pcrResult, verificationsCheck, ok := recalculatePcrs(tpmM, verifications)
	result.PcrRecalculation = pcrResult
	result.VerificationsCheck = verificationsCheck

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
		msg := fmt.Sprintf("Nonces mismatch: Supplied Nonce = %v, TPM Quote Nonce = %v)", hex.EncodeToString(nonce), hex.EncodeToString(tpmsAttest.ExtraData))
		result.QuoteFreshness.setFalse(&msg)
		ok = false
	}

	// Verify aggregated PCR against TPM Quote PCRDigest: Hash all verifications together then compare
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
		result.AggPcrQuoteMatch.Success = true
	} else {
		msg := fmt.Sprintf("Aggregated PCR does not match Quote PCR: %v vs. %v", hex.EncodeToString(verPcr[:]), hex.EncodeToString(tpmsAttest.AttestedQuoteInfo.PCRDigest))
		result.AggPcrQuoteMatch.setFalse(&msg)
		ok = false
	}

	result.QuoteSignature = verifyTpmQuoteSignature(tpmM.Message, tpmM.Signature, tpmM.Certs.Leaf)
	if !result.QuoteSignature.Signature.Success {
		ok = false
	}

	// Verify certificate chain
	cas, err := LoadCerts(casPem)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify certificate chain: %v", err)
		result.QuoteSignature.CertCheck.setFalse(&msg)
		ok = false
	}
	keyIds := make([][]byte, 0)
	for _, ca := range cas {
		keyIds = append(keyIds, ca.SubjectKeyId)
	}
	err = verifyCertChainPem(&tpmM.Certs, keyIds)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify certificate chain: %v", err)
		result.QuoteSignature.CertCheck.setFalse(&msg)
		ok = false
	} else {
		result.QuoteSignature.CertCheck.Success = true
	}

	result.Summary.Success = ok

	return result, ok
}

func recalculatePcrs(tpmM *TpmMeasurement, verifications []Verification) (map[int][]byte, []PcrResult, ResultMulti, bool) {
	ok := true
	pcrResult := make([]PcrResult, 0)
	verificationsCheck := ResultMulti{
		Success: true,
	}
	calculatedPcrs := make(map[int][]byte)
	for _, v := range verifications {

		if v.Pcr == nil {
			msg := fmt.Sprintf("No PCR set in TPM Verification %v (hash: %v)", v.Name, hex.EncodeToString(v.Sha256))
			verificationsCheck.setFalseMulti(&msg)
			ok = false
			continue
		}

		// Initialize calculated PCR if not yet initialized, afterwards extend
		// verification
		if _, ok := calculatedPcrs[*v.Pcr]; !ok {
			calculatedPcrs[*v.Pcr] = make([]byte, 32)
		}
		calculatedPcrs[*v.Pcr] = extendHash(calculatedPcrs[*v.Pcr], v.Sha256)

		// Only if the measurement contains the hashes of the individual software artifacts, (e.g.
		// provided through BIOS or IMA  measurement lists), we can check the verification directly
		for _, hce := range tpmM.HashChain {
			if hce.Pcr == int32(*v.Pcr) && len(hce.Sha256) > 1 {
				found := false
				for _, sha256 := range hce.Sha256 {
					if bytes.Equal(sha256, v.Sha256) {
						found = true
						break
					}
				}
				if !found {
					msg := fmt.Sprintf("No TPM Measurement found for TPM verification %v (hash: %v)", v.Name, v.Sha256)
					verificationsCheck.setFalseMulti(&msg)
					ok = false
				}
			}
		}
	}

	// Compare the calculated pcr values from the verifications with the measurement list
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

						// Check, if a verification exists for the measured value
						v := getVerification(sha256, verifications)
						if v == nil {
							msg := fmt.Sprintf("No TPM verification found for TPM measurement: %v", sha256)
							pcrRes.Validation.setFalseMulti(&msg)
							ok = false
						}
					}
				}

				if cmp := bytes.Compare(calculatedHash, measurement); cmp == 0 {
					pcrRes.Validation.Success = true
				} else {
					msg := fmt.Sprintf("PCR value did not match expectation: %v vs. %v", hce.Sha256[0], hex.EncodeToString(calculatedHash))
					pcrRes.Validation.setFalseMulti(&msg)
					ok = false
				}
				pcrResult = append(pcrResult, pcrRes)
			}
		}
		if !found {
			msg := fmt.Sprintf("No TPM Measurement found for TPM Verifications of PCR %v", pcrNum)
			verificationsCheck.setFalseMulti(&msg)
			ok = false
		}
	}

	// Sort the PCRs in ascending order
	sort.Slice(pcrResult, func(i, j int) bool {
		return pcrResult[i].Pcr < pcrResult[j].Pcr
	})

	// Finally, iterate over measurements to also include measured PCRs, that do not
	// contain matching verifications in the report
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
			msg := fmt.Sprintf("No TPM verifications found for TPM measurement PCR: %v", hce.Pcr)
			pcrRes.Validation.setFalseMulti(&msg)
			pcrResult = append(pcrResult, pcrRes)
			ok = false
		}
	}

	return calculatedPcrs, pcrResult, verificationsCheck, ok
}

func verifyTpmQuoteSignature(quote, sig []byte, cert []byte) SignatureResult {
	result := SignatureResult{}
	result.Signature.Success = true

	buf := new(bytes.Buffer)
	buf.Write((sig))
	tpmtSig, err := tpm2.DecodeSignature(buf)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode TPM signature: %v", err)
		result.Signature.setFalse(&msg)
		return result
	}

	if tpmtSig.Alg != tpm2.AlgRSASSA {
		msg := fmt.Sprintf("Hash algorithm %v not supported", tpmtSig.Alg)
		result.Signature.setFalse(&msg)
		return result
	}

	// Extract public key from x509 certificate
	x509Cert, err := LoadCert(cert)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse TPM certificate: %v", err)
		result.Signature.setFalse(&msg)
		return result
	}
	pubKey, ok := x509Cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		msg := "Failed to extract public key from certificate"
		result.Signature.setFalse(&msg)
		return result
	}
	hashAlg, err := tpmtSig.RSA.HashAlg.Hash()
	if err != nil {
		msg := "Hash algorithm not supported"
		result.Signature.setFalse(&msg)
		return result
	}

	// Store Name and Organization of AK Cert for the report
	result.Name = x509Cert.Subject.CommonName
	result.Organization = x509Cert.Subject.Organization
	result.SubjectKeyId = hex.EncodeToString(x509Cert.SubjectKeyId)
	result.AuthorityKeyId = hex.EncodeToString(x509Cert.AuthorityKeyId)

	// Hash the quote and Verify the TPM Quote signature
	hashed := sha256.Sum256(quote)
	err = rsa.VerifyPKCS1v15(pubKey, hashAlg, hashed[:], tpmtSig.RSA.Signature)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify TPM quote signature: %v", err)
		result.Signature.setFalse(&msg)
		return result
	}
	return result
}
