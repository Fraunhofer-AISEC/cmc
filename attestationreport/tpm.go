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

	"github.com/google/go-tpm/tpm2"
)

func verifyTpmMeasurements(tpmM *TpmMeasurement, nonce []byte, rtmVerifications, osVerifications []TpmVerification) (TpmMeasurementResult, bool) {
	result := TpmMeasurementResult{}
	ok := true

	// Extend the verifications to re-calculate the PCR value and evaluate it against the measured
	// PCR value. In case of a measurement list, also extend the measured values to re-calculate
	// the measured PCR value
	verifications := make(map[int][]byte)

	numExtends := 0
	for _, hce := range tpmM.HashChain {
		pcrRes := PcrResult{}
		pcrRes.Pcr = int(hce.Pcr)

		if len(hce.Sha256) == 1 {
			// This means, that the value from the PCR was directly taken for the measurement
			measurement, _ := hex.DecodeString(hce.Sha256[0])

			// Calculate the expected PCR value from the verifications
			ver, n := extendVerifications(int(hce.Pcr), rtmVerifications, osVerifications)
			verifications[int(hce.Pcr)] = ver
			numExtends += n

			// Compare the expected PCR value with the measured PCR value
			if bytes.Compare(measurement, verifications[int(hce.Pcr)]) == 0 {
				pcrRes.Validation.Success = true
			} else {
				msg := fmt.Sprintf("PCR value did not match expectation: %v vs. %v", hce.Sha256[0], hex.EncodeToString(verifications[int(hce.Pcr)]))
				pcrRes.Validation.setFalseMulti(&msg)
				ok = false
			}
		} else {
			// This means, that the values of the individual software artefacts were stored
			// In this case, we must extend those values in order to re-calculate the final
			// PCR value
			hash := make([]byte, 32)
			for _, sha256 := range hce.Sha256 {
				h, _ := hex.DecodeString(sha256)
				hash = extendHash(hash, h)

				// Check, if a verification exists for the measured value
				v := getVerification(h, rtmVerifications, osVerifications)
				if v != nil {
					pcrRes.Validation.Success = true
					verifications[int(hce.Pcr)] = hash
					numExtends++
				} else {
					msg := fmt.Sprintf("No verification found for measurement: %v", sha256)
					pcrRes.Validation.setFalseMulti(&msg)
					ok = false
				}
			}
		}
		result.PcrRecalculation = append(result.PcrRecalculation, pcrRes)
	}

	// Check that every verification was extended
	if numExtends != (len(rtmVerifications) + len(osVerifications)) {
		msg := fmt.Sprintf("Could not find each expected artefact in measurements (Total: %v, Expected: %v)", numExtends, len(rtmVerifications)+len(osVerifications))
		result.Summary.setFalse(&msg)
		ok = false
	}

	// Extract TPM Quote (TPMS ATTEST) and signature
	quote, err := hex.DecodeString(tpmM.Message)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode TPM quote: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}
	tpmsAttest, err := tpm2.DecodeAttestationData(quote)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode TPM attestation data: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}
	sig, err := hex.DecodeString(tpmM.Signature)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode TPM signature: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Verify nonce with nonce from TPM Quote
	if bytes.Compare(nonce, tpmsAttest.ExtraData) == 0 {
		result.QuoteFreshness.Success = true
	} else {
		msg := fmt.Sprintf("Nonces mismatch: Supplied Nonce = %v, TPM Quote Nonce = %v)", hex.EncodeToString(nonce), hex.EncodeToString(tpmsAttest.ExtraData))
		result.QuoteFreshness.setFalse(&msg)
		ok = false
	}

	// Verify aggregated PCR against TPM Quote PCRDigest: Hash all verifications together then compare
	sum := make([]byte, 0)
	for i := range tpmM.HashChain {
		_, ok := verifications[int(tpmM.HashChain[i].Pcr)]
		if !ok {
			continue
		}
		sum = append(sum, verifications[int(tpmM.HashChain[i].Pcr)]...)
	}
	verPcr := sha256.Sum256(sum)
	if bytes.Compare(verPcr[:], tpmsAttest.AttestedQuoteInfo.PCRDigest) == 0 {
		result.AggPcrQuoteMatch.Success = true
	} else {
		msg := fmt.Sprintf("Aggregated PCR does not match Quote PCR: %v vs. %v", hex.EncodeToString(verPcr[:]), hex.EncodeToString(tpmsAttest.AttestedQuoteInfo.PCRDigest))
		result.AggPcrQuoteMatch.setFalse(&msg)
		ok = false
	}

	result.QuoteSignature = verifyTpmQuoteSignature(quote, sig, tpmM.Certs.Leaf)
	if result.QuoteSignature.Signature.Success == false {
		ok = false
	}

	certCheck, certChainOk := verifyCertChain(&tpmM.Certs)
	if !certChainOk {
		ok = false
	}
	result.QuoteSignature.CertCheck = certCheck

	result.Summary.Success = ok

	return result, ok
}

func verifyTpmQuoteSignature(quote, sig []byte, cert string) SignatureResult {
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
	x509Cert, err := loadCert([]byte(cert))
	if err != nil {
		msg := fmt.Sprintf("Failed to parse TPM certificate: %v", err)
		result.Signature.setFalse(&msg)
		return result
	}
	pubKey, ok := x509Cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		msg := fmt.Sprintf("Failed to extract public key from certificate")
		result.Signature.setFalse(&msg)
		return result
	}
	hashAlg, err := tpmtSig.RSA.HashAlg.Hash()
	if err != nil {
		msg := fmt.Sprintf("Hash algorithm not supported")
		result.Signature.setFalse(&msg)
		return result
	}

	// Store Name and Organization of AK Cert for the report
	result.Name = x509Cert.Subject.CommonName
	result.Organization = x509Cert.Subject.Organization

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
