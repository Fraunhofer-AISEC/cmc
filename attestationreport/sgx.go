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
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

func verifySgxMeasurements(sgxM *SgxMeasurement, nonce []byte, referenceValues []ReferenceValue) (*SgxMeasurementResult, bool) {
	var err error
	result := &SgxMeasurementResult{}
	ok := true

	// If the attestationreport does contain neither SGX measurements, nor SGX Reference Values
	// there is nothing to to
	if sgxM == nil && len(referenceValues) == 0 {
		return nil, true
	}

	if len(referenceValues) == 0 {
		msg := "Could not find SGX Reference Value"
		result.Summary.setFalse(&msg)
		return result, false
	} else if len(referenceValues) > 1 {
		msg := fmt.Sprintf("Report contains %v reference values. Currently, only one SGX Reference Value is supported",
			len(referenceValues))
		result.Summary.setFalse(&msg)
		return result, false
	}
	sgxReferenceValue := referenceValues[0]

	// If the attestationreport contains SGX Reference Values, but no SGX measurement, the attestation must fail
	if sgxM == nil {
		for _, v := range referenceValues {
			result.Artifacts = append(result.Artifacts,
				DigestResult{
					Name:    v.Name,
					Digest:  hex.EncodeToString(v.Sha256),
					Success: false,
					Type:    "Reference Value",
				})
		}
		result.Summary.Success = false
		return result, false
	}

	// Validate Parameters:
	if sgxM.Report == nil || len(sgxM.Report) < SGX_QUOTE_MIN_SIZE {
		msg := "Invalid SGX Report."
		result.Summary.setFalse(&msg)
		return result, false
	}

	if sgxReferenceValue.Type != "SGX Reference Value" {
		msg := fmt.Sprintf("SGX Reference Value invalid type %v", sgxReferenceValue.Type)
		result.Summary.setFalse(&msg)
		return result, false
	}

	if sgxReferenceValue.Sgx == nil {
		msg := "SGX Reference Value is null"
		result.Summary.setFalse(&msg)
		return result, false
	}

	var sgxQuote SgxReport
	var quoteType uint32 = sgxReferenceValue.Sgx.Collateral.TeeType
	if quoteType == SGX_QUOTE_TYPE {
		// extract the attestation report into the SGXReport data structure
		sgxQuote, err = DecodeSgxReport(sgxM.Report)
		if err != nil {
			msg := fmt.Sprintf("Failed to decode SGX report: %v", err)
			result.Summary.setFalse(&msg)
			return result, false
		}
	} else {
		log.Tracef("Unknown quote type (tee_type: %X)\n", quoteType)
		return result, false
	}

	// Compare Nonce for Freshness (called Report Data in the SNP Attestation Report Structure)
	// ReportData contains: nonce in ReportData field
	nonce64 := make([]byte, 64)
	copy(nonce64, nonce[:])

	if cmp := bytes.Compare(sgxQuote.ISVEnclaveReport.ReportData[:], nonce64); cmp != 0 {
		msg := fmt.Sprintf("Nonces mismatch: Plain Nonce: %v, Expected: %v, Got = %v",
			nonce, hex.EncodeToString(nonce64), hex.EncodeToString(sgxQuote.ISVEnclaveReport.ReportData[:]))
		result.Freshness.setFalse(&msg)
		result.Summary.Success = false
		return result, false
	} else {
		result.Freshness.Success = true
	}

	// parse cert chain
	referenceCerts, err := ParseCertificates(sgxM.Certs, true)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse reference certificates: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// (from DCAP Library): parse PCK Cert chain (from the quote) into CertificateChain object. return error in case of failure
	// TODO: handle other QECertDataTypes (for now: throw an error)
	var quoteCerts SgxCertificates
	if sgxQuote.QuoteSignatureData.QECertDataType == 5 {
		quoteCerts, err = ParseCertificates(sgxQuote.QuoteSignatureData.QECertData, true)
		if err != nil {
			msg := fmt.Sprintf("Failed to parse certificate chain from QECertData: %v", err)
			result.Summary.setFalse(&msg)
			return result, false
		}
	} else {
		msg := fmt.Sprintf("QECertDataType not supported: %v", sgxQuote.QuoteSignatureData.QECertDataType)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Extract root CA from PCK cert chain in quote -> compare nullptr
	if quoteCerts.RootCACert == nil {
		msg := "root cert is null"
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Check root public key
	quotePublicKeyBytes, err := x509.MarshalPKIXPublicKey(quoteCerts.RootCACert.PublicKey)
	if err != nil {
		return result, false
	}

	referencePublicKeyBytes, err := x509.MarshalPKIXPublicKey(referenceCerts.RootCACert.PublicKey)
	if err != nil {
		return result, false
	}

	if !bytes.Equal(quotePublicKeyBytes, referencePublicKeyBytes) {
		msg := "root cert public key didn't match"
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Parse and verify PCK certificate extensions
	sgxExtensions, err := ParseSGXExtensions(quoteCerts.PCKCert.Extensions[SGX_EXTENSION_INDEX].Value[4:]) // skip the first value (not relevant)
	if err != nil {
		msg := fmt.Sprintf("failed to parse SGX Extensions from PCK Certificate: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Parse and verify TcbInfo object
	tcbInfo, err := ParseTcbInfo(sgxReferenceValue.Sgx.Collateral.TcbInfo)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse tcbInfo: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	tcbInfoResult, err := verifyTcbInfo(&tcbInfo, string(sgxReferenceValue.Sgx.Collateral.TcbInfo), referenceCerts.TCBSigningCert,
		sgxExtensions, [16]byte{}, SGX_QUOTE_TYPE)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify TCB info structure: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}
	result.TcbInfoCheck = tcbInfoResult

	// Parse and verify QE Identity object
	qeIdentity, err := ParseQEIdentity(sgxReferenceValue.Sgx.Collateral.QeIdentity)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse tcbInfo: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	qeIdentityResult, err := VerifyQEIdentity(&sgxQuote.QuoteSignatureData.QEReport, &qeIdentity,
		string(sgxReferenceValue.Sgx.Collateral.QeIdentity), referenceCerts.TCBSigningCert, SGX_QUOTE_TYPE)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify QE Identity structure: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}
	result.QeIdentityCheck = qeIdentityResult

	// Verify Quote Signature
	sig, ret := VerifyIntelQuoteSignature(sgxM.Report, sgxQuote.QuoteSignatureData,
		sgxQuote.QuoteSignatureDataLen, int(sgxQuote.QuoteHeader.AttestationKeyType), referenceCerts,
		sgxReferenceValue.Sgx.CaFingerprint, quoteType)
	if !ret {
		ok = false
	}
	result.Signature = sig

	// Verify Quote Body values
	err = VerifySgxQuoteBody(&sgxQuote.ISVEnclaveReport, &tcbInfo, &sgxExtensions, &sgxReferenceValue, result)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify SGX Report Body: %v", err)
		result.Summary.setFalse(&msg)
		result.Summary.Success = false
		return result, false
	}

	// Check version
	result.VersionMatch, ret = verifyQuoteVersion(sgxQuote.QuoteHeader, sgxReferenceValue.Sgx.Version)
	if !ret {
		return result, false
	}

	result.Summary.Success = ok

	return result, ok
}

func VerifySgxQuoteBody(body *EnclaveReportBody, tcbInfo *TcbInfo,
	sgxExtensions *SGXExtensionsValue, sgxReferenceValue *ReferenceValue, result *SgxMeasurementResult) error {
	if body == nil || tcbInfo == nil || sgxExtensions == nil || sgxReferenceValue == nil || result == nil {
		return fmt.Errorf("invalid function parameter (null pointer exception)")
	}

	// check MRENCLAVE reference value
	if !bytes.Equal(body.MRENCLAVE[:], []byte(sgxReferenceValue.Sha256)) {
		result.Artifacts = append(result.Artifacts,
			DigestResult{
				Name:    sgxReferenceValue.Name,
				Digest:  hex.EncodeToString(sgxReferenceValue.Sha256[:]),
				Success: false,
				Type:    "Reference Value",
			})
		result.Artifacts = append(result.Artifacts,
			DigestResult{
				Name:    sgxReferenceValue.Name,
				Digest:  hex.EncodeToString(body.MRENCLAVE[:]),
				Success: false,
				Type:    "Measurement",
			})
		return fmt.Errorf("MRENCLAVE mismatch. Expected: %v, Got. %v", sgxReferenceValue.Sha256, body.MRENCLAVE)
	} else {
		result.Artifacts = append(result.Artifacts,
			DigestResult{
				Name:    sgxReferenceValue.Name,
				Digest:  hex.EncodeToString(body.MRENCLAVE[:]),
				Success: true,
			})
	}

	result.ExtendedQuoteCheck.TeeIdentity = append(result.ExtendedQuoteCheck.TeeIdentity,
		ComparisonResult{
			Name:     "MrSigner",
			Success:  strings.EqualFold(sgxReferenceValue.Sgx.MrSigner, hex.EncodeToString(body.MRSIGNER[:])),
			Claimed:  sgxReferenceValue.Sgx.MrSigner,
			Measured: hex.EncodeToString(body.MRSIGNER[:]),
		},
		// TODO: check how to compare CPUSVN value
		ComparisonResult{
			Name:     "CpuSvn",
			Success:  bytes.Equal(sgxExtensions.Tcb.Value.CpuSvn.Value, body.CPUSVN[:]),
			Claimed:  hex.EncodeToString(sgxExtensions.Tcb.Value.CpuSvn.Value),
			Measured: hex.EncodeToString(body.CPUSVN[:]),
		},
		ComparisonResult{
			Name:     "IsvProdId",
			Success:  sgxReferenceValue.Sgx.IsvProdId == body.ISVProdID,
			Claimed:  strconv.Itoa(int(sgxReferenceValue.Sgx.IsvProdId)),
			Measured: strconv.Itoa(int(body.ISVProdID)),
		},
		ComparisonResult{
			Name:     "IsvSvn",
			Success:  sgxReferenceValue.Sgx.IsvSvn == body.ISVSVN,
			Claimed:  strconv.Itoa(int(sgxReferenceValue.Sgx.IsvSvn)),
			Measured: strconv.Itoa(int(body.ISVSVN)),
		},
	)

	result.ExtendedQuoteCheck.TeeAttributes = append(result.ExtendedQuoteCheck.TeeAttributes,
		AttributesCheck{
			Name:     "Attributes",
			Success:  bytes.Equal(sgxReferenceValue.Sgx.Attributes[:], body.Attributes[:]),
			Claimed:  sgxReferenceValue.Sgx.Attributes[:],
			Measured: body.Attributes[:],
		},
	)

	for _, v := range result.ExtendedQuoteCheck.TeeIdentity {
		if !v.Success {
			return fmt.Errorf("TDX Quote Body Verification failed. %v: (Expected: %v, Got: %v)", v.Name, v.Claimed, v.Measured)
		}
	}

	for _, v := range result.ExtendedQuoteCheck.TeeAttributes {
		if !v.Success {
			return fmt.Errorf("TDX Quote Body Verification failed. %v: (Expected: %v, Got: %v)", v.Name, v.Claimed, v.Measured)
		}
	}

	return nil
}
