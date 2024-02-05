// Copyright (c) 2024 Fraunhofer AISEC
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
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Overall structure: table 2 from https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
// Endianess: Little Endian (all Integer fields)
type SgxReport struct {
	QuoteHeader           QuoteHeader
	ISVEnclaveReport      EnclaveReportBody
	QuoteSignatureDataLen uint32
	QuoteSignatureData    ECDSA256QuoteSignatureDataStructure // variable size
}

// Parses the report into the SgxReport structure
func DecodeSgxReport(report []byte) (SgxReport, error) {
	var reportStruct SgxReport
	var header QuoteHeader
	var body EnclaveReportBody
	var sig ECDSA256QuoteSignatureDataStructure
	var sigLen uint32

	// parse header
	buf := bytes.NewBuffer(report)
	err := binary.Read(buf, binary.LittleEndian, &header)
	if err != nil {
		return SgxReport{}, fmt.Errorf("failed to decode SGX report header: %v", err)
	}

	// parse body
	err = binary.Read(buf, binary.LittleEndian, &body)
	if err != nil {
		return SgxReport{}, fmt.Errorf("failed to decode SGX report body: %v", err)
	}

	// parse signature size
	err = binary.Read(buf, binary.LittleEndian, &sigLen)
	if err != nil {
		return SgxReport{}, fmt.Errorf("failed to decode SGX report QuoteSignatureDataLen: %v", err)
	}

	// parse signature
	err = parseECDSASignature(buf, &sig)
	if err != nil {
		return SgxReport{}, fmt.Errorf("failed to decode SGX report ECDSA256QuotesignatureDataStructure: %v", err)
	}

	// compose the final report struct
	reportStruct.QuoteHeader = header
	reportStruct.ISVEnclaveReport = body
	reportStruct.QuoteSignatureDataLen = sigLen
	reportStruct.QuoteSignatureData = sig

	return reportStruct, nil
}

func verifySgxMeasurements(sgxM Measurement, nonce []byte, intelCache string, referenceValues []ReferenceValue) (*MeasurementResult, bool) {

	var err error
	result := &MeasurementResult{
		Type:      "SGX Result",
		SgxResult: &SgxResult{},
	}
	ok := true

	log.Trace("Verifying SGX measurements")

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

	// Validate Parameters:
	if sgxM.Evidence == nil || len(sgxM.Evidence) < SGX_QUOTE_MIN_SIZE {
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
		sgxQuote, err = DecodeSgxReport(sgxM.Evidence)
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

	// Parse certificate chain
	referenceCerts, err := parseCertificates(sgxM.Certs, true)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse reference certificates: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Currently only support for QECertDataType 5
	var quoteCerts SgxCertificates
	if sgxQuote.QuoteSignatureData.QECertDataType == 5 {
		quoteCerts, err = parseCertificates(sgxQuote.QuoteSignatureData.QECertData, true)
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
	sgxExtensions, err := parseSGXExtensions(quoteCerts.PCKCert.Extensions[SGX_EXTENSION_INDEX].Value[4:]) // skip the first value (not relevant)
	if err != nil {
		msg := fmt.Sprintf("failed to parse SGX Extensions from PCK Certificate: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Parse and verify TcbInfo object
	tcbInfo, err := parseTcbInfo(sgxReferenceValue.Sgx.Collateral.TcbInfo)
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
	result.SgxResult.TcbInfoCheck = tcbInfoResult

	// Parse and verify QE Identity object
	qeIdentity, err := parseQEIdentity(sgxReferenceValue.Sgx.Collateral.QeIdentity)
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
	result.SgxResult.QeIdentityCheck = qeIdentityResult

	// Verify Quote Signature
	sig, ret := VerifyIntelQuoteSignature(sgxM.Evidence, sgxQuote.QuoteSignatureData,
		sgxQuote.QuoteSignatureDataLen, int(sgxQuote.QuoteHeader.AttestationKeyType), referenceCerts,
		sgxReferenceValue.Sgx.CaFingerprint, intelCache, quoteType)
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
	result.SgxResult.VersionMatch, ret = verifyQuoteVersion(sgxQuote.QuoteHeader, sgxReferenceValue.Sgx.Version)
	if !ret {
		return result, false
	}

	result.Summary.Success = ok

	return result, ok
}

func VerifySgxQuoteBody(body *EnclaveReportBody, tcbInfo *TcbInfo,
	sgxExtensions *SGXExtensionsValue, sgxReferenceValue *ReferenceValue, result *MeasurementResult) error {
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
				Type:    "Measurement",
			})
	}

	result.Artifacts = append(result.Artifacts,
		DigestResult{
			Name:    "MrSigner",
			Digest:  hex.EncodeToString(body.MRENCLAVE[:]),
			Success: strings.EqualFold(sgxReferenceValue.Sgx.MrSigner, hex.EncodeToString(body.MRSIGNER[:])),
			Type:    "Measurement",
		},
		DigestResult{
			Name:    "CpuSvn",
			Digest:  hex.EncodeToString(body.CPUSVN[:]),
			Success: bytes.Compare(sgxExtensions.Tcb.Value.CpuSvn.Value, body.CPUSVN[:]) <= 0,
			Type:    "Security Version",
		},
		DigestResult{
			Name:    "IsvProdId",
			Digest:  strconv.Itoa(int(body.ISVProdID)),
			Success: sgxReferenceValue.Sgx.IsvProdId == body.ISVProdID,
			Type:    "Product ID",
		},
		DigestResult{
			Name:    "IsvSvn",
			Digest:  strconv.Itoa(int(body.ISVSVN)),
			Success: sgxReferenceValue.Sgx.IsvSvn == body.ISVSVN,
			Type:    "Security Version",
		},
	)

	for _, v := range result.Artifacts {
		if !v.Success {
			return fmt.Errorf("TDX Quote Body Verification failed. %v: (Got: %v)", v.Name, v.Digest)
		}
	}

	result.SgxResult.SgxAttributesCheck = SgxAttributesCheck{
		Initted: BooleanMatch{
			Success:  getBit(body.Attributes[:], 0) == sgxReferenceValue.Sgx.Attributes.Initted,
			Claimed:  sgxReferenceValue.Sgx.Attributes.Initted,
			Measured: getBit(body.Attributes[:], 0),
		},
		Debug: BooleanMatch{
			Success:  getBit(body.Attributes[:], 1) == sgxReferenceValue.Sgx.Attributes.Debug,
			Claimed:  sgxReferenceValue.Sgx.Attributes.Debug,
			Measured: getBit(body.Attributes[:], 1),
		},
		Mode64Bit: BooleanMatch{
			Success:  getBit(body.Attributes[:], 2) == sgxReferenceValue.Sgx.Attributes.Mode64Bit,
			Claimed:  sgxReferenceValue.Sgx.Attributes.Mode64Bit,
			Measured: getBit(body.Attributes[:], 2),
		},
		ProvisionKey: BooleanMatch{
			Success:  getBit(body.Attributes[:], 5) == sgxReferenceValue.Sgx.Attributes.ProvisionKey,
			Claimed:  sgxReferenceValue.Sgx.Attributes.ProvisionKey,
			Measured: getBit(body.Attributes[:], 5),
		},
		EInitToken: BooleanMatch{
			Success:  getBit(body.Attributes[:], 6) == sgxReferenceValue.Sgx.Attributes.EInitToken,
			Claimed:  sgxReferenceValue.Sgx.Attributes.EInitToken,
			Measured: getBit(body.Attributes[:], 6),
		},
		Kss: BooleanMatch{
			Success:  getBit(body.Attributes[:], 8) == sgxReferenceValue.Sgx.Attributes.Kss,
			Claimed:  sgxReferenceValue.Sgx.Attributes.Kss,
			Measured: getBit(body.Attributes[:], 8),
		},
		Legacy: BooleanMatch{
			Success:  (body.Attributes[8] == 3) == sgxReferenceValue.Sgx.Attributes.Legacy,
			Claimed:  sgxReferenceValue.Sgx.Attributes.Legacy,
			Measured: body.Attributes[8] == 3,
		},
		Avx: BooleanMatch{
			Success:  (body.Attributes[8] == 6) == sgxReferenceValue.Sgx.Attributes.Avx,
			Claimed:  sgxReferenceValue.Sgx.Attributes.Avx,
			Measured: body.Attributes[8] == 6,
		},
	}

	ok := result.SgxResult.SgxAttributesCheck.Initted.Success &&
		result.SgxResult.SgxAttributesCheck.Debug.Success &&
		result.SgxResult.SgxAttributesCheck.Mode64Bit.Success &&
		result.SgxResult.SgxAttributesCheck.ProvisionKey.Success &&
		result.SgxResult.SgxAttributesCheck.EInitToken.Success &&
		result.SgxResult.SgxAttributesCheck.Kss.Success &&
		result.SgxResult.SgxAttributesCheck.Legacy.Success &&
		result.SgxResult.SgxAttributesCheck.Avx.Success
	if !ok {
		return fmt.Errorf("SGXAttributesCheck failed: Initted: %v, Debug: %v, Mode64Bit: %v, ProvisionKey: %v, EInitToken: %v, Kss: %v, Legacy: %v, Avx: %v",
			result.SgxResult.SgxAttributesCheck.Initted.Success,
			result.SgxResult.SgxAttributesCheck.Debug.Success,
			result.SgxResult.SgxAttributesCheck.Mode64Bit.Success,
			result.SgxResult.SgxAttributesCheck.ProvisionKey.Success,
			result.SgxResult.SgxAttributesCheck.EInitToken.Success,
			result.SgxResult.SgxAttributesCheck.Kss.Success,
			result.SgxResult.SgxAttributesCheck.Legacy.Success,
			result.SgxResult.SgxAttributesCheck.Avx.Success,
		)
	}

	return nil
}

func getBit(data []byte, i int) bool {
	byteIndex := i / 8
	bitIndex := uint(i % 8)

	return (data[byteIndex]>>bitIndex)&1 == 1
}
