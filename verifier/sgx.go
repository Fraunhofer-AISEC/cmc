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

package verifier

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
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

func verifySgxMeasurements(sgxM ar.Measurement, nonce []byte, intelCache string, referenceValues []ar.ReferenceValue) (*ar.MeasurementResult, bool) {

	var err error
	result := &ar.MeasurementResult{
		Type:      "SGX Result",
		SgxResult: &ar.SgxResult{},
	}
	ok := true

	log.Debug("Verifying SGX measurements")

	if len(referenceValues) == 0 {
		log.Debugf("Could not find SGX Reference Value")
		result.Summary.SetErr(ar.RefValNotPresent)
		return result, false
	} else if len(referenceValues) > 1 {
		log.Debugf("Report contains %v reference values. Currently, only one SGX Reference Value is supported",
			len(referenceValues))
		result.Summary.SetErr(ar.RefValMultiple)
		return result, false
	}
	sgxReferenceValue := referenceValues[0]

	// Validate Parameters:
	if len(sgxM.Evidence) < SGX_QUOTE_MIN_SIZE {
		log.Debugf("Invalid SGX Report")
		result.Summary.SetErr(ar.ParseEvidence)
		return result, false
	}

	if sgxReferenceValue.Type != "SGX Reference Value" {
		log.Debugf("SGX Reference Value invalid type %v", sgxReferenceValue.Type)
		result.Summary.SetErr(ar.RefValType)
		return result, false
	}

	if sgxReferenceValue.Sgx == nil {
		log.Debugf("SGX Reference Value details not present")
		result.Summary.SetErr(ar.DetailsNotPresent)
		return result, false
	}

	var sgxQuote SgxReport
	var quoteType uint32 = sgxReferenceValue.Sgx.Collateral.TeeType
	if quoteType == SGX_QUOTE_TYPE {
		// extract the attestation report into the SGXReport data structure
		sgxQuote, err = DecodeSgxReport(sgxM.Evidence)
		if err != nil {
			log.Debugf("Failed to decode SGX report: %v", err)
			result.Summary.SetErr(ar.ParseEvidence)
			return result, false
		}
	} else {
		log.Debugf("Unknown quote type (tee_type: %X)\n", quoteType)
		return result, false
	}

	// Compare nonce for freshness (called report data in the SNP attestation report structure)
	// ReportData contains: nonce in ReportData field
	nonce64 := make([]byte, 64)
	copy(nonce64, nonce[:])

	if cmp := bytes.Compare(sgxQuote.ISVEnclaveReport.ReportData[:], nonce64); cmp != 0 {
		log.Debugf("Nonces mismatch: Plain Nonce: %v, Expected: %v, Got = %v",
			nonce, hex.EncodeToString(nonce64),
			hex.EncodeToString(sgxQuote.ISVEnclaveReport.ReportData[:]))
		result.Freshness.Success = false
		result.Freshness.Expected = hex.EncodeToString(nonce64)
		result.Freshness.Got = hex.EncodeToString(sgxQuote.ISVEnclaveReport.ReportData[:])
		result.Summary.Success = false
		return result, false
	} else {
		result.Freshness.Success = true
	}

	// Parse certificate chain
	referenceCerts, err := parseCertificates(sgxM.Certs, true)
	if err != nil {
		log.Debugf("Failed to parse reference certificates: %v", err)
		result.Summary.SetErr(ar.ParseCert)
		return result, false
	}

	// Currently only support for QECertDataType 5
	var quoteCerts SgxCertificates
	if sgxQuote.QuoteSignatureData.QECertDataType == 5 {
		quoteCerts, err = parseCertificates(sgxQuote.QuoteSignatureData.QECertData, true)
		if err != nil {
			log.Debugf("Failed to parse certificate chain from QECertData: %v", err)
			result.Summary.SetErr(ar.ParseCert)
			return result, false
		}
	} else {
		log.Debugf("QECertDataType not supported: %v", sgxQuote.QuoteSignatureData.QECertDataType)
		result.Summary.SetErr(ar.ParseCert)
		return result, false
	}

	// Extract root CA from PCK cert chain in quote -> compare nullptr
	if quoteCerts.RootCACert == nil {
		log.Debugf("root cert is null")
		result.Summary.SetErr(ar.ParseCA)
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
		log.Debugf("root cert public key didn't match")
		result.Summary.SetErr(ar.CaFingerprint)
		return result, false
	}

	// Parse and verify PCK certificate extensions
	sgxExtensions, err := ParseSGXExtensions(quoteCerts.PCKCert.Extensions[SGX_EXTENSION_INDEX].Value[4:]) // skip the first value (not relevant)
	if err != nil {
		log.Debugf("failed to parse SGX Extensions from PCK Certificate: %v", err)
		result.Summary.SetErr(ar.ParseExtensions)
		return result, false
	}

	// Parse and verify TcbInfo object
	tcbInfo, err := parseTcbInfo(sgxReferenceValue.Sgx.Collateral.TcbInfo)
	if err != nil {
		log.Debugf("Failed to parse tcbInfo: %v", err)
		result.Summary.SetErr(ar.ParseTcbInfo)
		return result, false
	}

	result.SgxResult.TcbInfoCheck = verifyTcbInfo(&tcbInfo,
		string(sgxReferenceValue.Sgx.Collateral.TcbInfo),
		referenceCerts.TCBSigningCert, sgxExtensions, [16]byte{}, SGX_QUOTE_TYPE)
	if !result.SgxResult.TcbInfoCheck.Summary.Success {
		log.Debugf("Failed to verify TCB info structure: %v", err)
		result.Summary.SetErr(ar.VerifyTcbInfo)
		return result, false
	}

	// Parse and verify QE Identity object
	qeIdentity, err := parseQEIdentity(sgxReferenceValue.Sgx.Collateral.QeIdentity)
	if err != nil {
		log.Debugf("Failed to parse QE identity: %v", err)
		result.Summary.SetErr(ar.ParseQEIdentity)
		return result, false
	}

	qeIdentityResult, err := VerifyQEIdentity(&sgxQuote.QuoteSignatureData.QEReport, &qeIdentity,
		string(sgxReferenceValue.Sgx.Collateral.QeIdentity), referenceCerts.TCBSigningCert, SGX_QUOTE_TYPE)
	if err != nil {
		log.Debugf("Failed to verify QE Identity structure: %v", err)
		result.Summary.SetErr(ar.VerifyQEIdentityErr)
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
		log.Debugf("Failed to verify SGX Report Body: %v", err)
		result.Summary.SetErr(ar.VerifySignature)
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
	sgxExtensions *SGXExtensionsValue, sgxReferenceValue *ar.ReferenceValue, result *ar.MeasurementResult) error {
	if body == nil || tcbInfo == nil || sgxExtensions == nil || sgxReferenceValue == nil || result == nil {
		return fmt.Errorf("invalid function parameter (null pointer exception)")
	}

	// check MRENCLAVE reference value
	if !bytes.Equal(body.MRENCLAVE[:], []byte(sgxReferenceValue.Sha256)) {
		result.Artifacts = append(result.Artifacts,
			ar.DigestResult{
				Type:     "Reference Value",
				SubType:  sgxReferenceValue.SubType,
				Digest:   hex.EncodeToString(sgxReferenceValue.Sha256[:]),
				Success:  false,
				Launched: false,
			})
		result.Artifacts = append(result.Artifacts,
			ar.DigestResult{
				Type:     "Measurement",
				SubType:  sgxReferenceValue.SubType,
				Digest:   hex.EncodeToString(body.MRENCLAVE[:]),
				Success:  false,
				Launched: false,
			})
		return fmt.Errorf("MRENCLAVE mismatch. Expected: %v, Got. %v", sgxReferenceValue.Sha256, body.MRENCLAVE)
	} else {
		result.Artifacts = append(result.Artifacts,
			ar.DigestResult{
				Type:     "Measurement",
				SubType:  sgxReferenceValue.SubType,
				Digest:   hex.EncodeToString(body.MRENCLAVE[:]),
				Success:  true,
				Launched: true,
			})
	}

	result.Artifacts = append(result.Artifacts,
		ar.DigestResult{
			Type:     "Measurement",
			SubType:  "MrSigner",
			Digest:   hex.EncodeToString(body.MRSIGNER[:]),
			Success:  strings.EqualFold(sgxReferenceValue.Sgx.MrSigner, hex.EncodeToString(body.MRSIGNER[:])),
			Launched: true,
		},
		ar.DigestResult{
			Type:     "Security Version",
			SubType:  "CpuSvn",
			Digest:   hex.EncodeToString(body.CPUSVN[:]),
			Success:  bytes.Compare(sgxExtensions.Tcb.Value.CpuSvn.Value, body.CPUSVN[:]) <= 0,
			Launched: true,
		},
		ar.DigestResult{
			Type:     "Product ID",
			SubType:  "IsvProdId",
			Digest:   strconv.Itoa(int(body.ISVProdID)),
			Success:  sgxReferenceValue.Sgx.IsvProdId == body.ISVProdID,
			Launched: true,
		},
		ar.DigestResult{
			Type:     "Security Version",
			SubType:  "IsvSvn",
			Digest:   strconv.Itoa(int(body.ISVSVN)),
			Success:  sgxReferenceValue.Sgx.IsvSvn == body.ISVSVN,
			Launched: true,
		},
	)

	for _, v := range result.Artifacts {
		if !v.Success {
			return fmt.Errorf("SGX Quote Body Verification failed. %v: (Got: %v)", v.SubType, v.Digest)
		}
	}

	result.SgxResult.SgxAttributesCheck = ar.SgxAttributesCheck{
		Initted: ar.BooleanMatch{
			Success:  getBit(body.Attributes[:], 0) == sgxReferenceValue.Sgx.Attributes.Initted,
			Claimed:  sgxReferenceValue.Sgx.Attributes.Initted,
			Measured: getBit(body.Attributes[:], 0),
		},
		Debug: ar.BooleanMatch{
			Success:  getBit(body.Attributes[:], 1) == sgxReferenceValue.Sgx.Attributes.Debug,
			Claimed:  sgxReferenceValue.Sgx.Attributes.Debug,
			Measured: getBit(body.Attributes[:], 1),
		},
		Mode64Bit: ar.BooleanMatch{
			Success:  getBit(body.Attributes[:], 2) == sgxReferenceValue.Sgx.Attributes.Mode64Bit,
			Claimed:  sgxReferenceValue.Sgx.Attributes.Mode64Bit,
			Measured: getBit(body.Attributes[:], 2),
		},
		ProvisionKey: ar.BooleanMatch{
			Success:  getBit(body.Attributes[:], 5) == sgxReferenceValue.Sgx.Attributes.ProvisionKey,
			Claimed:  sgxReferenceValue.Sgx.Attributes.ProvisionKey,
			Measured: getBit(body.Attributes[:], 5),
		},
		EInitToken: ar.BooleanMatch{
			Success:  getBit(body.Attributes[:], 6) == sgxReferenceValue.Sgx.Attributes.EInitToken,
			Claimed:  sgxReferenceValue.Sgx.Attributes.EInitToken,
			Measured: getBit(body.Attributes[:], 6),
		},
		Kss: ar.BooleanMatch{
			Success:  getBit(body.Attributes[:], 8) == sgxReferenceValue.Sgx.Attributes.Kss,
			Claimed:  sgxReferenceValue.Sgx.Attributes.Kss,
			Measured: getBit(body.Attributes[:], 8),
		},
		Legacy: ar.BooleanMatch{
			Success:  (body.Attributes[8] == 3) == sgxReferenceValue.Sgx.Attributes.Legacy,
			Claimed:  sgxReferenceValue.Sgx.Attributes.Legacy,
			Measured: body.Attributes[8] == 3,
		},
		Avx: ar.BooleanMatch{
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
