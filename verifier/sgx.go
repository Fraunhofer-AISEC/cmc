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
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/google/go-tdx-guest/pcs"
)

// Overall structure: table 2 from https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
// Endianess: Little Endian (all Integer fields)
type SgxReport struct {
	QuoteHeader           QuoteHeader
	ISVEnclaveReport      EnclaveReportBody
	QuoteSignatureDataLen uint32
	QuoteSignatureData    ECDSA256QuoteSignatureDataStructure // variable size
}

func verifySgxMeasurements(sgxM ar.Measurement, nonce []byte,
	rootManifest *ar.MetadataResult, referenceValues []ar.ReferenceValue,
) (*ar.MeasurementResult, bool) {

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
	if rootManifest == nil {
		log.Debugf("Internal error: root manifest not present")
		result.Summary.SetErr((ar.Internal))
		return result, false
	}
	sgxReferencePolicy := rootManifest.Manifest.SgxPolicy

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

	if sgxReferencePolicy == nil {
		log.Debugf("SGX manifest does not contain SGX policy")
		result.Summary.SetErr(ar.PolicyNotPresent)
		return result, false
	}

	// Extract the attestation report into the SGXReport data structure
	sgxQuote, err := DecodeSgxReport(sgxM.Evidence)
	if err != nil {
		log.Debugf("Failed to decode SGX report: %v", err)
		result.Summary.SetErr(ar.ParseEvidence)
		return result, false
	}

	if QuoteType(sgxQuote.QuoteHeader.TeeType) != SGX_QUOTE_TYPE {
		log.Debugf("Unsupported SGX quote type (tee_type: %X)\n", sgxQuote.QuoteHeader.TeeType)
		return result, false
	}

	// Compare nonce for freshness (called report data in the SNP attestation report structure)
	// ReportData contains: nonce in ReportData field
	nonce64 := make([]byte, 64)
	copy(nonce64, nonce[:])

	if cmp := bytes.Compare(sgxQuote.ISVEnclaveReport.ReportData[:], nonce64); cmp != 0 {
		log.Debugf("Nonces mismatch: Expected: %v, Got = %v", hex.EncodeToString(nonce64),
			hex.EncodeToString(sgxQuote.ISVEnclaveReport.ReportData[:]))
		result.Freshness.Success = false
		result.Freshness.Expected = hex.EncodeToString(nonce64)
		result.Freshness.Got = hex.EncodeToString(sgxQuote.ISVEnclaveReport.ReportData[:])
		result.Summary.Success = false
		return result, false
	} else {
		result.Freshness.Success = true
	}

	// Obtain collateral from measurements
	if len(sgxM.Artifacts) == 0 ||
		len(sgxM.Artifacts[0].Events) == 0 ||
		sgxM.Artifacts[0].Events[0].IntelCollateral == nil {
		log.Debugf("Could not find TDX artifacts (collateral)")
		result.Summary.SetErr(ar.CollateralNotPresent)
		return result, false
	}
	collateralRaw := sgxM.Artifacts[0].Events[0].IntelCollateral
	collateral, err := ParseCollateral(collateralRaw)
	if err != nil {
		log.Debugf("Could not parse SGX artifacts (collateral)")
		result.Summary.SetErr(ar.ParseCollateral)
		return result, false
	}

	// Extract quote PCK certificate chain. Currently only support for QECertDataType 5
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

	// Check that root CA from PCK cert chain is present in quote
	if quoteCerts.RootCACert == nil {
		log.Debugf("root cert is null")
		result.Summary.SetErr(ar.ParseCA)
		return result, false
	}

	// Match measurement root CAs against reference root CA fingerprint
	errCode := verifyRootCas(&quoteCerts, collateral, rootManifest.CaFingerprint)
	if errCode != ar.NotSet {
		result.Summary.SetErr(errCode)
		return result, false
	}

	// Parse and verify PCK certificate extensions
	sgxExtensions, err := ParseSGXExtensions(quoteCerts.PCKCert.Extensions[SGX_EXTENSION_INDEX].Value[4:]) // skip the first value (not relevant)
	if err != nil {
		log.Debugf("failed to parse SGX Extensions from PCK Certificate: %v", err)
		result.Summary.SetErr(ar.ParseExtensions)
		return result, false
	}

	// Verify TcbInfo
	result.SgxResult.TcbInfoCheck = ValidateTcbInfo(
		&collateral.TcbInfo, collateralRaw.TcbInfo,
		collateral.TcbInfoIntermediateCert, collateral.TcbInfoRootCert,
		sgxExtensions, [16]byte{}, SGX_QUOTE_TYPE)
	if !result.SgxResult.TcbInfoCheck.Summary.Success {
		log.Debugf("Failed to verify TCB info structure")
		result.Summary.SetErr(ar.VerifyTcbInfo)
		return result, false
	}

	// Verify QE Identity
	qeIdentityResult, err := ValidateQEIdentity(
		&sgxQuote.QuoteSignatureData.QEReport,
		&collateral.QeIdentity, collateralRaw.QeIdentity,
		collateral.QeIdentityIntermediateCert, collateral.QeIdentityRootCert,
		SGX_QUOTE_TYPE)
	if err != nil {
		log.Debugf("Failed to verify QE Identity structure: %v", err)
		result.Summary.SetErr(ar.VerifyQEIdentityErr)
		return result, false
	}
	result.SgxResult.QeReportCheck = qeIdentityResult

	// Verify Quote Signature
	sig, ret := VerifyIntelQuoteSignature(sgxM.Evidence, sgxQuote.QuoteSignatureData,
		sgxQuote.QuoteSignatureDataLen, int(sgxQuote.QuoteHeader.AttestationKeyType), quoteCerts,
		rootManifest.CaFingerprint, QuoteType(sgxQuote.QuoteHeader.TeeType), collateral.PckCrl, collateral.RootCaCrl)
	if !ret {
		ok = false
	}
	result.Signature = sig

	// Verify Quote Body values
	err = VerifySgxQuoteBody(&sgxQuote.ISVEnclaveReport, &collateral.TcbInfo, &sgxExtensions,
		&sgxReferenceValue, sgxReferencePolicy, result)
	if err != nil {
		log.Debugf("Failed to verify SGX Report Body: %v", err)
		result.Summary.SetErr(ar.VerifySignature)
		result.Summary.Success = false
		return result, false
	}

	// Check version
	result.SgxResult.VersionMatch, ret = verifyQuoteVersion(sgxQuote.QuoteHeader.Version, sgxReferencePolicy.QuoteVersion)
	if !ret {
		return result, false
	}

	result.Summary.Success = ok

	return result, ok
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

func VerifySgxQuoteBody(body *EnclaveReportBody, tcbInfo *pcs.TdxTcbInfo,
	sgxExtensions *SGXExtensionsValue, sgxReferenceValue *ar.ReferenceValue,
	sgxReferencePolicy *ar.SgxPolicy, result *ar.MeasurementResult,
) error {

	if tcbInfo == nil {
		return fmt.Errorf("internal error: SGX tcb info is nil")
	}
	if sgxExtensions == nil {
		return fmt.Errorf("internal error: SGX certs is nil")
	}
	if sgxReferenceValue == nil {
		return fmt.Errorf("internal error: SGX reference value is nil")
	}
	if result == nil {
		return fmt.Errorf("internal error: SGX measurement result is nil")
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
		return fmt.Errorf("MRENCLAVE mismatch. Expected: %v, Got. %v",
			hex.EncodeToString(sgxReferenceValue.Sha256), hex.EncodeToString(body.MRENCLAVE[:]))
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
			Type:     "Reference Value",
			SubType:  "MrSigner",
			Digest:   sgxReferencePolicy.MrSigner,
			Measured: hex.EncodeToString(body.MRSIGNER[:]),
			Success:  strings.EqualFold(sgxReferencePolicy.MrSigner, hex.EncodeToString(body.MRSIGNER[:])),
			Launched: true,
		},
		ar.DigestResult{
			Type:     "Reference Value",
			SubType:  "CpuSvn",
			Digest:   hex.EncodeToString(sgxExtensions.Tcb.Value.CpuSvn.Value),
			Measured: hex.EncodeToString(body.CPUSVN[:]),
			Success:  bytes.Compare(sgxExtensions.Tcb.Value.CpuSvn.Value, body.CPUSVN[:]) <= 0,
			Launched: true,
		},
		ar.DigestResult{
			Type:     "Reference Value",
			SubType:  "IsvProdId",
			Digest:   strconv.Itoa(int(sgxReferencePolicy.IsvProdId)),
			Measured: strconv.Itoa(int(body.ISVProdID)),
			Success:  sgxReferencePolicy.IsvProdId == body.ISVProdID,
			Launched: true,
		},
		ar.DigestResult{
			Type:     "Reference Value",
			SubType:  "IsvSvn",
			Digest:   strconv.Itoa(int(sgxReferencePolicy.IsvSvn)),
			Measured: strconv.Itoa(int(body.ISVSVN)),
			Success:  sgxReferencePolicy.IsvSvn == body.ISVSVN,
			Launched: true,
		},
	)

	for _, v := range result.Artifacts {
		if !v.Success {
			return fmt.Errorf("SGX Quote Body Verification failed. %v: (Expected: %v Got: %v)", v.SubType, v.Digest, v.Measured)
		}
	}

	result.SgxResult.SgxAttributesCheck = ar.SgxAttributesCheck{
		Initted: ar.BooleanMatch{
			Success:  getBit(body.Attributes[:], 0) == sgxReferencePolicy.Attributes.Initted,
			Claimed:  sgxReferencePolicy.Attributes.Initted,
			Measured: getBit(body.Attributes[:], 0),
		},
		Debug: ar.BooleanMatch{
			Success:  getBit(body.Attributes[:], 1) == sgxReferencePolicy.Attributes.Debug,
			Claimed:  sgxReferencePolicy.Attributes.Debug,
			Measured: getBit(body.Attributes[:], 1),
		},
		Mode64Bit: ar.BooleanMatch{
			Success:  getBit(body.Attributes[:], 2) == sgxReferencePolicy.Attributes.Mode64Bit,
			Claimed:  sgxReferencePolicy.Attributes.Mode64Bit,
			Measured: getBit(body.Attributes[:], 2),
		},
		ProvisionKey: ar.BooleanMatch{
			Success:  getBit(body.Attributes[:], 5) == sgxReferencePolicy.Attributes.ProvisionKey,
			Claimed:  sgxReferencePolicy.Attributes.ProvisionKey,
			Measured: getBit(body.Attributes[:], 5),
		},
		EInitToken: ar.BooleanMatch{
			Success:  getBit(body.Attributes[:], 6) == sgxReferencePolicy.Attributes.EInitToken,
			Claimed:  sgxReferencePolicy.Attributes.EInitToken,
			Measured: getBit(body.Attributes[:], 6),
		},
		Kss: ar.BooleanMatch{
			Success:  getBit(body.Attributes[:], 8) == sgxReferencePolicy.Attributes.Kss,
			Claimed:  sgxReferencePolicy.Attributes.Kss,
			Measured: getBit(body.Attributes[:], 8),
		},
		Legacy: ar.BooleanMatch{
			Success:  (body.Attributes[8] == 3) == sgxReferencePolicy.Attributes.Legacy,
			Claimed:  sgxReferencePolicy.Attributes.Legacy,
			Measured: body.Attributes[8] == 3,
		},
		Avx: ar.BooleanMatch{
			Success:  (body.Attributes[8] == 6) == sgxReferencePolicy.Attributes.Avx,
			Claimed:  sgxReferencePolicy.Attributes.Avx,
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

// (for SGX): parses quote signature data structure from buf to sig
func parseECDSASignature(buf *bytes.Buffer, sig *ECDSA256QuoteSignatureDataStructure) error {

	err := binary.Read(buf, binary.LittleEndian, &sig.ISVEnclaveReportSignature)
	if err != nil {
		return fmt.Errorf("failed to parse ISVEnclaveReportSignature")
	}
	err = binary.Read(buf, binary.LittleEndian, &sig.ECDSAAttestationKey)
	if err != nil {
		return fmt.Errorf("failed to parse ECDSAAttestationKey")
	}
	err = binary.Read(buf, binary.LittleEndian, &sig.QEReport)
	if err != nil {
		return fmt.Errorf("failed to parse QEReport")
	}
	err = binary.Read(buf, binary.LittleEndian, &sig.QEReportSignature)
	if err != nil {
		return fmt.Errorf("failed to parse QEReportSignature")
	}
	err = binary.Read(buf, binary.LittleEndian, &sig.QEAuthDataSize)
	if err != nil {
		return fmt.Errorf("failed to parse QEAuthDataSize")
	}
	tmp := make([]byte, sig.QEAuthDataSize)
	err = binary.Read(buf, binary.LittleEndian, &tmp)
	if err != nil {
		return fmt.Errorf("failed to parse QEAuthData")
	}
	sig.QEAuthData = tmp

	err = binary.Read(buf, binary.LittleEndian, &sig.QECertDataType)
	if err != nil {
		return fmt.Errorf("failed to parse QECertDataType")
	}
	err = binary.Read(buf, binary.LittleEndian, &sig.QECertDataSize)
	if err != nil {
		return fmt.Errorf("failed to parse QECertDataSize")
	}
	tmp = make([]byte, sig.QECertDataSize)
	err = binary.Read(buf, binary.LittleEndian, &tmp)
	if err != nil {
		return fmt.Errorf("failed to parse QECertData")
	}
	sig.QECertData = tmp

	return nil
}

func getBit(data []byte, i int) bool {
	byteIndex := i / 8
	bitIndex := uint(i % 8)

	return (data[byteIndex]>>bitIndex)&1 == 1
}
