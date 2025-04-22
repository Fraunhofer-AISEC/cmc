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

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/google/go-tdx-guest/pcs"
)

const NUM_TDX_MRS = 6

// TDX quote V4: Intel TDX DCAP: Quote Generation Library and Quote Verification Library Rev 0.9 p37
// A.3. Version 4 Quote Format (TDX-ECDSA, SGX-ECDSA, and SGX-EPID)
type TdxReportV4 struct {
	QuoteHeader           QuoteHeader
	QuoteBody             TdxReportBody
	QuoteSignatureDataLen uint32
	QuoteSignatureData    ECDSA256QuoteSignatureDataStructureV4 // variable size
}

// TDX quote V4: Intel TDX DCAP: Quote Generation Library and Quote Verification Library Rev 0.9 p38
// A.3.2. TD Quote Body (574 Bytes)
type TdxReportBody struct {
	TeeTcbSvn      [16]byte // Describes the TCB of TDX
	MrSeam         [48]byte // Measurement of the TDX Module
	MrSignerSeam   [48]byte // Zero for the Intel TDX Module.
	SeamAttributes [8]byte  // Must be zero for TDX 1.0
	TdAttributes   [8]byte
	XFAM           [8]byte
	MrTd           [48]byte // Measurements of the initial contents of the TD
	MrConfigId     [48]byte
	MrOwner        [48]byte
	MrOwnerConfig  [48]byte
	RtMr0          [48]byte
	RtMr1          [48]byte
	RtMr2          [48]byte
	RtMr3          [48]byte
	ReportData     [64]byte
}

// TDX quote V4: Intel TDX DCAP: Quote Generation Library and Quote Verification Library Rev 0.9 p41
// A.3.8. ECDSA 256-bit Quote Signature Data Structure - Version 4
type ECDSA256QuoteSignatureDataStructureV4 struct {
	QuoteSignature      [64]byte
	ECDSAAttestationKey [64]byte
	QECertificationData QECertificationData
}

// TDX quote V4: Intel TDX DCAP: Quote Generation Library and Quote Verification Library Rev 0.9 p42
// A.3.9. QE Certification Data - Version 4
type QECertificationData struct {
	QECertificationDataType   uint16 // Type 6 (QEReportCertDataV4)
	Size                      uint32
	QEReportCertificationData QEReportCertificationData // Only in case of type 6
}

// TDX quote V4: Intel TDX DCAP: Quote Generation Library and Quote Verification Library Rev 0.9 p44
// A.3.11. QE Report Certification Data
type QEReportCertificationData struct {
	QEReport          EnclaveReportBody
	QEReportSignature [64]byte
	QEAuthDataSize    uint16          // A3.7 QE Authentication Data
	QEAuthData        []byte          // A3.7 QE Authentication Data
	QECertDataType    uint16          // A3.9 QE Certification Data: Type 5 (PCK Cert Chain)
	QECertDataSize    uint32          // A3.9 QE Certification Data
	PCKCertChain      SgxCertificates // A3.9 QE Certification Data: Type 5 (PCK Cert Chain)
}

func verifyTdxMeasurements(measurement ar.Measurement, nonce []byte, rootManifest *ar.MetadataResult,
	referenceValues []ar.ReferenceValue) (*ar.MeasurementResult, bool) {

	log.Debug("Verifying TDX measurements")

	var err error
	result := &ar.MeasurementResult{
		Type:      "TDX Result",
		TdxResult: &ar.TdxResult{},
	}
	ok := true

	if len(referenceValues) == 0 {
		log.Debugf("Could not find TDX reference values")
		result.Summary.SetErr(ar.RefValNotPresent)
		return result, false
	}
	if rootManifest == nil {
		log.Debugf("Internal error: root manifest not present")
		result.Summary.SetErr((ar.Internal))
		return result, false
	}
	tdxPolicy := rootManifest.TdxPolicy
	if tdxPolicy == nil {
		log.Debugf("TDX manifest does not contain TDX policy")
		result.Summary.SetErr(ar.PolicyNotPresent)
		return result, false
	}

	// Parse intel collateral (QE identity, TCB info, certificate revocation lists)
	if len(measurement.Artifacts) == 0 ||
		len(measurement.Artifacts[0].Events) == 0 ||
		measurement.Artifacts[0].Events[0].IntelCollateral == nil {
		log.Debugf("Could not find TDX artifacts (collateral)")
		result.Summary.SetErr(ar.CollateralNotPresent)
		return result, false
	}
	collateralRaw := measurement.Artifacts[0].Events[0].IntelCollateral
	collateral, err := ParseCollateral(collateralRaw)
	if err != nil {
		log.Debugf("Could not parse TDX artifacts (collateral)")
		result.Summary.SetErr(ar.ParseCollateral)
		return result, false
	}

	// Currently only support for report version 4
	tdxQuote, err := DecodeTdxReportV4(measurement.Evidence)
	if err != nil {
		log.Debugf("Failed to decode TDX report: %v", err)
		result.Summary.SetErr(ar.ParseEvidence)
		return result, false
	}

	// Compare nonce for freshness (called report data in the TDX attestation report structure)
	nonce64 := make([]byte, 64)
	copy(nonce64, nonce)
	if !bytes.Equal(tdxQuote.QuoteBody.ReportData[:], nonce64) {
		log.Debugf("Nonces mismatch: Supplied Nonce = %v, Nonce in TDX Report = %v)",
			hex.EncodeToString(nonce), hex.EncodeToString(tdxQuote.QuoteBody.ReportData[:]))
		result.Freshness.Success = false
		result.Freshness.Expected = hex.EncodeToString(nonce)
		result.Freshness.Got = hex.EncodeToString(tdxQuote.QuoteBody.ReportData[:])
		ok = false
		return result, ok
	} else {
		result.Freshness.Success = true
	}

	// Extract certificate chain from quote
	var quoteCerts SgxCertificates = tdxQuote.QuoteSignatureData.QECertificationData.QEReportCertificationData.PCKCertChain
	if quoteCerts.RootCACert == nil || quoteCerts.IntermediateCert == nil || quoteCerts.PCKCert == nil {
		log.Debugf("incomplete certificate chain")
		result.Summary.SetErr(ar.VerifyCertChain)
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
		result.Summary.SetErr(ar.ParseCert)
		return result, false
	}

	// Verify TCB info
	result.TdxResult.TcbInfoCheck = ValidateTcbInfo(
		&collateral.TcbInfo, collateralRaw.TcbInfo,
		collateral.TcbInfoIntermediateCert, collateral.TcbInfoRootCert,
		sgxExtensions, tdxQuote.QuoteBody.TeeTcbSvn, TDX_QUOTE_TYPE)
	if !result.TdxResult.TcbInfoCheck.Summary.Success {
		log.Debugf("Failed to validate TCB info")
		result.Summary.SetErr(ar.VerifyTcbInfo)
		return result, false
	}

	// Verify Quoting Enclave Identity
	qeIdentityResult, err := ValidateQEIdentity(
		&tdxQuote.QuoteSignatureData.QECertificationData.QEReportCertificationData.QEReport,
		&collateral.QeIdentity, collateralRaw.QeIdentity,
		collateral.QeIdentityIntermediateCert, collateral.QeIdentityRootCert,
		TDX_QUOTE_TYPE)
	result.TdxResult.QeReportCheck = qeIdentityResult
	if err != nil {
		log.Debugf("Failed to validate QE Identity: %v", err)
		result.Summary.SetErr(ar.VerifyQEIdentityErr)
		return result, false
	}

	// Verify Quote Signature including certificate chains and CRLs
	sig, ret := VerifyIntelQuoteSignature(measurement.Evidence, tdxQuote.QuoteSignatureData,
		tdxQuote.QuoteSignatureDataLen, int(tdxQuote.QuoteHeader.AttestationKeyType), quoteCerts,
		rootManifest.CaFingerprint, TDX_QUOTE_TYPE, collateral.PckCrl, collateral.RootCaCrl)
	if !ret {
		log.Debug("Failed to verify Intel quote signature")
		ok = false
	}
	result.Signature = sig

	// Verify the measurement registers (MRTD, RTMRs) against the reference values
	mrResults, detailedResults, errCode, ok := verifyTdxMrs(&tdxQuote.QuoteBody, referenceValues)
	if errCode != ar.NotSet || !ok {
		log.Debugf("Failed to recalculate measurement registers")
		ok = false
		result.Summary.SetErr(errCode)
	} else {
		log.Tracef("Successfully recalculated TDX MRs")
	}
	result.TdxResult.MrMatch = mrResults
	result.Artifacts = append(result.Artifacts, detailedResults...)

	// TODO verify MRSEAM

	tdIdResults, okTdId := verifyTdxTdId(&tdxQuote.QuoteBody, &tdxPolicy.TdId, &collateral.TcbInfo)
	if !okTdId {
		log.Debugf("Failed to verify TDX TD ID")
		ok = false
	}
	result.Artifacts = append(result.Artifacts, tdIdResults...)

	result.TdxResult.XfamCheck = verifyTdxXfam(tdxQuote.QuoteBody.XFAM[:], tdxPolicy.Xfam)
	if !result.TdxResult.XfamCheck.Success {
		log.Debugf("TDX XFAM check failed")
		ok = false
	}

	result.TdxResult.SeamAttributesCheck = verifyTdxSeamAttributes(tdxQuote.QuoteBody.SeamAttributes[:])
	if !result.TdxResult.SeamAttributesCheck.Success {
		log.Debugf("TDX SEAM attributes check failed")
		ok = false
	}

	// Verify Quote Body values against reference TDX policy
	var okTdAttr bool
	result.TdxResult.TdAttributesCheck, okTdAttr = verifyTdxTdAttributes(tdxQuote.QuoteBody.TdAttributes, &tdxPolicy.TdAttributes)
	if !okTdAttr {
		log.Debugf("TDX TD Attributes check failed")
		ok = false
	}

	// Check version
	result.TdxResult.VersionMatch, ret = verifyQuoteVersion(tdxQuote.QuoteHeader.Version, tdxPolicy.QuoteVersion)
	if !ret {
		return result, false
	}
	log.Tracef("Successfully validated TDX quote version")

	if ok {
		log.Debug("Successfully verified TDX measurements")
	} else {
		log.Debug("Failed to verify TDX measurements")
	}

	result.Summary.Success = ok

	return result, ok
}

// Parses the report into the TDReport structure
func DecodeTdxReportV4(report []byte) (TdxReportV4, error) {
	var reportStruct TdxReportV4
	var header QuoteHeader
	var body TdxReportBody
	var sig ECDSA256QuoteSignatureDataStructureV4
	var sigLen uint32

	// parse header
	buf := bytes.NewBuffer(report)
	err := binary.Read(buf, binary.LittleEndian, &header)
	if err != nil {
		return TdxReportV4{}, fmt.Errorf("failed to decode TD report header: %v", err)
	}

	if header.Version != uint16(4) {
		return TdxReportV4{}, fmt.Errorf("unsupported Quote version %v. Only  v4 is supported", header.Version)
	}
	log.Tracef("Decoding TDX quote header version 4")

	// parse body
	err = binary.Read(buf, binary.LittleEndian, &body)
	if err != nil {
		return TdxReportV4{}, fmt.Errorf("failed to decode TD report body: %v", err)
	}

	// parse signature size
	err = binary.Read(buf, binary.LittleEndian, &sigLen)
	if err != nil {
		return TdxReportV4{}, fmt.Errorf("failed to decode TD report QuoteSignatureDataLen: %v", err)
	}

	// parse signature
	err = parseECDSAQuoteSignatureDataStructV4(buf, &sig)
	if err != nil {
		return TdxReportV4{}, fmt.Errorf("failed to decode TD report QuoteSignatureData: %v", err)
	}

	// compose the final report struct
	reportStruct.QuoteHeader = header
	reportStruct.QuoteBody = body
	reportStruct.QuoteSignatureDataLen = sigLen
	reportStruct.QuoteSignatureData = sig

	return reportStruct, nil
}

// parse the full quote signature data structure (V4) from buf to sig
func parseECDSAQuoteSignatureDataStructV4(buf *bytes.Buffer, quoteSigStruct *ECDSA256QuoteSignatureDataStructureV4) error {

	err := binary.Read(buf, binary.LittleEndian, &quoteSigStruct.QuoteSignature)
	if err != nil {
		return fmt.Errorf("failed to parse QuoteSignature")
	}
	err = binary.Read(buf, binary.LittleEndian, &quoteSigStruct.ECDSAAttestationKey)
	if err != nil {
		return fmt.Errorf("failed to parse ECDSAAttestationKey")
	}
	err = binary.Read(buf, binary.LittleEndian, &quoteSigStruct.QECertificationData.QECertificationDataType)
	if err != nil {
		return fmt.Errorf("failed to parse QECertDataType")
	}
	err = binary.Read(buf, binary.LittleEndian, &quoteSigStruct.QECertificationData.Size)
	if err != nil {
		return fmt.Errorf("failed to parse QECertDataSize")
	}

	// QE Certification Data Type 6: QE Report Certification Data (outer type)
	if quoteSigStruct.QECertificationData.QECertificationDataType != uint16(6) {
		return fmt.Errorf("unsupported QE certification data type %v (expected type 6: QE Report Certification Data)",
			quoteSigStruct.QECertificationData.QECertificationDataType)
	}
	log.Trace("QE certification data type: 6 (QE Report Certification Data)")

	rawData := make([]byte, quoteSigStruct.QECertificationData.Size)
	err = binary.Read(buf, binary.LittleEndian, &rawData)
	if err != nil {
		return fmt.Errorf("failed to parse QECertData")
	}

	// parse QEReportCertDataV4
	buf = bytes.NewBuffer(rawData)
	err = binary.Read(buf, binary.LittleEndian, &quoteSigStruct.QECertificationData.QEReportCertificationData.QEReport)
	if err != nil {
		return fmt.Errorf("failed to parse QE Report: %v", err)
	}

	err = binary.Read(buf, binary.LittleEndian, &quoteSigStruct.QECertificationData.QEReportCertificationData.QEReportSignature)
	if err != nil {
		return fmt.Errorf("failed to parse QE Report Signature: %v", err)
	}

	err = binary.Read(buf, binary.LittleEndian, &quoteSigStruct.QECertificationData.QEReportCertificationData.QEAuthDataSize)
	if err != nil {
		return fmt.Errorf("failed to parse QE Authentication Data Size: %v", err)
	}

	tmp := make([]byte, quoteSigStruct.QECertificationData.QEReportCertificationData.QEAuthDataSize)
	err = binary.Read(buf, binary.LittleEndian, &tmp)
	if err != nil {
		return fmt.Errorf("failed to parse QE Authentication Data: %v", err)
	}
	quoteSigStruct.QECertificationData.QEReportCertificationData.QEAuthData = tmp

	// QE Report Certification Data Type 5: PCK Cert Chain
	err = binary.Read(buf, binary.LittleEndian, &quoteSigStruct.QECertificationData.QEReportCertificationData.QECertDataType)
	if err != nil {
		return fmt.Errorf("failed to parse QE Certification Data Type: %v", err)
	}
	if quoteSigStruct.QECertificationData.QEReportCertificationData.QECertDataType != 5 {
		return fmt.Errorf("wrong QECertDataType. Expected: 5, Got: %v", quoteSigStruct.QECertificationData.QEReportCertificationData.QECertDataType)
	}
	log.Tracef("QE report certifiation data type: 5 (Concatenated PCK Cert Chain)")

	err = binary.Read(buf, binary.LittleEndian, &quoteSigStruct.QECertificationData.QEReportCertificationData.QECertDataSize)
	if err != nil {
		return fmt.Errorf("failed to parse QE Certification Data Size: %v", err)
	}

	// parse QE Certification Data (Raw)
	tmp = make([]byte, quoteSigStruct.QECertificationData.QEReportCertificationData.QECertDataSize)
	err = binary.Read(buf, binary.LittleEndian, &tmp)
	if err != nil {
		return fmt.Errorf("failed to parse QE Certification Data: %v", err)
	}

	// parse PCK Cert Chain (PCK Leaf Cert || Intermediate CA Cert || Root CA Cert)
	log.Trace("Parsing measurement certificate chain from report..")
	certChain, err := ParseCertificates(tmp[:], true)
	if err != nil {
		return fmt.Errorf("failed to parse certificate chain from QECertData: %v", err)
	}
	quoteSigStruct.QECertificationData.QEReportCertificationData.PCKCertChain = certChain

	return nil
}

// verifyTdxMrs recalculates the TDX measurement registers based on the reference values
// and compares them with the measurements. For the MR index, the function uses the mapping
// according to UEFI Spec 2.10 Section 38.4.1:
// CC MR Index | TDX register
// 0           | MRTD
// 1           | RTMR0
// 2           | RTMR1
// 3           | RTMR2
// 4           | RTMR3
// 5           | MRSEAM (not in UEFI spec)
func verifyTdxMrs(body *TdxReportBody, refvals []ar.ReferenceValue) ([]ar.DigestResult, []ar.DigestResult, ar.ErrorCode, bool) {

	success := true
	detailedResults := make([]ar.DigestResult, 0)
	mrResults := make([]ar.DigestResult, 0, NUM_TDX_MRS)

	// Recalculate the expected MR values based on the reference values
	calculatedMrs := make([][]byte, NUM_TDX_MRS)
	for i := 0; i < NUM_TDX_MRS; i++ {
		calculatedMrs[i] = make([]byte, 48)
	}
	for _, refval := range refvals {
		if refval.Index >= NUM_TDX_MRS {
			return nil, nil, ar.IllegalTdxMrIndex, false
		}
		if refval.Index == 0 || refval.Index == 5 {
			// MRTD and MRSEAM are not extended
			copy(calculatedMrs[refval.Index], refval.Sha384)
		} else {
			// RTMRs are extended
			calculatedMrs[refval.Index] = internal.ExtendSha384(calculatedMrs[refval.Index], refval.Sha384)
			log.Tracef("Extended %v: %v = %v", internal.IndexToMr(refval.Index), refval.SubType,
				hex.EncodeToString(refval.Sha384))
		}
	}

	measuredMrs := [][]byte{
		body.MrTd[:],
		body.RtMr0[:],
		body.RtMr1[:],
		body.RtMr2[:],
		body.RtMr3[:],
		body.MrSeam[:],
	}

	successMrs := make([]bool, NUM_TDX_MRS)

	// Verify the calculated MR values against the quote body MR values
	for i := 0; i < NUM_TDX_MRS; i++ {

		successMrs[i] = bytes.Equal(calculatedMrs[i], measuredMrs[i])
		if !successMrs[i] {
			success = false
			detailedResults = append(detailedResults,
				ar.DigestResult{
					Type:     "Measurement",
					Digest:   hex.EncodeToString(measuredMrs[i]),
					Index:    i,
					Success:  false,
					Launched: true,
				})
			log.Debugf("%v: Measurement %q does not match reference %q",
				internal.IndexToMr(i),
				hex.EncodeToString(measuredMrs[i]), hex.EncodeToString(calculatedMrs[i]))
		} else {
			log.Tracef("%v: Measurement %q does match reference", internal.IndexToMr(i),
				hex.EncodeToString(measuredMrs[i]))
		}

		// Measurement register summary
		mrResults = append(mrResults, ar.DigestResult{
			Index:    i,
			SubType:  internal.IndexToMr(i),
			Success:  successMrs[i],
			Digest:   hex.EncodeToString(calculatedMrs[i]),
			Measured: hex.EncodeToString(measuredMrs[i]),
		})
	}

	// Without the CC eventlog, we cannot display, which individual measurements
	// did not match. Instead, we set all reference values of a certain MR to false in case the
	// comparison of the recalculated MR with the measured MR fails
	for _, refval := range refvals {
		detailedResults = append(detailedResults,
			ar.DigestResult{
				Type:        "Reference Value",
				SubType:     refval.SubType,
				Index:       refval.Index,
				Digest:      hex.EncodeToString(refval.Sha384),
				Success:     successMrs[refval.Index],
				Launched:    successMrs[refval.Index],
				Description: refval.Description,
			})
	}

	return mrResults, detailedResults, ar.NotSet, success
}

func verifyTdxTdId(report *TdxReportBody, refTdId *ar.TDId, tcbInfo *pcs.TdxTcbInfo) ([]ar.DigestResult, bool) {

	tdIdSuccess := true
	results := make([]ar.DigestResult, 0, 3)

	// Verify MROWNER
	success := bytes.Equal(refTdId.MrOwner[:], report.MrOwner[:])
	results = append(results, ar.DigestResult{
		Type:     "Reference Value",
		SubType:  "MrOwner",
		Digest:   hex.EncodeToString(refTdId.MrOwner),
		Success:  success,
		Launched: success,
	})
	if !success {
		tdIdSuccess = false
		results = append(results, ar.DigestResult{
			Type:     "Measurement",
			SubType:  "MROWNER",
			Digest:   hex.EncodeToString(report.MrOwner[:]),
			Success:  false,
			Launched: false,
		})
	}

	// Verify MROWNERCONFIG
	success = bytes.Equal(refTdId.MrOwnerConfig[:], report.MrOwnerConfig[:])
	results = append(results, ar.DigestResult{
		Type:     "Reference Value",
		SubType:  "MROWNERCONFIG",
		Digest:   hex.EncodeToString(refTdId.MrOwnerConfig),
		Success:  success,
		Launched: success,
	})
	if !success {
		tdIdSuccess = false
		results = append(results, ar.DigestResult{
			Type:     "Measurement",
			SubType:  "MROWNERCONFIG",
			Digest:   hex.EncodeToString(report.MrOwnerConfig[:]),
			Success:  false,
			Launched: false,
		})
	}

	// Verify MRCONFIGID
	success = bytes.Equal(refTdId.MrConfigId[:], report.MrConfigId[:])
	results = append(results, ar.DigestResult{
		Type:     "Reference Value",
		SubType:  "MRCONFIGID",
		Digest:   hex.EncodeToString(refTdId.MrConfigId),
		Success:  success,
		Launched: success,
	})
	if !success {
		tdIdSuccess = false
		results = append(results, ar.DigestResult{
			Type:     "Measurement",
			SubType:  "MRCONFIGID",
			Digest:   hex.EncodeToString(report.MrConfigId[:]),
			Success:  false,
			Launched: false,
		})
	}

	// Verify MRSIGNERSEAM
	success = bytes.Equal(tcbInfo.TcbInfo.TdxModule.Mrsigner.Bytes, report.MrSignerSeam[:])
	results = append(results, ar.DigestResult{
		Type:     "Reference Value",
		SubType:  "MRSIGNERSEAM",
		Digest:   hex.EncodeToString(tcbInfo.TcbInfo.TdxModule.Mrsigner.Bytes),
		Success:  success,
		Launched: success,
	})
	if !success {
		tdIdSuccess = false
		results = append(results, ar.DigestResult{
			Type:     "Measurement",
			SubType:  "MRSIGNERSEAM",
			Digest:   hex.EncodeToString(report.MrSignerSeam[:]),
			Success:  false,
			Launched: false,
		})
	}

	return results, tdIdSuccess
}

func verifyTdxXfam(measured, reference []byte) ar.Result {
	success := bytes.Equal(measured, reference)
	result := ar.Result{
		Success:  success,
		Got:      hex.EncodeToString(measured),
		Expected: hex.EncodeToString(reference),
	}
	return result
}

func verifyTdxSeamAttributes(measured []byte) ar.Result {

	// Intel TDX DCAP Quote Generation Library and Quote Verification Library p38:
	// SeamAttributes must be zero for Intel TDX 1.0
	refAttributes := make([]byte, 8)
	success := bytes.Equal(measured, refAttributes)
	result := ar.Result{
		Success:  success,
		Got:      hex.EncodeToString(measured),
		Expected: hex.EncodeToString(refAttributes),
	}
	return result
}

func verifyTdxTdAttributes(measuredAttributes [8]byte, refTdAttributes *ar.TDAttributes) (ar.TdAttributesCheck, bool) {

	result := ar.TdAttributesCheck{
		Debug: ar.BooleanMatch{
			Success:  refTdAttributes.Debug == (measuredAttributes[0] > 0),
			Claimed:  refTdAttributes.Debug,
			Measured: measuredAttributes[0] > 0,
		},
		SeptVEDisable: ar.BooleanMatch{
			Success:  refTdAttributes.SeptVEDisable == getBit(measuredAttributes[:], 28),
			Claimed:  refTdAttributes.SeptVEDisable,
			Measured: getBit(measuredAttributes[:], 28),
		},
		Pks: ar.BooleanMatch{
			Success:  refTdAttributes.Pks == getBit(measuredAttributes[:], 30),
			Claimed:  refTdAttributes.Pks,
			Measured: getBit(measuredAttributes[:], 30),
		},
		Kl: ar.BooleanMatch{
			Success:  refTdAttributes.Kl == getBit(measuredAttributes[:], 31),
			Claimed:  refTdAttributes.Kl,
			Measured: getBit(measuredAttributes[:], 31),
		},
	}
	ok := result.Debug.Success &&
		result.SeptVEDisable.Success &&
		result.Pks.Success &&
		result.Kl.Success

	log.Tracef("TDX Attribute 'Debug' reference: %v, measurement: %v",
		refTdAttributes.Debug, measuredAttributes[0] > 0)

	log.Tracef("TDX Attribute 'EPT violation conversion disabled' reference: %v, measurement: %v",
		refTdAttributes.SeptVEDisable, getBit(measuredAttributes[:], 28))

	log.Tracef("TDX Attribute 'Protection Kes (PKS) Enabled' reference: %v, measurement: %v",
		refTdAttributes.Pks, getBit(measuredAttributes[:], 30))

	log.Tracef("TDX Attribute 'Key Locker (KL) Enabled' reference: %v, measurement: %v",
		refTdAttributes.Kl, getBit(measuredAttributes[:], 31))

	return result, ok
}
