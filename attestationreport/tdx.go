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
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// TDX Report V4
type TdxReportV4 struct {
	QuoteHeader           QuoteHeader
	QuoteBody             TdxReportBody
	QuoteSignatureDataLen uint32
	QuoteSignatureData    ECDSA256QuoteSignatureDataStructureV4 // variable size
}

// TDX 1.0: 584 bytes
type TdxReportBody struct {
	TeeTcbSvn      [16]byte
	MrSeam         [48]byte
	MrSignerSeam   [48]byte
	SeamAttributes [8]byte
	TdAttributes   [8]byte
	XFAM           [8]byte
	MrTd           [48]byte
	MrConfigId     [48]byte
	MrOwner        [48]byte
	MrOwnerConfig  [48]byte
	RtMr0          [48]byte
	RtMr1          [48]byte
	RtMr2          [48]byte
	RtMr3          [48]byte
	ReportData     [64]byte
}

// Quote Signature for TDX, contains QE Certification Data version 4
type ECDSA256QuoteSignatureDataStructureV4 struct {
	QuoteSignature      [64]byte
	ECDSAAttestationKey [64]byte
	QECertDataType      uint16
	QECertDataSize      uint32
	QECertData          QEReportCertDataV4 // Version 4
}

// This is the datastructure of QECertDataType 6
type QEReportCertDataV4 struct {
	QEReport          EnclaveReportBody
	QEReportSignature [64]byte
	QEAuthDataSize    uint16
	QEAuthData        []byte
	QECertDataType    uint16 // Type 5 (PCK Cert Chain)
	QECertDataSize    uint32
	QECertData        SgxCertificates
}

// Parses the report into the TDReport structure
func decodeTdxReportV4(report []byte) (TdxReportV4, error) {
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
	err = parseECDSASignatureV4(buf, &sig)
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
func parseECDSASignatureV4(buf *bytes.Buffer, sig *ECDSA256QuoteSignatureDataStructureV4) error {

	err := binary.Read(buf, binary.LittleEndian, &sig.QuoteSignature)
	if err != nil {
		return fmt.Errorf("failed to parse QuoteSignature")
	}
	err = binary.Read(buf, binary.LittleEndian, &sig.ECDSAAttestationKey)
	if err != nil {
		return fmt.Errorf("failed to parse ECDSAAttestationKey")
	}
	err = binary.Read(buf, binary.LittleEndian, &sig.QECertDataType)
	if err != nil {
		return fmt.Errorf("failed to parse QECertDataType")
	}
	err = binary.Read(buf, binary.LittleEndian, &sig.QECertDataSize)
	if err != nil {
		return fmt.Errorf("failed to parse QECertDataSize")
	}

	rawData := make([]byte, sig.QECertDataSize)
	err = binary.Read(buf, binary.LittleEndian, &rawData)
	if err != nil {
		return fmt.Errorf("failed to parse QECertData")
	}

	// parse QEReportCertDataV4
	buf = bytes.NewBuffer(rawData)
	err = binary.Read(buf, binary.LittleEndian, &sig.QECertData.QEReport)
	if err != nil {
		return fmt.Errorf("failed to parse QE Report: %v", err)
	}

	err = binary.Read(buf, binary.LittleEndian, &sig.QECertData.QEReportSignature)
	if err != nil {
		return fmt.Errorf("failed to parse QE Report Signature: %v", err)
	}

	err = binary.Read(buf, binary.LittleEndian, &sig.QECertData.QEAuthDataSize)
	if err != nil {
		return fmt.Errorf("failed to parse QE Authentication Data Size: %v", err)
	}

	tmp := make([]byte, sig.QECertData.QEAuthDataSize)
	err = binary.Read(buf, binary.LittleEndian, &tmp)
	if err != nil {
		return fmt.Errorf("failed to parse QE Authentication Data: %v", err)
	}
	sig.QECertData.QEAuthData = tmp

	// parse QE Certification Data Type (has to be type 5)
	err = binary.Read(buf, binary.LittleEndian, &sig.QECertData.QECertDataType)
	if err != nil {
		return fmt.Errorf("failed to parse QE Certification Data Type: %v", err)
	}
	if sig.QECertData.QECertDataType != 5 {
		return fmt.Errorf("wrong QECertDataType. Expected: 5, Got: %v", sig.QECertData.QECertDataType)
	}

	err = binary.Read(buf, binary.LittleEndian, &sig.QECertData.QECertDataSize)
	if err != nil {
		return fmt.Errorf("failed to parse QE Certification Data Size: %v", err)
	}

	// parse QE Certification Data (Raw)
	tmp = make([]byte, sig.QECertData.QECertDataSize)
	err = binary.Read(buf, binary.LittleEndian, &tmp)
	if err != nil {
		return fmt.Errorf("failed to parse QE Certification Data: %v", err)
	}

	// parse PCK Cert Chain (PCK Leaf Cert || Intermediate CA Cert || Root CA Cert)
	certChain, err := parseCertificates(tmp[:], true)
	if err != nil {
		return fmt.Errorf("failed to parse certificate chain from QECertData: %v", err)
	}
	sig.QECertData.QECertData = certChain

	return nil
}

func verifyTdxMeasurements(tdxM Measurement, nonce []byte, intelCache string, referenceValues []ReferenceValue) (*MeasurementResult, bool) {

	var err error
	result := &MeasurementResult{
		Type:      "TDX Result",
		TdxResult: &TdxResult{},
	}
	ok := true

	log.Trace("Verifying TDX measurements")

	if len(referenceValues) == 0 {
		log.Tracef("Could not find TDX Reference Value")
		result.Summary.SetErr(RefValNotPresent)
		return result, false
	} else if len(referenceValues) > 1 {
		log.Tracef("Report contains %v reference values. Currently, only one TDX Reference Value is supported",
			len(referenceValues))
		result.Summary.SetErr(RefValMultiple)
		return result, false
	}
	tdxReferenceValue := referenceValues[0]

	if tdxReferenceValue.Type != "TDX Reference Value" {
		log.Tracef("TDX Reference Value invalid type %v", tdxReferenceValue.Type)
		result.Summary.SetErr(RefValType)
		return result, false
	}
	if tdxReferenceValue.Tdx == nil {
		log.Tracef("TDX Reference Value does not contain details")
		result.Summary.SetErr(DetailsNotPresent)
		return result, false
	}

	// Currently only support for report version 4
	tdxQuote, err := decodeTdxReportV4(tdxM.Evidence)
	if err != nil {
		log.Tracef("Failed to decode TDX report: %v", err)
		result.Summary.SetErr(ParseEvidence)
		return result, false
	}

	// Compare Nonce for Freshness (called Report Data in the SNP Attestation Report Structure)
	nonce64 := make([]byte, 64)
	copy(nonce64, nonce)
	if cmp := bytes.Compare(tdxQuote.QuoteBody.ReportData[:], nonce64); cmp != 0 {
		log.Tracef("Nonces mismatch: Supplied Nonce = %v, Nonce in TDX Report = %v)",
			hex.EncodeToString(nonce), hex.EncodeToString(tdxQuote.QuoteBody.ReportData[:]))
		result.Freshness.Success = false
		result.Freshness.Expected = hex.EncodeToString(nonce)
		result.Freshness.Got = hex.EncodeToString(tdxQuote.QuoteBody.ReportData[:])
		ok = false
		return result, ok
	} else {
		result.Freshness.Success = true
	}

	var quoteCerts SgxCertificates = tdxQuote.QuoteSignatureData.QECertData.QECertData

	if quoteCerts.RootCACert == nil || quoteCerts.IntermediateCert == nil || quoteCerts.PCKCert == nil {
		log.Tracef("incomplete certificate chain")
		result.Summary.SetErr(VerifyCertChain)
		return result, false
	}

	// parse reference cert chain (TCBSigningCert chain)
	referenceCerts, err := parseCertificates(tdxM.Certs, true)
	if err != nil || referenceCerts.TCBSigningCert == nil || referenceCerts.RootCACert == nil {
		log.Tracef("Failed to parse reference certificates (TCBSigningCert + IntelRootCACert): %v", err)
		result.Summary.SetErr(ParseCert)
		return result, false
	}

	_, code := VerifyTCBSigningCertChain(referenceCerts, intelCache)
	if code != NotSet {
		log.Tracef("%v", err.Error())
		result.Summary.SetErr(code)
		return result, false
	}

	// Parse and verify PCK certificate extensions
	sgxExtensions, err := parseSGXExtensions(quoteCerts.PCKCert.Extensions[SGX_EXTENSION_INDEX].Value[4:]) // skip the first value (not relevant)
	if err != nil {
		log.Tracef("failed to parse SGX Extensions from PCK Certificate: %v", err)
		result.Summary.SetErr(ParseCert)
		return result, false
	}

	// Parse and verify TcbInfo object
	tcbInfo, err := parseTcbInfo(tdxReferenceValue.Tdx.Collateral.TcbInfo)
	if err != nil {
		log.Tracef("Failed to parse tcbInfo: %v", err)
		result.Summary.SetErr(ParseTcbInfo)
		return result, false
	}

	result.TdxResult.TcbInfoCheck = verifyTcbInfo(&tcbInfo,
		string(tdxReferenceValue.Tdx.Collateral.TcbInfo), referenceCerts.TCBSigningCert,
		sgxExtensions, tdxQuote.QuoteBody.TeeTcbSvn, TDX_QUOTE_TYPE)
	if !result.TdxResult.TcbInfoCheck.Summary.Success {
		log.Tracef("Failed to verify TCB info structure: %v", err)
		result.Summary.SetErr(VerifyTcbInfo)
		return result, false
	}

	// Parse and verify QE Identity object
	qeIdentity, err := parseQEIdentity(tdxReferenceValue.Tdx.Collateral.QeIdentity)
	if err != nil {
		log.Tracef("Failed to parse QE Identity: %v", err)
		result.Summary.SetErr(ParseQEIdentity)
		return result, false
	}

	qeIdentityResult, err := VerifyQEIdentity(&tdxQuote.QuoteSignatureData.QECertData.QEReport, &qeIdentity,
		string(tdxReferenceValue.Tdx.Collateral.QeIdentity), referenceCerts.TCBSigningCert, TDX_QUOTE_TYPE)
	result.TdxResult.QeIdentityCheck = qeIdentityResult
	if err != nil {
		log.Tracef("Failed to verify QE Identity structure: %v", err)
		result.Summary.SetErr(VerifyQEIdentityErr)
		return result, false
	}

	// Verify Quote Signature
	sig, ret := VerifyIntelQuoteSignature(tdxM.Evidence, tdxQuote.QuoteSignatureData,
		tdxQuote.QuoteSignatureDataLen, int(tdxQuote.QuoteHeader.AttestationKeyType), quoteCerts,
		tdxReferenceValue.Tdx.CaFingerprint, intelCache, TDX_QUOTE_TYPE)
	if !ret {
		ok = false
	}
	result.Signature = sig

	// Verify Quote Body values
	err = verifyTdxQuoteBody(&tdxQuote.QuoteBody, &tcbInfo, &quoteCerts, &tdxReferenceValue, result)
	if err != nil {
		log.Tracef("Failed to verify TDX Report Body: %v", err)
		result.Summary.SetErr(VerifySignature)
		result.Summary.Success = false
		return result, false
	}

	// Check version
	result.TdxResult.VersionMatch, ret = verifyQuoteVersion(tdxQuote.QuoteHeader, tdxReferenceValue.Tdx.Version)
	if !ret {
		return result, false
	}

	return result, ok
}

func verifyTdxQuoteBody(body *TdxReportBody, tcbInfo *TcbInfo,
	certs *SgxCertificates, tdxReferenceValue *ReferenceValue, result *MeasurementResult) error {
	if body == nil || tcbInfo == nil || certs == nil || tdxReferenceValue == nil || result == nil {
		return fmt.Errorf("invalid function parameter (null pointer exception)")
	}

	// check MrTd reference value (measurement of the initial contents of the TD)
	if !bytes.Equal(body.MrTd[:], []byte(tdxReferenceValue.Sha256)) {
		result.Artifacts = append(result.Artifacts,
			DigestResult{
				Name:    tdxReferenceValue.Name,
				Digest:  hex.EncodeToString(tdxReferenceValue.Sha256),
				Success: false,
				Type:    "Reference Value",
			})
		result.Artifacts = append(result.Artifacts,
			DigestResult{
				Name:    tdxReferenceValue.Name,
				Digest:  hex.EncodeToString(body.MrTd[:]),
				Success: false,
				Type:    "Measurement",
			})
		return fmt.Errorf("MrTd mismatch. Expected: %v, Got. %v", tdxReferenceValue.Sha256, body.MrTd)
	} else {
		result.Artifacts = append(result.Artifacts,
			DigestResult{
				Name:    tdxReferenceValue.Name,
				Digest:  hex.EncodeToString(body.MrTd[:]),
				Success: true,
			})
	}

	result.Artifacts = append(result.Artifacts,
		DigestResult{
			Name:    "MrSignerSeam",
			Digest:  hex.EncodeToString(body.MrSignerSeam[:]),
			Success: bytes.Equal(tcbInfo.TcbInfo.TdxModule.Mrsigner[:], body.MrSignerSeam[:]),
			Type:    "Measurement",
		},
		DigestResult{
			Name:    "MrSeam",
			Digest:  hex.EncodeToString(body.MrSeam[:]),
			Success: bytes.Equal(body.MrSeam[:], tdxReferenceValue.Tdx.TdMeas.MrSeam),
			Type:    "Measurement",
		},
		DigestResult{
			Name:    "RtMr0",
			Digest:  hex.EncodeToString(body.RtMr0[:]),
			Success: recalculateRtMr(body.RtMr0[:], tdxReferenceValue.Tdx.TdMeas.RtMr0),
			Type:    "Firmware Measurement",
		},
		DigestResult{
			Name:    "RtMr1",
			Digest:  hex.EncodeToString(body.RtMr1[:]),
			Success: recalculateRtMr(body.RtMr1[:], tdxReferenceValue.Tdx.TdMeas.RtMr1),
			Type:    "BIOS Measurement",
		},
		DigestResult{
			Name:    "RtMr2",
			Digest:  hex.EncodeToString(body.RtMr2[:]),
			Success: recalculateRtMr(body.RtMr2[:], tdxReferenceValue.Tdx.TdMeas.RtMr2),
			Type:    "OS Measurement",
		},
		DigestResult{
			Name:    "RtMr3",
			Digest:  hex.EncodeToString(body.RtMr3[:]),
			Success: recalculateRtMr(body.RtMr3[:], tdxReferenceValue.Tdx.TdMeas.RtMr3),
			Type:    "Runtime Measurement",
		},
		DigestResult{
			Name:    "MrOwner",
			Digest:  hex.EncodeToString(body.MrOwner[:]),
			Success: bytes.Equal(tdxReferenceValue.Tdx.TdId.MrOwner[:], body.MrOwner[:]),
			Type:    "Software-defined ID",
		},
		DigestResult{
			Name:    "MrOwnerConfig",
			Digest:  hex.EncodeToString(body.MrOwnerConfig[:]),
			Success: bytes.Equal(tdxReferenceValue.Tdx.TdId.MrOwnerConfig[:], body.MrOwnerConfig[:]),
			Type:    "Software-defined ID",
		},
		DigestResult{
			Name:    "MrConfigId",
			Digest:  hex.EncodeToString(body.MrConfigId[:]),
			Success: bytes.Equal(tdxReferenceValue.Tdx.TdId.MrConfigId[:], body.MrConfigId[:]),
			Type:    "Software-defined ID",
		},
	)

	seamAttributesQuote := body.SeamAttributes
	if len(tcbInfo.TcbInfo.TdxModule.AttributesMask) == len(seamAttributesQuote) {
		for i := range seamAttributesQuote {
			seamAttributesQuote[i] &= tcbInfo.TcbInfo.TdxModule.AttributesMask[i]
		}
	}
	seamAttributesResult := bytes.Equal(tcbInfo.TcbInfo.TdxModule.Attributes, seamAttributesQuote[:])

	result.TdxResult.TdAttributesCheck = TdAttributesCheck{
		Debug: BooleanMatch{
			Success:  tdxReferenceValue.Tdx.TdAttributes.Debug == (body.TdAttributes[0] > 0),
			Claimed:  tdxReferenceValue.Tdx.TdAttributes.Debug,
			Measured: body.TdAttributes[0] > 0,
		},
		SeptVEDisable: BooleanMatch{
			Success:  tdxReferenceValue.Tdx.TdAttributes.SeptVEDisable == getBit(body.TdAttributes[:], 28),
			Claimed:  tdxReferenceValue.Tdx.TdAttributes.SeptVEDisable,
			Measured: getBit(body.TdAttributes[:], 28),
		},
		Pks: BooleanMatch{
			Success:  tdxReferenceValue.Tdx.TdAttributes.Pks == getBit(body.TdAttributes[:], 30),
			Claimed:  tdxReferenceValue.Tdx.TdAttributes.Pks,
			Measured: getBit(body.TdAttributes[:], 30),
		},
		Kl: BooleanMatch{
			Success:  tdxReferenceValue.Tdx.TdAttributes.Kl == getBit(body.TdAttributes[:], 31),
			Claimed:  tdxReferenceValue.Tdx.TdAttributes.Kl,
			Measured: getBit(body.TdAttributes[:], 31),
		},
	}
	ok := result.TdxResult.TdAttributesCheck.Debug.Success &&
		result.TdxResult.TdAttributesCheck.SeptVEDisable.Success &&
		result.TdxResult.TdAttributesCheck.Pks.Success &&
		result.TdxResult.TdAttributesCheck.Kl.Success

	if !ok {
		return fmt.Errorf("TDAttributesCheck failed: Debug: %v, SeptVEDisable: %v, Pks: %v, Kl: %v",
			result.TdxResult.TdAttributesCheck.Debug.Success, result.TdxResult.TdAttributesCheck.SeptVEDisable.Success,
			result.TdxResult.TdAttributesCheck.Pks, result.TdxResult.TdAttributesCheck.Kl)
	}

	result.TdxResult.SeamAttributesCheck = AttributesCheck{
		Success:  seamAttributesResult,
		Claimed:  HexByte(tcbInfo.TcbInfo.TdxModule.Attributes),
		Measured: HexByte(seamAttributesQuote[:]),
	}
	if !result.TdxResult.SeamAttributesCheck.Success {
		return fmt.Errorf("SeamAttributesCheck failed: Expected: %v, Measured: %v",
			result.TdxResult.SeamAttributesCheck.Claimed, result.TdxResult.SeamAttributesCheck.Measured)
	}

	result.TdxResult.XfamCheck = AttributesCheck{
		Success:  seamAttributesResult,
		Claimed:  HexByte(tcbInfo.TcbInfo.TdxModule.Attributes),
		Measured: HexByte(seamAttributesQuote[:]),
	}
	if !result.TdxResult.SeamAttributesCheck.Success {
		return fmt.Errorf("XfamCheck failed: Expected: %v, Measured: %v",
			result.TdxResult.XfamCheck.Claimed, result.TdxResult.XfamCheck.Measured)
	}

	for _, v := range result.Artifacts {
		if !v.Success {
			return fmt.Errorf("TDX Quote Body Verification failed. %v: (Got: %v)", v.Name, v.Digest)
		}
	}

	return nil
}

// calculation of rtmrs according to Intel TDX Module 1.5 base architecture specification:
// chapter 12.1.2. RTMR: Run-Time Measurement Registers
func recalculateRtMr(rmtr HexByte, refHashes RtMrHashChainElem) bool {
	if len(refHashes.Hashes) == 0 {
		log.Tracef("no reference hash values found")
		return false
	}
	var calculatedMeas []byte = make([]byte, 48)
	if refHashes.Summary {
		calculatedMeas = refHashes.Hashes[0]
	} else {
		for _, ref := range refHashes.Hashes {
			calculatedMeas = extendSha384(calculatedMeas, ref)
		}
	}

	if bytes.Equal(rmtr, calculatedMeas) {
		return true
	}
	log.Tracef("Expected: %v, Got: %v\n", calculatedMeas, rmtr)

	return false
}
