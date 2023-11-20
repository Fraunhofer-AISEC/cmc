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
	"encoding/hex"
	"fmt"
	"reflect"
	"time"
)

func verifyTdxMeasurements(tdxM *TdxMeasurement, nonce []byte, referenceValues []ReferenceValue) (*TdxMeasurementResult, bool) {
	var err error
	result := &TdxMeasurementResult{}
	ok := true

	// If the attestationreport does contain neither TDX measurements, nor TDX Reference Values
	// there is nothing to to
	if tdxM == nil && len(referenceValues) == 0 {
		return nil, true
	}

	if len(referenceValues) == 0 {
		msg := "Could not find TDX Reference Value"
		result.Summary.setFalse(&msg)
		return result, false
	} else if len(referenceValues) > 1 {
		msg := fmt.Sprintf("Report contains %v reference values. Currently, only one TDX Reference Value is supported",
			len(referenceValues))
		result.Summary.setFalse(&msg)
		return result, false
	}
	tdxReferenceValue := referenceValues[0]

	if tdxReferenceValue.Type != "TDX Reference Value" {
		msg := fmt.Sprintf("TDX Reference Value invalid type %v", tdxReferenceValue.Type)
		result.Summary.setFalse(&msg)
		return result, false
	}
	if tdxReferenceValue.Tdx == nil {
		msg := "TDX Reference Value does not contain policy"
		result.Summary.setFalse(&msg)
		return result, false
	}

	// TODO: support other report types
	tdxQuote, err := DecodeTdxReportV4(tdxM.Report)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode TDX report: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Compare Nonce for Freshness (called Report Data in the SNP Attestation Report Structure)
	nonce64 := make([]byte, 64)
	copy(nonce64, nonce)
	if cmp := bytes.Compare(tdxQuote.QuoteBody.ReportData[:], nonce64); cmp != 0 {
		msg := fmt.Sprintf("Nonces mismatch: Supplied Nonce = %v, Nonce in TDX Report = %v)",
			hex.EncodeToString(nonce), hex.EncodeToString(tdxQuote.QuoteBody.ReportData[:]))
		result.Freshness.setFalse(&msg)
		ok = false
		return result, ok
	} else {
		result.Freshness.Success = true
	}

	var current_time time.Time = time.Now()
	log.Trace("current time: ", current_time)

	var quoteCerts SgxCertificates = tdxQuote.QuoteSignatureData.QECertData.QECertData

	if quoteCerts.RootCACert == nil || quoteCerts.IntermediateCert == nil || quoteCerts.PCKCert == nil {
		msg := "incomplete certificate chain"
		result.Summary.setFalse(&msg)
		return result, false
	}

	// parse reference cert chain (TCBSigningCert chain)
	referenceCerts, err := ParseCertificates(tdxM.Certs, true)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse reference certificates (TCBSigningCert + IntelRootCACert): %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	_, err = VerifyTCBSigningCertChain(referenceCerts)
	if err != nil {
		msg := err.Error()
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
	tcbInfo, err := ParseTcbInfo(tdxReferenceValue.Tdx.Collateral.TcbInfo)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse tcbInfo: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	tcbInfoResult, err := verifyTcbInfo(&tcbInfo, string(tdxReferenceValue.Tdx.Collateral.TcbInfo), referenceCerts.TCBSigningCert,
		sgxExtensions, tdxQuote.QuoteBody.TeeTcbSvn, TDX_QUOTE_TYPE)
	result.TcbInfoCheck = tcbInfoResult
	if err != nil {
		msg := fmt.Sprintf("Failed to verify TCB info structure: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Parse and verify QE Identity object
	qeIdentity, err := ParseQEIdentity(tdxReferenceValue.Tdx.Collateral.QeIdentity)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse tcbInfo: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	qeIdentityResult, err := VerifyQEIdentity(&tdxQuote.QuoteSignatureData.QECertData.QEReport, &qeIdentity,
		string(tdxReferenceValue.Tdx.Collateral.QeIdentity), referenceCerts.TCBSigningCert, TDX_QUOTE_TYPE)
	result.QeIdentityCheck = qeIdentityResult
	if err != nil {
		msg := fmt.Sprintf("Failed to verify QE Identity structure: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Verify Quote Signature
	sig, ret := VerifyIntelQuoteSignature(tdxM.Report, tdxQuote.QuoteSignatureData,
		tdxQuote.QuoteSignatureDataLen, int(tdxQuote.QuoteHeader.AttestationKeyType), quoteCerts,
		tdxReferenceValue.Tdx.CaFingerprint, TDX_QUOTE_TYPE)
	if !ret {
		ok = false
	}
	result.Signature = sig

	// Verify Quote Body values
	err = verifyTdxQuoteBody(&tdxQuote.QuoteBody, &tcbInfo, &quoteCerts, &tdxReferenceValue, result)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify TDX Report Body: %v", err)
		result.Summary.setFalse(&msg)
		result.Summary.Success = false
		return result, false
	}

	// check version
	result.VersionMatch, ret = verifyQuoteVersion(tdxQuote.QuoteHeader, tdxReferenceValue.Tdx.Version)
	if !ret {
		return result, false
	}

	return result, ok
}

func verifyTdxQuoteBody(body *TdxReportBody, tcbInfo *TcbInfo, certs *SgxCertificates, tdxReferenceValue *ReferenceValue, result *TdxMeasurementResult) error {
	if body == nil || tcbInfo == nil || certs == nil || tdxReferenceValue == nil || result == nil {
		return fmt.Errorf("invalid function parameter (null pointer exception)")
	}

	// check MrTd reference value (measurement of the initial contents of the TD)
	if !reflect.DeepEqual(body.MrTd[:], []byte(tdxReferenceValue.Sha256)) {
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

	// Perform Extended TD Check (see DCAP documentation)
	result.ExtendedTdCheck.TdIdentity = append(result.ExtendedTdCheck.TdIdentity,
		ComparisonResult{
			Name:     "MrSignerSeam",
			Success:  bytes.Equal(tcbInfo.TcbInfo.TdxModule.Mrsigner[:], body.MrSignerSeam[:]),
			Claimed:  hex.EncodeToString(tcbInfo.TcbInfo.TdxModule.Mrsigner[:]),
			Measured: hex.EncodeToString(body.MrSignerSeam[:]),
		},
		ComparisonResult{
			Name:     "MrSeam",
			Success:  tdxReferenceValue.Tdx.MrSeam == hex.EncodeToString(body.MrSeam[:]),
			Claimed:  tdxReferenceValue.Tdx.MrSeam,
			Measured: hex.EncodeToString(body.MrSeam[:]),
		},
		ComparisonResult{
			Name:     "MrOwner",
			Success:  bytes.Equal(tdxReferenceValue.Tdx.TdId.MrOwner[:], body.MrOwner[:]),
			Claimed:  hex.EncodeToString(tdxReferenceValue.Tdx.TdId.MrOwner[:]),
			Measured: hex.EncodeToString(body.MrOwner[:]),
		},
		ComparisonResult{
			Name:     "MrOwnerConfig",
			Success:  bytes.Equal(tdxReferenceValue.Tdx.TdId.MrOwnerConfig[:], body.MrOwnerConfig[:]),
			Claimed:  hex.EncodeToString(tdxReferenceValue.Tdx.TdId.MrOwnerConfig[:]),
			Measured: hex.EncodeToString(body.MrOwnerConfig[:]),
		},
		ComparisonResult{
			Name:     "MrConfigId",
			Success:  bytes.Equal(tdxReferenceValue.Tdx.TdId.MrConfigId[:], body.MrConfigId[:]),
			Claimed:  hex.EncodeToString(tdxReferenceValue.Tdx.TdId.MrConfigId[:]),
			Measured: hex.EncodeToString(body.MrConfigId[:]),
		},
		ComparisonResult{
			Name:     "RtMr0",
			Success:  bytes.Equal(tdxReferenceValue.Tdx.TdId.RtMr0[:], body.RtMr0[:]),
			Claimed:  hex.EncodeToString(tdxReferenceValue.Tdx.TdId.RtMr0[:]),
			Measured: hex.EncodeToString(body.RtMr0[:]),
		},
		ComparisonResult{
			Name:     "RtMr1",
			Success:  bytes.Equal(tdxReferenceValue.Tdx.TdId.RtMr1[:], body.RtMr1[:]),
			Claimed:  hex.EncodeToString(tdxReferenceValue.Tdx.TdId.RtMr1[:]),
			Measured: hex.EncodeToString(body.RtMr1[:]),
		},
		ComparisonResult{
			Name:     "RtMr2",
			Success:  bytes.Equal(tdxReferenceValue.Tdx.TdId.RtMr2[:], body.RtMr2[:]),
			Claimed:  hex.EncodeToString(tdxReferenceValue.Tdx.TdId.RtMr2[:]),
			Measured: hex.EncodeToString(body.RtMr3[:]),
		},
		ComparisonResult{
			Name:     "RtMr3",
			Success:  bytes.Equal(tdxReferenceValue.Tdx.TdId.RtMr3[:], body.RtMr3[:]),
			Claimed:  hex.EncodeToString(tdxReferenceValue.Tdx.TdId.RtMr3[:]),
			Measured: hex.EncodeToString(body.RtMr3[:]),
		},
	)

	seamAttributesQuote := body.SeamAttributes
	if len(tcbInfo.TcbInfo.TdxModule.AttributesMask) == len(seamAttributesQuote) {
		for i := range seamAttributesQuote {
			seamAttributesQuote[i] &= tcbInfo.TcbInfo.TdxModule.AttributesMask[i]
		}
	}
	seamAttributesResult := bytes.Equal(tcbInfo.TcbInfo.TdxModule.Attributes, seamAttributesQuote[:])

	result.ExtendedTdCheck.TdAttributes = append(result.ExtendedTdCheck.TdAttributes,
		AttributesCheck{
			Name:     "TdAttributes",
			Success:  bytes.Equal(body.TdAttributes[:], tdxReferenceValue.Tdx.TdAttributes[:]),
			Claimed:  tdxReferenceValue.Tdx.TdAttributes[:],
			Measured: body.TdAttributes[:],
		},
		AttributesCheck{
			Name:     "XFAM",
			Success:  bytes.Equal(body.XFAM[:], tdxReferenceValue.Tdx.Xfam[:]),
			Claimed:  tdxReferenceValue.Tdx.Xfam[:],
			Measured: body.XFAM[:],
		},
		AttributesCheck{
			Name:     "SeamAttributes",
			Success:  seamAttributesResult,
			Claimed:  tcbInfo.TcbInfo.TdxModule.Attributes,
			Measured: seamAttributesQuote[:],
		},
	)

	for _, v := range result.ExtendedTdCheck.TdIdentity {
		if !v.Success {
			return fmt.Errorf("TDX Quote Body Verification failed. %v: (Expected: %v, Got: %v)", v.Name, v.Claimed, v.Measured)
		}
	}

	for _, v := range result.ExtendedTdCheck.TdAttributes {
		if !v.Success {
			return fmt.Errorf("TDX Quote Body Verification failed. %v: (Expected: %v, Got: %v)", v.Name, v.Claimed, v.Measured)
		}
	}

	return nil
}
