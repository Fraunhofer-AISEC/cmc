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
	"reflect"
	"time"

	"github.com/Fraunhofer-AISEC/cmc/internal"
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

	// (from DCAP Library): parse and verify the entire PCK certificate chain
	x509CertChains, err := VerifyIntelCertChainFull(quoteCerts)
	if err != nil {
		msg := err.Error()
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Store details from validated certificate chain(s) in the validation report
	for _, chain := range x509CertChains {
		chainExtracted := []X509CertExtracted{}
		for _, cert := range chain {
			chainExtracted = append(chainExtracted, ExtractX509Infos(cert))
		}
		result.Signature.ValidatedCerts = append(result.Signature.ValidatedCerts, chainExtracted)
	}

	// parse reference cert chain (TCBSigningCert chain)
	referenceCerts, err := ParseCertificates(tdxM.Certs, true)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse reference certificates (TCBSigningCert + IntelRootCACert): %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// verify TCB Signing cert chain
	_, err = internal.VerifyCertChain(
		[]*x509.Certificate{referenceCerts.TCBSigningCert},
		[]*x509.Certificate{quoteCerts.RootCACert})
	if err != nil {
		msg := fmt.Sprintf("Failed to verify TCB Signing certificate chain: %v", err)
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

	// (from DCAP Library): parse and verify TcbInfo object
	tcbInfo, err := ParseTcbInfo(tdxReferenceValue.Tdx.Collateral.TcbInfo)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse tcbInfo: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	err = verifyTcbInfo(&tcbInfo, string(tdxReferenceValue.Tdx.Collateral.TcbInfo), referenceCerts.TCBSigningCert, sgxExtensions)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify TCB info structure: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// (from DCAP Library): parse and verify QE Identity object
	qeIdentity, err := ParseQEIdentity(tdxReferenceValue.Tdx.Collateral.QeIdentity)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse tcbInfo: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	err = VerifyQEIdentity(&tdxQuote.QuoteSignatureData.QECertData.QEReport, &qeIdentity,
		string(tdxReferenceValue.Tdx.Collateral.QeIdentity), referenceCerts.TCBSigningCert, TDX_QUOTE_TYPE)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify QE Identity structure: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Verify Quote Signature
	sig, ret := VerifyIntelQuoteSignature(tdxM.Report, tdxQuote.QuoteSignatureData,
		tdxQuote.QuoteSignatureDataLen, int(tdxQuote.QuoteHeader.AttestationKeyType), quoteCerts,
		tdxReferenceValue.Tdx.Cafingerprint, TDX_QUOTE_TYPE)
	if !ret {
		msg := fmt.Sprintf("Failed to verify Quote Signature: %v", sig)
		result.Summary.setFalse(&msg)
		return result, false
	}

	result.Signature = sig

	// check version
	result.VersionMatch, ret = verifySgxVersion(tdxQuote.QuoteHeader, tdxReferenceValue.Tdx.Version)
	if !ret {
		return result, false
	}

	// Verify Quote Body values
	err = VerifyTdxQuoteBody(&tdxQuote.QuoteBody, &tcbInfo, &quoteCerts, &tdxReferenceValue, result)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify TDX Report Body: %v", err)
		result.Summary.setFalse(&msg)
		result.Summary.Success = false
		return result, false
	} else {
		result.Artifacts = append(result.Artifacts,
			DigestResult{
				Name:    tdxReferenceValue.Name,
				Digest:  hex.EncodeToString(tdxQuote.QuoteBody.MrSeam[:]),
				Success: true,
			})
		ok = true
	}

	return result, ok
}

func VerifyTdxQuoteBody(body *TdxReportBody, tcbInfo *TcbInfo, certs *SgxCertificates, tdxReferenceValue *ReferenceValue, result *TdxMeasurementResult) error {
	if body == nil || tcbInfo == nil || certs == nil || tdxReferenceValue == nil || result == nil {
		return fmt.Errorf("invalid function parameter (null pointer exception)")
	}

	// Parse and verify PCK certificate extensions
	sgxExtensions, err := ParseSGXExtensions(certs.PCKCert.Extensions[SGX_EXTENSION_INDEX].Value[4:]) // skip the first value (not relevant, only means it is a sequence)
	if err != nil {
		return fmt.Errorf("failed to parse SGX Extensions from PCK Certificate: %v", err)
	}

	if !reflect.DeepEqual([]byte(tcbInfo.TcbInfo.Fmspc), sgxExtensions.Fmspc.Value) {
		return fmt.Errorf("FMSPC value from TcbInfo (%v) and FMSPC value from SGX Extensions in PCK Cert (%v) do not match",
			tcbInfo.TcbInfo.Fmspc, sgxExtensions.Fmspc.Value)
	}

	if !reflect.DeepEqual([]byte(tcbInfo.TcbInfo.PceId), sgxExtensions.PceId.Value) {
		return fmt.Errorf("PCEID value from TcbInfo (%v) and PCEID value from SGX Extensions in PCK Cert (%v) do not match",
			tcbInfo.TcbInfo.PceId, sgxExtensions.PceId.Value)
	}

	// check MrTd reference value
	// (MrTd is the measurement of the initial contents of the TD)
	if !reflect.DeepEqual(body.MrTd[:], []byte(tdxReferenceValue.Sha256)) {
		result.Artifacts = append(result.Artifacts,
			DigestResult{
				Name:    tdxReferenceValue.Name,
				Digest:  hex.EncodeToString(tdxReferenceValue.Sha256[:]),
				Success: false,
			})
		return fmt.Errorf("MrSeam mismatch. Expected: %v, Got. %v", tdxReferenceValue.Sha256, body.MrTd)
	} else {
		result.Artifacts = append(result.Artifacts,
			DigestResult{
				Name:    tdxReferenceValue.Name,
				Digest:  hex.EncodeToString(body.MrSeam[:]),
				Success: true,
			})
	}

	// check SeamAttributes
	attributes_quote := body.SeamAttributes
	if !reflect.DeepEqual(tdxReferenceValue.Tdx.SeamAttributes[:], attributes_quote[:]) {
		return fmt.Errorf("SeamAttributes mismatch. Expected: %v, Got: %v", tdxReferenceValue.Tdx.SeamAttributes, attributes_quote)
	}

	// check MrSignerSeam value
	refSigner, err := hex.DecodeString(tdxReferenceValue.Tdx.MrSignerSeam)
	if err != nil {
		return fmt.Errorf("decoding MRSIGNERSEAM reference value failed: %v", err)
	}
	if !reflect.DeepEqual(refSigner[:], body.MrSignerSeam[:]) {
		return fmt.Errorf("MRSIGNERSEAM mismatch. Expected: %v, Got: %v", refSigner, body.MrSignerSeam[:])
	}

	attributes_quote = body.TdAttributes
	if !reflect.DeepEqual(tdxReferenceValue.Tdx.TdAttributes[:], attributes_quote[:]) {
		return fmt.Errorf("TdAttributes mismatch. Expected: %v, Got: %v", tdxReferenceValue.Tdx.TdAttributes, attributes_quote)
	}
	return nil
}
