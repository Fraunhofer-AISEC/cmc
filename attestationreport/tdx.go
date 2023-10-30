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
	"crypto/x509"
	"fmt"
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
		msg := fmt.Sprintf("Report contains %v reference values. Currently, only one SGX Reference Value is supported",
			len(referenceValues))
		result.Summary.setFalse(&msg)
		return result, false
	}
	tdxReferenceValue := referenceValues[0]

	// TODO: support other report types
	tdxQuote, err := DecodeTdxReportV4(tdxM.Report)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode TDX report: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	var current_time time.Time = time.Now()
	log.Trace("current time: ", current_time)

	var certChain SgxCertificates = tdxQuote.QuoteSignatureData.QECertData.QECertData

	if certChain.RootCACert == nil || certChain.IntermediateCert == nil || certChain.PCKCert == nil {
		msg := "incomplete certificate chain"
		result.Summary.setFalse(&msg)
		return result, false
	}

	// (from DCAP Library): parse and verify PCK certificate chain
	_, err = internal.VerifyCertChain(
		[]*x509.Certificate{certChain.PCKCert, certChain.IntermediateCert},
		[]*x509.Certificate{certChain.RootCACert})
	if err != nil {
		msg := fmt.Sprintf("Failed to verify pck certificate chain: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// TODO: verify the certificates (fetch CRLs and check expiration date)

	// Verify Quote Signature
	sig, ret := VerifyIntelQuoteSignature(tdxM.Report, tdxQuote.QuoteSignatureData,
		tdxQuote.QuoteSignatureDataLen, int(tdxQuote.QuoteHeader.AttestationKeyType), certChain,
		tdxReferenceValue.Tdx.Cafingerprint, TDX_QUOTE_TYPE)
	if !ret {
		msg := fmt.Sprintf("Failed to verify Quote Signature: %v", sig)
		result.Summary.setFalse(&msg)
		return result, false
	}

	//result.Signature = sig

	return result, ok
}
