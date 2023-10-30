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

import "fmt"

func verifyTdxMeasurements(tdxM *TdxMeasurement, nonce []byte, referenceValues []ReferenceValue) (*TdxMeasurementResult, bool) {
	var err error
	var qeReportCertData QEReportCertData
	result := &TdxMeasurementResult{}
	ok := true

	// If the attestationreport does contain neither TDX measurements, nor TDX Reference Values
	// there is nothing to to
	if tdxM == nil && len(referenceValues) == 0 {
		return nil, true
	}

	tdxQuote, err := DecodeTdxReportV4(tdxM.Report)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode TDX report: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// fmt.Println(tdxQuote)

	fmt.Println("Certification Data Type: ", tdxQuote.QuoteSignatureData.QECertDataType)

	if tdxQuote.QuoteSignatureData.QECertDataType == 6 {
		err = ParseQEReportCertificationData(tdxQuote.QuoteSignatureData.QECertData, &qeReportCertData)
		if err != nil {
			msg := fmt.Sprintf("Failed to parse QE Report Certification Data: %v", err)
			result.Summary.setFalse(&msg)
			return result, false
		}
		fmt.Println("Successfully parsed QECertData: ", qeReportCertData)

	} else {
		msg := fmt.Sprintf("QECertDataType not supported: %v", tdxQuote.QuoteSignatureData.QECertDataType)
		result.Summary.setFalse(&msg)
		return result, false
	}
	fmt.Println("QEReportCertData.QECertDataType", qeReportCertData.QECertDataType)

	fmt.Println("QEReportCertData.QECertData", qeReportCertData.QECertData)

	return result, ok
}
