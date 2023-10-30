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
	"encoding/binary"
	"fmt"
)

// TDX Report V4
type TdxReport struct {
	QuoteHeader           QuoteHeader
	ISVEnclaveReport      TdxReportBody
	QuoteSignatureDataLen uint32
	QuoteSignatureData    ECDSA256QuoteSignatureDataStructureV4 // variable size
}

// 584 bytes (TDX 1.0)
type TdxReportBody struct {
	TeeTcbSvn      [16]byte
	MrSeam         [48]byte
	MrSigner       [48]byte
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
	QECertData          []byte // Version 4
}

// This is the datastructure of QECertDataType 6
type QEReportCertData struct {
	QEReport          EnclaveReportBody
	QEReportSignature [64]byte
	QEAuthDataSize    uint16
	QEAuthData        []byte
	QECertDataType    uint16 // Type 5 (PCK Cert Chain)
	QECertDataSize    uint32
	// QECertData        []byte // Version 4 (here: PCK Cert Chain)
	QECertData SgxCertificates
}

// Parses the report into the TDReport structure
func DecodeTdxReportV4(report []byte) (TdxReport, error) {
	var reportStruct TdxReport
	var header QuoteHeader
	var body TdxReportBody
	var sig ECDSA256QuoteSignatureDataStructureV4
	var sigLen uint32

	// parse header
	buf := bytes.NewBuffer(report)
	err := binary.Read(buf, binary.LittleEndian, &header)
	if err != nil {
		return TdxReport{}, fmt.Errorf("failed to decode TD report header: %v", err)
	}

	// parse body
	err = binary.Read(buf, binary.LittleEndian, &body)
	if err != nil {
		return TdxReport{}, fmt.Errorf("failed to decode TD report body: %v", err)
	}

	// parse signature size
	err = binary.Read(buf, binary.LittleEndian, &sigLen)
	if err != nil {
		return TdxReport{}, fmt.Errorf("failed to decode TD report QuoteSignatureDataLen: %v", err)
	}

	// parse signature
	err = parseECDSASignatureV4(buf, &sig)
	if err != nil {
		return TdxReport{}, fmt.Errorf("failed to decode TD report QuoteSignatureData: %v", err)
	}

	// compose the final report struct
	reportStruct.QuoteHeader = header
	reportStruct.ISVEnclaveReport = body
	reportStruct.QuoteSignatureDataLen = sigLen
	reportStruct.QuoteSignatureData = sig

	return reportStruct, nil
}

// parses quote signature data structure from buf to sig
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
	tmp := make([]byte, sig.QECertDataSize)
	err = binary.Read(buf, binary.LittleEndian, &tmp)
	if err != nil {
		return fmt.Errorf("failed to parse QECertData")
	}
	sig.QECertData = tmp

	return nil
}

func ParseQEReportCertificationData(rawData []byte, qeReportCertData *QEReportCertData) error {

	// parse QE Report
	buf := bytes.NewBuffer(rawData)
	err := binary.Read(buf, binary.LittleEndian, &qeReportCertData.QEReport)
	if err != nil {
		return fmt.Errorf("failed to parse QE Report: %v", err)
	}

	// parse QE Report Signature
	err = binary.Read(buf, binary.LittleEndian, &qeReportCertData.QEReportSignature)
	if err != nil {
		return fmt.Errorf("failed to parse QE Report Signature: %v", err)
	}

	// parse QE Authentication Data Size
	err = binary.Read(buf, binary.LittleEndian, &qeReportCertData.QEAuthDataSize)
	if err != nil {
		return fmt.Errorf("failed to parse QE Authentication Data Size: %v", err)
	}

	// parse QE Authentication Data
	tmp := make([]byte, qeReportCertData.QEAuthDataSize)
	err = binary.Read(buf, binary.LittleEndian, &tmp)
	if err != nil {
		return fmt.Errorf("failed to parse QE Authentication Data: %v", err)
	}
	qeReportCertData.QEAuthData = tmp

	// parse QE Certification Data Type (has to be type 5)
	err = binary.Read(buf, binary.LittleEndian, &qeReportCertData.QECertDataType)
	if err != nil {
		return fmt.Errorf("failed to parse QE Certification Data Type: %v", err)
	}
	if qeReportCertData.QECertDataType != 5 {
		return fmt.Errorf("wrong QECertDataType. Expected: 5, Got: %v", qeReportCertData.QECertDataType)
	}

	// parse QE Certification Data Size
	err = binary.Read(buf, binary.LittleEndian, &qeReportCertData.QECertDataSize)
	if err != nil {
		return fmt.Errorf("failed to parse QE Certification Data Size: %v", err)
	}

	// parse QE Certification Data (Raw)
	tmp = make([]byte, qeReportCertData.QECertDataSize)
	err = binary.Read(buf, binary.LittleEndian, &tmp)
	if err != nil {
		return fmt.Errorf("failed to parse QE Certification Data: %v", err)
	}

	// parse PCK Cert Chain (PCK Leaf Cert || Intermediate CA Cert || Root CA Cert)
	certChain, err := ParseCertificates(tmp[:], false)
	if err != nil {
		return fmt.Errorf("failed to parse certificate chain from QECertData: %v", err)
	}
	qeReportCertData.QECertData = certChain

	return nil
}
