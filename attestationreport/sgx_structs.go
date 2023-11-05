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
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Fraunhofer-AISEC/cmc/internal"
)

type EnclaveID string
type TcbStatus string

const (
	QE    EnclaveID = "QE"
	QVE   EnclaveID = "QVE"
	TD_QE EnclaveID = "TD_QE"

	UpToDate                     TcbStatus = "UpToDate"
	ConfigurationNeeded          TcbStatus = "ConfigurationNeeded"
	OutOfDate                    TcbStatus = "OutOfDate"
	OutOfDateConfigurationNeeded TcbStatus = "OutOfDateConfigurationNeeded"
	Revoked                      TcbStatus = "Revoked"
)

// Overall structure: table 2 from https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
// Endianess: Little Endian (all Integer fields)
type SgxReport struct {
	QuoteHeader           QuoteHeader
	ISVEnclaveReport      EnclaveReportBody
	QuoteSignatureDataLen uint32
	QuoteSignatureData    ECDSA256QuoteSignatureDataStructure // variable size
}

// Quote Header: Table 3 from https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
// 48 bytes
type QuoteHeader struct {
	Version            uint16
	AttestationKeyType uint16 // 2: ECDSA-256-with-P-256 curve
	TeeType            uint32 // value from dcap library (not in documentation)
	QESVN              uint16
	PCESVN             uint16
	QEVendorID         [16]byte
	UserData           [20]byte
}

// Enclave Report Body: Table 5 from https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
// 384 bytes
type EnclaveReportBody struct {
	CPUSVN     [16]byte
	MISCSELECT uint32
	Reserved1  [28]byte
	Attributes [16]byte
	MRENCLAVE  [32]byte
	Reserved2  [32]byte
	MRSIGNER   [32]byte
	Reserved3  [96]byte
	ISVProdID  uint16
	ISVSVN     uint16
	Reserved4  [60]byte
	ReportData [64]byte
}

// table 4: https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
type ECDSA256QuoteSignatureDataStructure struct {
	ISVEnclaveReportSignature [64]byte
	ECDSAAttestationKey       [64]byte
	QEReport                  EnclaveReportBody
	QEReportSignature         [64]byte

	QEAuthDataSize uint16
	QEAuthData     []byte

	QECertDataType uint16
	QECertDataSize uint32
	QECertData     []byte
}

// from Intel SGX DCAP library: AttestationParsers.h
type TcbInfo struct {
	TcbInfo   TcbInfoBody `json:"tcbInfo"`
	Signature HexByte     `json:"signature"`
}

type TcbInfoBody struct {
	Id                      string     `json:"id"`
	Version                 uint32     `json:"version"`
	IssueDate               time.Time  `json:"issueDate"`
	NextUpdate              time.Time  `json:"nextUpdate"`
	Fmspc                   HexByte    `json:"fmspc"`
	PceId                   HexByte    `json:"pceId"`
	TcbType                 uint32     `json:"tcbType"`
	TcbEvaluationDataNumber uint32     `json:"tcbEvaluationDataNumber"`
	TcbLevels               []TcbLevel `json:"tcbLevels"`

	// Get properties of Intel’s TDX SEAM module
	TdxModule TdxModule `json:"tdxModule"` // Only required for TDX
}

type TcbLevel struct {
	Tcb struct {
		SgxTcbComponents []TcbComponent `json:"sgxTcbComponents"`
		TdxTcbComponents []TcbComponent `json:"tdxTcbComponents"`
		PceSvn           uint32         `json:"pceSvn"`
	} `json:"tcb"`

	TcbStatus   string    `json:"tcbStatus"`
	TcbDate     time.Time `json:"tcbDate"`
	AdvisoryIDs []string  `json:"advisoryIDs"`

	// TODO: not sure if these 3 values are entirely correct
	Id               string  `json:"id"`
	Version          uint32  `json:"version"`
	CpuSvnComponents HexByte `json:"cpuSvnComponents"`
}

type TcbComponent struct {
	Svn      byte   `json:"svn"`
	Category string `json:"category"`
	Type     string `json:"type"`
}

// TODO: not sure if this is correct
type TdxModule struct {
	Mrsigner       HexByte `json:"mrsigner"`
	Attributes     HexByte `json:"attributes"`
	AttributesMask HexByte `json:"attributesMask"`
}

type SgxCertificates struct {
	RootCACert       *x509.Certificate
	IntermediateCert *x509.Certificate // Processor or Platform
	PCKCert          *x509.Certificate
	TCBSigningCert   *x509.Certificate
}

type QEIdentity struct {
	EnclaveIdentity QEIdentityBody `json:"enclaveIdentity"`
	Signature       HexByte        `json:"signature"`
}

type QEIdentityBody struct {
	Id                      EnclaveID           `json:"id"`
	Version                 uint32              `json:"version"`
	IssueDate               time.Time           `json:"issueDate"`
	NextUpdate              time.Time           `json:"nextUpdate"`
	TcbEvaluationDataNumber uint32              `json:"tcbEvaluationDataNumber"`
	Miscselect              HexByte             `json:"miscselect"`
	MiscselectMask          HexByte             `json:"miscselectMask"`
	Attributes              HexByte             `json:"attributes"`
	AttributesMask          HexByte             `json:"attributesMask"`
	Mrsigner                HexByte             `json:"mrsigner"`
	IsvProdId               uint32              `json:"isvprodid"`
	TcbLevels               []TcbLevelEnclaveId `json:"tcbLevels"`
}

type TcbLevelEnclaveId struct {
	Tcb struct {
		Isvsvn uint32 `json:"isvsvn"`
	} `json:"tcb"`
	TcbDate     time.Time `json:"tcbDate"`
	TcbStatus   TcbStatus `json:"tcbStatus"`
	AdvisoryIDs []string  `json:"advisoryIDs"`
}

// ------------------------- start SGX Extensions -------------------------
// asn1 encoded data structure from pck certificate
type SGXExtensionsWrapper struct {
	Value SGXExtensionsValue
}

type SGXExtensionsValue struct {
	// required:
	Ppid    PPID
	Tcb     TCB
	PceId   PCEID
	Fmspc   FMSPC
	SgxType SGXTYPE

	//optional:
	PlatformInstanceId PlatformInstanceId
	Configuration      Configuration
}

type PPID struct {
	Id    asn1.ObjectIdentifier
	Value []byte
}

type TCB struct {
	Id    asn1.ObjectIdentifier
	Value struct {
		Comp_01 TCBComp
		Comp_02 TCBComp
		Comp_03 TCBComp
		Comp_04 TCBComp
		Comp_05 TCBComp
		Comp_06 TCBComp
		Comp_07 TCBComp
		Comp_08 TCBComp
		Comp_09 TCBComp
		Comp_10 TCBComp
		Comp_11 TCBComp
		Comp_12 TCBComp
		Comp_13 TCBComp
		Comp_14 TCBComp
		Comp_15 TCBComp
		Comp_16 TCBComp
		PceSvn  TCBComp
		CpuSvn  struct {
			Svn   asn1.ObjectIdentifier
			Value []byte
		}
	}
}

type TCBComp struct {
	Svn   asn1.ObjectIdentifier
	Value int
}

type PCEID struct {
	Id    asn1.ObjectIdentifier
	Value []byte
}

type FMSPC struct {
	Id    asn1.ObjectIdentifier
	Value []byte
}

type SGXTYPE struct {
	Id    asn1.ObjectIdentifier
	Value asn1.Enumerated
}

type PlatformInstanceId struct {
	Id    asn1.ObjectIdentifier
	Value []byte
}

// ConfigurationId determines the type of the ConfigurationValue:
// [0]: dynamicPlatform, [1]: cachedKeys, [2]: sMTenabled
type Configuration struct {
	Id    asn1.ObjectIdentifier
	Value []struct {
		ConfigurationId    asn1.ObjectIdentifier
		ConfigurationValue bool
	}
}

// ------------------------- end SGX Extensions -------------------------

func ParseSGXExtensions(extensions []byte) (SGXExtensionsValue, error) {
	var sgx_extensions SGXExtensionsValue

	rest, err := asn1.Unmarshal(extensions, &sgx_extensions.Ppid)
	if err != nil {
		return SGXExtensionsValue{}, fmt.Errorf("failed to decode SGX Extensions PPID %v", err)
	}
	rest, err = asn1.Unmarshal(rest, &sgx_extensions.Tcb)
	if err != nil || len(rest) == 0 {
		return SGXExtensionsValue{}, fmt.Errorf("failed to decode SGX extensions TCB %v", err)
	}
	rest, err = asn1.Unmarshal(rest, &sgx_extensions.PceId)
	if err != nil || len(rest) == 0 {
		return SGXExtensionsValue{}, fmt.Errorf("failed to decode SGX Extensions PCEID %v", err)
	}
	rest, err = asn1.Unmarshal(rest, &sgx_extensions.Fmspc)
	if err != nil || len(rest) == 0 {
		return SGXExtensionsValue{}, fmt.Errorf("failed to decode SGX Extensions FMSPC %v", err)
	}
	rest, err = asn1.Unmarshal(rest, &sgx_extensions.SgxType)
	if err != nil {
		return SGXExtensionsValue{}, fmt.Errorf("failed to decode SGX Extensions SGXTYPE %v", err)
	} else if len(rest) > 0 {
		// parse optional parameters
		rest, err = asn1.Unmarshal(rest, &sgx_extensions.PlatformInstanceId)
		if err != nil || len(rest) == 0 {
			return SGXExtensionsValue{}, fmt.Errorf("failed to decode SGX extensions PlatfromInstanceId %v", err)
		}
		rest, err = asn1.Unmarshal(rest, &sgx_extensions.Configuration)
		if err != nil || len(rest) != 0 {
			return SGXExtensionsValue{}, fmt.Errorf("failed to decode SGX extensions Configuration %v", err)
		}
	}

	return sgx_extensions, nil
}

func GetTCBCompByIndex(tcb TCB, index int) (TCBComp, error) {
	switch index {
	case 1:
		return tcb.Value.Comp_01, nil
	case 2:
		return tcb.Value.Comp_02, nil
	case 3:
		return tcb.Value.Comp_03, nil
	case 4:
		return tcb.Value.Comp_04, nil
	case 5:
		return tcb.Value.Comp_05, nil
	case 6:
		return tcb.Value.Comp_06, nil
	case 7:
		return tcb.Value.Comp_07, nil
	case 8:
		return tcb.Value.Comp_08, nil
	case 9:
		return tcb.Value.Comp_09, nil
	case 10:
		return tcb.Value.Comp_10, nil
	case 11:
		return tcb.Value.Comp_11, nil
	case 12:
		return tcb.Value.Comp_12, nil
	case 13:
		return tcb.Value.Comp_13, nil
	case 14:
		return tcb.Value.Comp_14, nil
	case 15:
		return tcb.Value.Comp_15, nil
	case 16:
		return tcb.Value.Comp_16, nil
	default:
		return TCBComp{}, fmt.Errorf("invalid index")
	}
}

// expects enclave Identity structure in JSON format
func ParseQEIdentity(qeIdentityJson []byte) (QEIdentity, error) {
	var qe_identity QEIdentity
	err := json.Unmarshal(qeIdentityJson, &qe_identity)
	if err != nil {
		return QEIdentity{}, fmt.Errorf("failed to decode Enclave Identity %v", err)
	}
	return qe_identity, nil
}

// expects tcb Info in JSON format
func ParseTcbInfo(tcbInfoJson []byte) (TcbInfo, error) {
	var tcbInfo TcbInfo
	err := json.Unmarshal(tcbInfoJson, &tcbInfo)
	if err != nil {
		return TcbInfo{}, fmt.Errorf("failed to decode TcbInfo %v", err)
	}
	return tcbInfo, nil
}

// parse PEM/DER formatted certificates into a SgxCertificates struct
func ParseCertificates(certsRaw any, pem bool) (SgxCertificates, error) {
	var certChain SgxCertificates
	var certs []*x509.Certificate
	var err error

	switch t := certsRaw.(type) {
	case []byte:
		if pem {
			certs, err = internal.ParseCertsPem(t)
		} else {
			certs, err = internal.ParseCertsDer(t)
		}
		if err != nil {
			return SgxCertificates{}, fmt.Errorf("failed to parse PEM certificates %v", err)
		}
	case [][]byte:
		if pem {
			certs, err = internal.ParseCertsPem(t)
		} else {
			certs, err = internal.ParseCertsDer(t)
		}
		if err != nil {
			return SgxCertificates{}, fmt.Errorf("failed to parse DER certificates %v", err)
		}
	default:
		return SgxCertificates{}, fmt.Errorf("ParseCertificates not implemented for type %T", certsRaw)
	}

	// TODO: identify based on subject key identifier
	for _, v := range certs {
		switch v.Subject.CommonName {
		case "Intel SGX PCK Certificate":
			certChain.PCKCert = v
		case "Intel SGX PCK Processor CA":
			certChain.IntermediateCert = v
		case "Intel SGX PCK Platform CA":
			certChain.IntermediateCert = v
		case "Intel SGX Root CA":
			certChain.RootCACert = v
		case "Intel SGX TCB Signing":
			certChain.TCBSigningCert = v
		}
	}

	return certChain, nil
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

// parses quote signature data structure from buf to sig
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
	binary.Read(buf, binary.LittleEndian, &tmp)
	if err != nil {
		return fmt.Errorf("failed to parse QECertData")
	}
	sig.QECertData = tmp

	return nil
}
