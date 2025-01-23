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

package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

type EnclaveID string
type TcbStatus string

const (
	SGX_QUOTE_TYPE      uint32 = 0x0
	TDX_QUOTE_TYPE      uint32 = 0x81
	ECDSA_P_256                = 2
	SGX_EXTENSION_INDEX        = 5

	QUOTE_HEADER_SIZE          = 48
	SGX_QUOTE_BODY_SIZE        = 384
	SGX_QUOTE_SIGNATURE_OFFSET = 436
	SGX_QUOTE_MIN_SIZE         = 1020 // value from Intel SGX QVL
	TDX_QUOTE_BODY_SIZE        = 584
	TDX_QUOTE_SIGNATURE_OFFSET = 636

	// Url params: ca = processor/platform, encoding = pem/der
	PCS_PCK_CERT_CRL_URI = "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=%v&encoding=der"
	PCS_ROOT_CA_CRL_URI  = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
	CA_PLATFORM          = "platform"
	CA_PROCESSOR         = "processor"
	ROOT_CA_CRL_NAME     = "RootCaCRL"
	PCK_CERT_CRL_NAME    = "PCKCertCRL"
	CACHE_DIR            = "cache" // stores the CRLs

	QE    EnclaveID = "QE"
	QVE   EnclaveID = "QVE"
	TD_QE EnclaveID = "TD_QE"

	UpToDate                     TcbStatus = "UpToDate"
	ConfigurationNeeded          TcbStatus = "ConfigurationNeeded"
	OutOfDate                    TcbStatus = "OutOfDate"
	OutOfDateConfigurationNeeded TcbStatus = "OutOfDateConfigurationNeeded"
	Revoked                      TcbStatus = "REVOKED"
	NotSupported                 TcbStatus = "NotSupported"
)

// 48 bytes
type QuoteHeader struct {
	Version            uint16
	AttestationKeyType uint16 // 2: ECDSA-256-with-P-256 curve
	TeeType            uint32
	QESVN              uint16
	PCESVN             uint16
	QEVendorID         [16]byte
	UserData           [20]byte
}

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

type TcbInfo struct {
	TcbInfo   TcbInfoBody `json:"tcbInfo"`
	Signature ar.HexByte  `json:"signature"`
}

type TcbInfoBody struct {
	Id                      string     `json:"id"`
	Version                 uint32     `json:"version"`
	IssueDate               time.Time  `json:"issueDate"`
	NextUpdate              time.Time  `json:"nextUpdate"`
	Fmspc                   ar.HexByte `json:"fmspc"`
	PceId                   ar.HexByte `json:"pceId"`
	TcbType                 uint32     `json:"tcbType"`
	TcbEvaluationDataNumber uint32     `json:"tcbEvaluationDataNumber"`
	TcbLevels               []TcbLevel `json:"tcbLevels"`

	TdxModule TdxModule `json:"tdxModule"` // Only required for TDX (SEAM Module)
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
}

type TcbComponent struct {
	Svn      byte   `json:"svn"`
	Category string `json:"category"`
	Type     string `json:"type"`
}

type TdxModule struct {
	Mrsigner       ar.HexByte `json:"mrsigner"`
	Attributes     ar.HexByte `json:"attributes"`
	AttributesMask ar.HexByte `json:"attributesMask"`
}

type SgxCertificates struct {
	RootCACert       *x509.Certificate
	IntermediateCert *x509.Certificate // Processor or Platform
	PCKCert          *x509.Certificate
	TCBSigningCert   *x509.Certificate
}

type QEIdentity struct {
	EnclaveIdentity QEIdentityBody `json:"enclaveIdentity"`
	Signature       ar.HexByte     `json:"signature"`
}

type QEIdentityBody struct {
	Id                      EnclaveID           `json:"id"`
	Version                 uint32              `json:"version"`
	IssueDate               time.Time           `json:"issueDate"`
	NextUpdate              time.Time           `json:"nextUpdate"`
	TcbEvaluationDataNumber uint32              `json:"tcbEvaluationDataNumber"`
	Miscselect              ar.HexByte          `json:"miscselect"`
	MiscselectMask          ar.HexByte          `json:"miscselectMask"`
	Attributes              ar.HexByte          `json:"attributes"`
	AttributesMask          ar.HexByte          `json:"attributesMask"`
	Mrsigner                ar.HexByte          `json:"mrsigner"`
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

	// optional:
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

func getTCBCompByIndex(tcb TCB, index int) TCBComp {
	switch index {
	case 1:
		return tcb.Value.Comp_01
	case 2:
		return tcb.Value.Comp_02
	case 3:
		return tcb.Value.Comp_03
	case 4:
		return tcb.Value.Comp_04
	case 5:
		return tcb.Value.Comp_05
	case 6:
		return tcb.Value.Comp_06
	case 7:
		return tcb.Value.Comp_07
	case 8:
		return tcb.Value.Comp_08
	case 9:
		return tcb.Value.Comp_09
	case 10:
		return tcb.Value.Comp_10
	case 11:
		return tcb.Value.Comp_11
	case 12:
		return tcb.Value.Comp_12
	case 13:
		return tcb.Value.Comp_13
	case 14:
		return tcb.Value.Comp_14
	case 15:
		return tcb.Value.Comp_15
	case 16:
		return tcb.Value.Comp_16
	default:
		return TCBComp{}
	}
}

// expects enclave Identity structure in JSON format
func parseQEIdentity(qeIdentityJson []byte) (QEIdentity, error) {
	var qe_identity QEIdentity
	err := json.Unmarshal(qeIdentityJson, &qe_identity)
	if err != nil {
		return QEIdentity{}, fmt.Errorf("failed to decode Enclave Identity %v", err)
	}
	return qe_identity, nil
}

// expects tcb Info in JSON format
func parseTcbInfo(tcbInfoJson []byte) (TcbInfo, error) {
	var tcbInfo TcbInfo
	err := json.Unmarshal(tcbInfoJson, &tcbInfo)
	if err != nil {
		return TcbInfo{}, fmt.Errorf("failed to decode TcbInfo %v", err)
	}
	return tcbInfo, nil
}

// parse PEM/DER formatted certificates into a SgxCertificates struct
func parseCertificates(certsRaw any, pem bool) (SgxCertificates, error) {
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
			return SgxCertificates{}, fmt.Errorf("failed to parse certificates %v", err)
		}
	case [][]byte:
		if pem {
			certs, err = internal.ParseCertsPem(t)
		} else {
			certs, err = internal.ParseCertsDer(t)
		}
		if err != nil {
			return SgxCertificates{}, fmt.Errorf("failed to parse certificates %v", err)
		}
	default:
		return SgxCertificates{}, fmt.Errorf("ParseCertificates not implemented for type %T", certsRaw)
	}

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

// Verifies the quote signature
// Params: QuoteType = 0x00 (SGX) or 0x81 (TDX)
func VerifyIntelQuoteSignature(reportRaw []byte, quoteSignature any,
	quoteSignatureSize uint32, quoteSignatureType int, certs SgxCertificates,
	fingerprint string, intelCache string, quoteType uint32) (ar.SignatureResult, bool) {
	result := ar.SignatureResult{}
	var digest [32]byte
	var ak_pub [64]byte // attestation public key (generated by the QE)
	var reportData [64]byte
	var hash_ref [32]byte
	var err error

	// check signature type and size
	switch quoteType {
	case SGX_QUOTE_TYPE:
		if uint32(len(reportRaw)-SGX_QUOTE_SIGNATURE_OFFSET) != quoteSignatureSize {
			log.Tracef("parsed QuoteSignatureData size doesn't match QuoteSignatureDataLen. expected: %v, got: %v\n",
				quoteSignatureSize, uint32(len(reportRaw)-signature_offset))
			result.SignCheck.SetErr(ar.SignatureLength)
			return result, false
		}
	case TDX_QUOTE_TYPE:
		if uint32(len(reportRaw)-TDX_QUOTE_SIGNATURE_OFFSET) != quoteSignatureSize {
			log.Tracef("parsed QuoteSignatureData size doesn't match QuoteSignatureDataLen. expected: %v, got: %v\n",
				quoteSignatureSize, uint32(len(reportRaw)-signature_offset))
			result.SignCheck.SetErr(ar.SignatureLength)
			return result, false
		}
	default:
		log.Tracef("Quote Type not supported %v", quoteType)
		result.SignCheck.SetErr(ar.EvidenceType)
		return result, false
	}

	// for now only ECDSA_P_256 support
	if quoteSignatureType != ECDSA_P_256 {
		log.Tracef("Signature Algorithm %v not supported", quoteSignatureType)
		result.SignCheck.SetErr(ar.UnsupportedAlgorithm)
		return result, false
	}

	// Step 1: Verify ISV Enclave Report Signature
	r := new(big.Int)
	s := new(big.Int)

	switch quoteSig := quoteSignature.(type) {
	case ECDSA256QuoteSignatureDataStructure: // for SGX
		r.SetBytes(quoteSig.ISVEnclaveReportSignature[:32])
		s.SetBytes(quoteSig.ISVEnclaveReportSignature[32:])
		digest = sha256.Sum256(reportRaw[:QUOTE_HEADER_SIZE+SGX_QUOTE_BODY_SIZE])
		ak_pub = quoteSig.ECDSAAttestationKey

	case ECDSA256QuoteSignatureDataStructureV4: // for TDX
		r.SetBytes(quoteSig.QuoteSignature[:32])
		s.SetBytes(quoteSig.QuoteSignature[32:])
		digest = sha256.Sum256(reportRaw[:QUOTE_HEADER_SIZE+TDX_QUOTE_BODY_SIZE])
		ak_pub = quoteSig.ECDSAAttestationKey
	}

	if len(ak_pub) == 0 {
		log.Tracef("Failed to extract ECDSA public key from certificate")
		result.SignCheck.SetErr(ar.ExtractPubKey)
		return result, false
	}

	//get x and y from public key
	pubX := new(big.Int)
	pubX.SetBytes(ak_pub[:32])
	pubY := new(big.Int)
	pubY.SetBytes(ak_pub[32:])

	ecdsa_ak_pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     pubX,
		Y:     pubY,
	}

	// Verify ECDSA Signature represented by r and s
	ok := ecdsa.Verify(ecdsa_ak_pub, digest[:], r, s)
	if !ok {
		log.Tracef("Failed to verify ISV Enclave report signature")
		result.SignCheck.SetErr(ar.VerifySignature)
		return result, false
	}
	log.Trace("Successfully verified ISV Enclave report signature")
	result.SignCheck.Success = true

	// Step 2: Verify QE Report Signature (Get QE Report from QE Report Signature Data)
	switch quoteSig := quoteSignature.(type) {
	case ECDSA256QuoteSignatureDataStructure: // for SGX
		digest = sha256.Sum256(reportRaw[SGX_QUOTE_SIGNATURE_OFFSET+128 : SGX_QUOTE_SIGNATURE_OFFSET+128+SGX_QUOTE_BODY_SIZE])
		r.SetBytes(quoteSig.QEReportSignature[:32])
		s.SetBytes(quoteSig.QEReportSignature[32:])
		reportData = quoteSig.QEReport.ReportData
		hash_ref = sha256.Sum256(append(ak_pub[:], quoteSig.QEAuthData...))
	case ECDSA256QuoteSignatureDataStructureV4: // for TDX
		digest = sha256.Sum256(reportRaw[TDX_QUOTE_SIGNATURE_OFFSET+128+6 : TDX_QUOTE_SIGNATURE_OFFSET+128+6+SGX_QUOTE_BODY_SIZE])
		r.SetBytes(quoteSig.QECertData.QEReportSignature[:32])
		s.SetBytes(quoteSig.QECertData.QEReportSignature[32:])
		reportData = quoteSig.QECertData.QEReport.ReportData
		hash_ref = sha256.Sum256(append(ak_pub[:], quoteSig.QECertData.QEAuthData...))
	}

	// Extract the PCK public key from the PCK certificate
	pck_pub, ok := certs.PCKCert.PublicKey.(*ecdsa.PublicKey)
	if pck_pub == nil || !ok {
		log.Tracef("Failed to extract PCK public key from certificate")
		result.SignCheck.SetErr(ar.ExtractPubKey)
		return result, false
	}

	// Verify the ECDSA QEReportSignature
	ok = ecdsa.Verify(pck_pub, digest[:], r, s)
	if !ok {
		log.Tracef("Failed to verify QE report signature")
		result.SignCheck.SetErr(ar.VerifySignature)
		return result, false
	}

	log.Trace("Successfully verified QE report signature")
	result.SignCheck.Success = true

	// Step 3: Verify Report Data: SHA256(ECDSA Attestation Key || QE Authentication Data) || 32-0x00’s)
	reportDataRef := append(hash_ref[:], make([]byte, 32)...)

	if !bytes.Equal(reportData[:], reportDataRef[:]) {
		log.Tracef("invalid SHA256(ECDSA Attestation Key || QE Authentication Data) || 32*0x00) in QEReport.ReportData. expected: %v, got: %v\n", reportDataRef, reportData)
		result.CertChainCheck.SetErr(ar.VerifyCertChain)
		return result, false
	}

	// Step 4: Parse and verify the entire PCK certificate chain
	var x509Chains [][]*x509.Certificate
	var code ar.ErrorCode
	switch quoteType {
	case SGX_QUOTE_TYPE:
		x509Chains, code = VerifyIntelCertChainFull(certs, CA_PROCESSOR, intelCache)
	case TDX_QUOTE_TYPE:
		x509Chains, code = VerifyIntelCertChainFull(certs, CA_PLATFORM, intelCache)
	}
	if code != ar.NotSet {
		log.Tracef("Failed to verify certificate chain: %v", err)
		result.CertChainCheck.SetErr(code)
		return result, false
	}

	// Step 5: Verify that the reference value fingerprint matches the certificate fingerprint
	refFingerprint, err := hex.DecodeString(fingerprint)
	if err != nil {
		log.Tracef("Failed to decode CA fingerprint %v: %v", fingerprint, err)
		result.CertChainCheck.SetErr(ar.ParseCAFingerprint)
		return result, false
	}
	caFingerprint := sha256.Sum256(certs.RootCACert.Raw)
	if !bytes.Equal(refFingerprint, caFingerprint[:]) {
		log.Tracef("CA fingerprint %v does not match measurement CA fingerprint %v",
			fingerprint, hex.EncodeToString(caFingerprint[:]))
		result.CertChainCheck.SetErr(ar.CaFingerprint)
		return result, false
	}
	result.CertChainCheck.Success = true

	// Step 6: Store details from (all) validated certificate chain(s) in the report
	for _, chain := range x509Chains {
		chainExtracted := []ar.X509CertExtracted{}
		for _, cert := range chain {
			chainExtracted = append(chainExtracted, ar.ExtractX509Infos(cert))
		}
		result.ValidatedCerts = append(result.ValidatedCerts, chainExtracted)
	}

	return result, true
}

// teeTcbSvn is only required for TDX (from TdxReportBody)
func verifyTcbInfo(tcbInfo *TcbInfo, tcbInfoBodyRaw string, tcbKeyCert *x509.Certificate,
	sgxExtensions SGXExtensionsValue, teeTcbSvn [16]byte, quoteType uint32) ar.TcbLevelResult {
	var result ar.TcbLevelResult

	if tcbInfo == nil || tcbKeyCert == nil {
		log.Tracef("invalid function parameter (null pointer exception)")
		result.Summary.SetErr(ar.Internal)
		return result
	}

	regex := regexp.MustCompile(`("(?:\\.|[^"])*")|\s+`)
	// remove whitespaces from json while preserving strings
	tcbInfoBodyRaw = regex.ReplaceAllString(tcbInfoBodyRaw, "$1")
	// remove "{"tcbInfo":" from beginning and signature + rest from the end
	tcbInfoBodyRaw = tcbInfoBodyRaw[len(`{"tcbInfo":`) : len(tcbInfoBodyRaw)-128-16]
	// get checksum of tcb info body
	digest := sha256.Sum256([]byte(tcbInfoBodyRaw))

	// get signature
	r := new(big.Int)
	s := new(big.Int)
	r.SetBytes(tcbInfo.Signature[:32])
	s.SetBytes(tcbInfo.Signature[32:])

	pub_key := tcbKeyCert.PublicKey.(*ecdsa.PublicKey)

	// verify signature
	ok := ecdsa.Verify(pub_key, digest[:], r, s)
	if !ok {
		log.Tracef("failed to verify tcbInfo signature")
		result.Summary.SetErr(ar.VerifyTcbInfo)
		return result
	}

	now := time.Now()

	if now.After(tcbInfo.TcbInfo.NextUpdate) {
		log.Tracef("tcbInfo has expired since: %v", tcbInfo.TcbInfo.NextUpdate)
		result.Summary.SetErr(ar.TcbInfoExpired)
		return result
	}

	if !bytes.Equal([]byte(tcbInfo.TcbInfo.Fmspc), sgxExtensions.Fmspc.Value) {
		log.Tracef("FMSPC value from TcbInfo (%v) and FMSPC value from SGX Extensions in PCK Cert (%v) do not match",
			tcbInfo.TcbInfo.Fmspc, sgxExtensions.Fmspc.Value)
		result.Summary.SetErr(ar.SgxFmpcMismatch)
		return result

	}

	if !bytes.Equal([]byte(tcbInfo.TcbInfo.PceId), sgxExtensions.PceId.Value) {
		log.Tracef("PCEID value from TcbInfo (%v) and PCEID value from SGX Extensions in PCK Cert (%v) do not match",
			tcbInfo.TcbInfo.PceId, sgxExtensions.PceId.Value)
		result.Summary.SetErr(ar.SgxPceidMismatch)
		return result
	}

	// Checking tcb level
	for _, tcbLevel := range tcbInfo.TcbInfo.TcbLevels {
		// Compare SGX TCB Comp SVNs from PCK Certificate with TCB Level
		if !compareSgxTcbCompSvns(sgxExtensions, tcbLevel) {
			continue
		}

		// Compare PCESVN value
		if sgxExtensions.Tcb.Value.PceSvn.Value < int(tcbLevel.Tcb.PceSvn) {
			continue
		}

		// Stop here for SGX
		if quoteType == SGX_QUOTE_TYPE {
			result.Summary.Success = true
			result.TcbLevelDate = tcbLevel.TcbDate
			result.TcbLevelStatus = tcbLevel.TcbStatus
			return result
		}

		// Only TDX: Compare TEE TCB SVNs from TDX Report with TCB Level
		if !compareTeeTcbSvns(teeTcbSvn, tcbLevel) || tcbLevel.Tcb.TdxTcbComponents[1].Svn != teeTcbSvn[1] {
			result.Summary.SetErr(ar.TcbLevelUnsupported)
			return result
		}

		// Only TDX: fail if Status == REVOKED
		if tcbLevel.TcbStatus == string(Revoked) {
			result.TcbLevelStatus = string(Revoked)
			result.TcbLevelDate = tcbLevel.TcbDate
			result.Summary.SetErr(ar.TcbLevelRevoked)
			return result
		}

		result.Summary.Success = true
		result.TcbLevelDate = tcbLevel.TcbDate
		result.TcbLevelStatus = tcbLevel.TcbStatus
		return result
	}

	result.Summary.SetErr(ar.TcbLevelUnsupported)
	return result
}

// helper function for verifyTcbInfo
func compareSgxTcbCompSvns(sgxExtensions SGXExtensionsValue, tcbLevel TcbLevel) bool {
	// Compare all of the SGX TCB Comp SVNs retrieved from the SGX PCK Certificate (from 01 to 16)
	// with the corresponding values of SVNs in sgxtcbcomponents array of TCB Level.
	for i := 0; i < 16; i++ {
		tcbFromCert := getTCBCompByIndex(sgxExtensions.Tcb, i+1)
		if byte(tcbFromCert.Value) < tcbLevel.Tcb.SgxTcbComponents[i].Svn {
			return false
		}
	}
	return true
}

// helper function for verifyTcbInfo
func compareTeeTcbSvns(teeTcbSvn [16]byte, tcbLevel TcbLevel) bool {
	// Compare all of the SVNs in TEE TCB SVN array retrieved from TD Report in Quote (from index 0 to 15)
	// with the corresponding values of SVNs in tdxtcbcomponents array of TCB Level
	for i := 0; i < 16; i++ {
		if teeTcbSvn[i] < tcbLevel.Tcb.TdxTcbComponents[i].Svn {
			return false
		}
	}
	return true
}

// verify QE Identity and compare the values to the QE (SGX/TDX)
func VerifyQEIdentity(qeReportBody *EnclaveReportBody, qeIdentity *QEIdentity, qeIdentityBodyRaw string, tcbKeyCert *x509.Certificate, teeType uint32) (ar.TcbLevelResult, error) {
	result := ar.TcbLevelResult{}
	if qeReportBody == nil || qeIdentity == nil || tcbKeyCert == nil {
		return result, fmt.Errorf("invalid function parameter (null pointer exception)")
	}

	regex := regexp.MustCompile(`\s+`)
	qeIdentityBodyRaw = regex.ReplaceAllString(qeIdentityBodyRaw, "")                                 // remove whitespace
	qeIdentityBodyRaw = qeIdentityBodyRaw[len(`{"enclaveIdentity":`) : len(qeIdentityBodyRaw)-128-16] // remove "{"enclaveIdentity":" from beginning and signature + rest from the end

	// get checksum of qe identity body
	digest := sha256.Sum256([]byte(qeIdentityBodyRaw))

	// get signature
	r := new(big.Int)
	s := new(big.Int)
	r.SetBytes(qeIdentity.Signature[:32])
	s.SetBytes(qeIdentity.Signature[32:])

	pub_key, ok := tcbKeyCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return result, fmt.Errorf("failed to extract public key from certificate")
	}

	// verify signature
	ok = ecdsa.Verify(pub_key, digest[:], r, s)
	if !ok {
		return result, fmt.Errorf("failed to verify QE Identity signature")
	}

	now := time.Now()
	if now.After(qeIdentity.EnclaveIdentity.NextUpdate) {
		return result, fmt.Errorf("qeIdentity has expired since: %v", qeIdentity.EnclaveIdentity.NextUpdate)
	}

	if teeType == TDX_QUOTE_TYPE {
		if qeIdentity.EnclaveIdentity.Version == 1 {
			return result, fmt.Errorf("enclave Identity version 1 is invalid for TDX TEE")
		} else if qeIdentity.EnclaveIdentity.Version == 2 {
			if qeIdentity.EnclaveIdentity.Id != TD_QE {
				return result, fmt.Errorf("enclave Identity is not generated for TDX and does not match Quote's TEE")
			}
		}
	} else if teeType == SGX_QUOTE_TYPE {
		if qeIdentity.EnclaveIdentity.Id != QE {
			return result, fmt.Errorf("enclave Identity is not generated for SGX and does not match Quote's TEE")
		}
	} else {
		return result, fmt.Errorf("unknown Quote's TEE. Enclave Identity cannot be valid")
	}

	// check mrsigner
	if !bytes.Equal([]byte(qeIdentity.EnclaveIdentity.Mrsigner), qeReportBody.MRSIGNER[:]) {
		log.Tracef("MRSIGNER mismatch. Expected: %v, Got: %v",
			qeIdentity.EnclaveIdentity.Mrsigner, qeReportBody.MRSIGNER)
		result.Summary.Success = false
		result.MrSigner = ar.Result{
			Success:  false,
			Expected: hex.EncodeToString(qeIdentity.EnclaveIdentity.Mrsigner),
			Got:      hex.EncodeToString(qeReportBody.MRSIGNER[:]),
		}
		return result, nil
	}
	result.MrSigner = ar.Result{Success: true}

	// check isvProdId
	if qeReportBody.ISVProdID != uint16(qeIdentity.EnclaveIdentity.IsvProdId) {
		log.Tracef("IsvProdId mismatch. Expected: %v, Got: %v", qeIdentity.EnclaveIdentity.IsvProdId, qeReportBody.ISVProdID)
		result.Summary.Success = false
		result.IsvProdId = ar.Result{
			Success:  false,
			Expected: strconv.FormatUint(uint64(qeIdentity.EnclaveIdentity.IsvProdId), 10),
			Got:      strconv.FormatUint(uint64(qeReportBody.ISVProdID), 10),
		}
		return result, nil
	}
	result.IsvProdId = ar.Result{Success: true}

	// check miscselect
	miscselectMask := binary.LittleEndian.Uint32(qeIdentity.EnclaveIdentity.MiscselectMask)
	refMiscSelect := binary.LittleEndian.Uint32(qeIdentity.EnclaveIdentity.Miscselect)
	reportMiscSelect := qeReportBody.MISCSELECT & miscselectMask
	if refMiscSelect != reportMiscSelect {
		log.Tracef("miscSelect value from QEIdentity: %v does not match miscSelect value from QE Report: %v",
			qeIdentity.EnclaveIdentity.Miscselect, (qeReportBody.MISCSELECT & miscselectMask))
		result.Summary.Success = false
		result.MrSigner = ar.Result{
			Success:  false,
			Expected: strconv.FormatUint(uint64(refMiscSelect), 10),
			Got:      strconv.FormatUint(uint64(reportMiscSelect), 10),
		}
		return result, nil
	}
	result.MrSigner = ar.Result{Success: true}

	// check attributes
	attributes_quote := qeReportBody.Attributes
	attributes_mask := qeIdentity.EnclaveIdentity.AttributesMask
	if len(attributes_mask) == len(attributes_quote) {
		for i := range attributes_quote {
			attributes_quote[i] &= attributes_mask[i]
		}
	}
	if !bytes.Equal([]byte(qeIdentity.EnclaveIdentity.Attributes), attributes_quote[:]) {
		log.Tracef("attributes mismatch. Expected: %v, Got: %v", qeIdentity.EnclaveIdentity.Attributes, attributes_quote)
		result.Summary.Success = false
		result.Attributes = ar.Result{
			Success:  false,
			Expected: hex.EncodeToString(qeIdentity.EnclaveIdentity.Attributes),
			Got:      hex.EncodeToString(attributes_quote[:]),
		}
		return result, nil
	}
	result.Attributes = ar.Result{Success: true}

	tcbStatus, tcbDate := getTcbStatusAndDateQE(qeIdentity, qeReportBody)
	log.Tracef("TcbStatus for Enclave's Identity tcbLevel (isvSvn: %v): '%v'", qeReportBody.ISVSVN, tcbStatus)

	switch tcbStatus {
	case Revoked:
		fallthrough
	case NotSupported:
		result.TcbLevelStatus = string(tcbStatus)
		result.TcbLevelDate = tcbDate
		result.Summary.Success = false
		return result, fmt.Errorf("tcbStatus: %v", tcbStatus)
	default:
		result.TcbLevelStatus = string(tcbStatus)
		result.TcbLevelDate = tcbDate
		result.Summary.Success = true
		return result, nil
	}
}

func getTcbStatusAndDateQE(qeIdentity *QEIdentity, body *EnclaveReportBody) (TcbStatus, time.Time) {
	for i := len(qeIdentity.EnclaveIdentity.TcbLevels) - 1; i >= 0; i-- {
		tcbLevel := qeIdentity.EnclaveIdentity.TcbLevels[i]
		if uint16(tcbLevel.Tcb.Isvsvn) <= body.ISVSVN {
			return tcbLevel.TcbStatus, tcbLevel.TcbDate
		}
	}
	return NotSupported, time.Now()
}

// Check if CRL parameters are valid and check if the certificate has been revoked
func CrlCheck(crl *x509.RevocationList, cert *x509.Certificate, parentCert *x509.Certificate) (bool, error) {

	if cert == nil || crl == nil {
		return false, fmt.Errorf("certificate or revocation null pointer exception")
	}

	// Check CRL signature
	err := crl.CheckSignatureFrom(parentCert)
	if err != nil {
		return false, fmt.Errorf("CRL signature is invalid: %v", err)
	}

	// Check if CRL is up to date
	now := time.Now()
	if now.After(crl.NextUpdate) {
		return false, fmt.Errorf("CRL has expired since: %v", crl.NextUpdate)
	}

	if !bytes.Equal(crl.RawIssuer, cert.RawIssuer) {
		return false, fmt.Errorf("CRL RawIssuer is invalid. got: %v, expected: %v ", crl.RawIssuer, cert.RawIssuer)
	}

	// Check if certificate has been revoked
	for _, revokedCert := range crl.RevokedCertificateEntries {
		if cert.SerialNumber == revokedCert.SerialNumber {
			return false, fmt.Errorf("certificate has been revoked since: %v", revokedCert.RevocationTime)
		}
	}

	return true, nil
}

// fetch the CRL either from local cache or download it from PCS
func fetchCRL(uri string, name string, ca string, cache string) (*x509.RevocationList, error) {
	// No cache
	if cache == "" {
		crl, err := downloadCRL(uri)
		if err != nil {
			return nil, fmt.Errorf("error downloading CRL: %v", err)
		}
		return crl, nil
	}

	// Use cache
	filePath := fmt.Sprintf("%s/%s_%s", cache, name, ca)
	fileInfo, err := os.Stat(filePath)
	if err == nil {
		log.Tracef("File %s exists.\n", filePath)

		lastModifiedTime := fileInfo.ModTime()
		currentTime := time.Now()
		timeSinceLastModification := currentTime.Sub(lastModifiedTime)

		// Update the CRL if it is older than a day
		if timeSinceLastModification > 24*time.Hour {
			crl, err := downloadCRL(uri)
			if err != nil {
				return nil, fmt.Errorf("error downloading CRL: %v", err)
			}
			// Store CRL in file
			err = os.WriteFile(filePath, crl.Raw, 0644)
			if err != nil {
				return nil, err
			}
		}

		// Read CRL
		crl_raw, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CRL: %w", err)
		}

		// Parse CRL
		crl, err := x509.ParseRevocationList(crl_raw)
		if err != nil {
			return nil, err
		}
		return crl, nil
	} else if os.IsNotExist(err) {
		err := os.MkdirAll(CACHE_DIR, 0755)
		if err != nil {
			return nil, fmt.Errorf("error creating cache folder: %v", err)
		}
		crl, err := downloadCRL(uri)
		if err != nil {
			return nil, fmt.Errorf("error downloading CRL: %v", err)
		}
		// Store CRL in file
		err = os.WriteFile(filePath, crl.Raw, 0644)
		if err != nil {
			return nil, err
		}
		return crl, nil
	}
	return nil, err
}

// Download CRL from the Intel PCS
func downloadCRL(uri string) (*x509.RevocationList, error) {
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)

	}
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status code: %d", resp.StatusCode)
	}

	crlData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse CRL
	crl, err := x509.ParseRevocationList(crlData)
	if err != nil {
		return nil, err
	}

	return crl, nil
}

// Verifies a given SGX certificate chain, fetches CRLs and checks if the certs are outdated
func VerifyIntelCertChainFull(quoteCerts SgxCertificates, ca string, intelCache string) ([][]*x509.Certificate, ar.ErrorCode) {
	// verify PCK certificate chain
	x509CertChains, err := internal.VerifyCertChain(
		[]*x509.Certificate{quoteCerts.PCKCert, quoteCerts.IntermediateCert},
		[]*x509.Certificate{quoteCerts.RootCACert})
	if err != nil {
		log.Tracef("Failed to verify pck certificate chain: %v", err)
		return nil, ar.VerifyPCKChain
	}

	// download CRLs from PCS
	root_ca_crl, err := fetchCRL(PCS_ROOT_CA_CRL_URI, ROOT_CA_CRL_NAME, "", intelCache)
	if err != nil {
		log.Tracef("downloading Root CA CRL from PCS failed: %v", err)
		return nil, ar.DownloadRootCRL
	}

	pck_crl_uri := fmt.Sprintf(PCS_PCK_CERT_CRL_URI, ca)
	pck_crl, err := fetchCRL(pck_crl_uri, PCK_CERT_CRL_NAME, ca, intelCache)
	if err != nil {
		log.Tracef("downloading PCK Cert CRL from PCS failed: %v", err)
		return nil, ar.DownloadPCKCRL
	}

	// perform CRL checks (signature + values)
	res, err := CrlCheck(root_ca_crl, quoteCerts.RootCACert, quoteCerts.RootCACert)
	if !res || err != nil {
		log.Tracef("CRL check on rootCert failed: %v", err)
		return nil, ar.CRLCheckRoot
	}

	res, err = CrlCheck(pck_crl, quoteCerts.PCKCert, quoteCerts.IntermediateCert)
	if !res || err != nil {
		log.Tracef("CRL check on pckCert failed: %v", err)
		return nil, ar.CRLCheckPCK
	}

	return x509CertChains, ar.NotSet
}

// Verifies the TCB signing cert chain
func VerifyTCBSigningCertChain(quoteCerts SgxCertificates, intelCache string) ([][]*x509.Certificate, ar.ErrorCode) {
	tcbSigningCertChain, err := internal.VerifyCertChain(
		[]*x509.Certificate{quoteCerts.TCBSigningCert},
		[]*x509.Certificate{quoteCerts.RootCACert})
	if err != nil {
		log.Tracef("Failed to verify TCB Signing certificate chain: %v", err)
		return nil, ar.VerifyTCBChain
	}

	root_ca_crl, err := fetchCRL(PCS_ROOT_CA_CRL_URI, ROOT_CA_CRL_NAME, "", intelCache)
	if err != nil {
		log.Tracef("downloading Root CA CRL from PCS failed: %v", err)
		return nil, ar.DownloadRootCRL
	}

	// perform CRL checks (signature + values)
	res, err := CrlCheck(root_ca_crl, quoteCerts.TCBSigningCert, quoteCerts.RootCACert)
	if !res || err != nil {
		log.Tracef("CRL check on TcbSigningCert failed: %v", err)
		return nil, ar.CRLCheckSigningCert
	}

	return tcbSigningCertChain, ar.NotSet
}

func verifyQuoteVersion(quote QuoteHeader, version uint16) (ar.Result, bool) {
	r := ar.Result{}
	ok := quote.Version == version
	if !ok {
		log.Tracef("Quote version mismatch: Report = %v, supplied = %v", quote.Version, version)
		r.Success = false
		r.Expected = strconv.FormatUint(uint64(version), 10)
		r.Got = strconv.FormatUint(uint64(quote.Version), 10)
	} else {
		r.Success = true
	}
	return r, ok
}
