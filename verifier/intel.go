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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/google/go-tdx-guest/pcs"
)

type QuoteType uint32

const (
	SGX_QUOTE_TYPE      QuoteType = 0x0
	TDX_QUOTE_TYPE      QuoteType = 0x81
	ECDSA_P_256                   = 2
	SGX_EXTENSION_INDEX           = 5

	QUOTE_HEADER_SIZE          = 48
	SGX_QUOTE_BODY_SIZE        = 384
	SGX_QUOTE_SIGNATURE_OFFSET = 436
	SGX_QUOTE_MIN_SIZE         = 1020 // value from Intel SGX QVL
	TDX_QUOTE_BODY_SIZE        = 584
	TDX_QUOTE_SIGNATURE_OFFSET = 636

	CA_PLATFORM  = "platform"
	CA_PROCESSOR = "processor"

	QE     = "QE"
	QVE_ID = "QVE"
	QE_ID  = "TD_QE"

	CN_ROOT_CERT         = "Intel SGX Root CA"
	CN_PLATFORM_CA_CERT  = "Intel SGX PCK Platform CA"
	CN_PROCESSOR_CA_CERT = "Intel SGX PCK Processor CA"
	CN_PCK_CERT          = "Intel SGX PCK Certificate"
	CN_TCB_SIGNING       = "Intel SGX TCB Signing"

	TCB_INFO_JSON_KEY    = "tcbInfo"
	QE_IDENTITY_JSON_KEY = "enclaveIdentity"

	TCB_INFO_ID        = "TDX"
	TCB_INFO_VERSION   = 3
	QE_IDENTIY_VERSION = 2
)

// 48 bytes
type QuoteHeader struct {
	Version            uint16
	AttestationKeyType uint16 // 2: ECDSA-256-with-P-256 curve
	TeeType            uint32 // 0x00000000: SGX, 0x00000081: TDX
	QESVN              uint16 // TDX: RESERVED
	PCESVN             uint16 // TDX: RESERVED
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

type SgxCertificates struct {
	RootCACert       *x509.Certificate
	IntermediateCert *x509.Certificate // Processor or Platform
	PCKCert          *x509.Certificate
	TCBSigningCert   *x509.Certificate
}

type Collateral struct {
	TcbInfo                    pcs.TdxTcbInfo
	QeIdentity                 pcs.QeIdentity
	RootCaCrl                  *x509.RevocationList
	PckCrl                     *x509.RevocationList
	PckCrlIntermediateCert     *x509.Certificate
	PckCrlRootCert             *x509.Certificate
	TcbInfoIntermediateCert    *x509.Certificate
	TcbInfoRootCert            *x509.Certificate
	QeIdentityIntermediateCert *x509.Certificate
	QeIdentityRootCert         *x509.Certificate
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

func ParseCollateral(c *ar.IntelCollateral) (*Collateral, error) {

	if c == nil {
		return nil, errors.New("cannot parse collateral: collateral is nil")
	}

	var tcbInfo pcs.TdxTcbInfo
	err := json.Unmarshal(c.TcbInfo, &tcbInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TcbInfo %v", err)
	}

	tcbInfoIntermediateCert, err := x509.ParseCertificate(c.TcbInfoIntermediateCert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TCB Info issuer intermediate cert: %w", err)
	}

	tcbInfoRootCert, err := x509.ParseCertificate(c.TcbInfoRootCert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TCB Info issuer root cert: %w", err)
	}

	var qeIdentity pcs.QeIdentity
	err = json.Unmarshal(c.QeIdentity, &qeIdentity)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Enclave Identity %v", err)
	}

	qeIdentityIntermediateCert, err := x509.ParseCertificate(c.QeIdentityIntermediateCert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse QE identity issuer intermediate cert: %w", err)
	}

	qeIdentityRootCert, err := x509.ParseCertificate(c.QeIdentityRootCert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse QE identity issuer intermediate cert: %w", err)
	}

	pckCrl, err := x509.ParseRevocationList(c.PckCrl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PCK CRL: %w", err)
	}

	pckCrlIntermediateCert, err := x509.ParseCertificate(c.PckCrlIntermediateCert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PCK CRL issuer intermediate cert: %w", err)
	}

	pckCrlRootCert, err := x509.ParseCertificate(c.PckCrlRootCert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PCK CRL root cert: %w", err)
	}

	rootCrl, err := x509.ParseRevocationList(c.RootCaCrl)
	if err != nil {
		log.Warnf("failed to parse root CA CRL: %v", err)
	}

	return &Collateral{
		TcbInfo:                    tcbInfo,
		QeIdentity:                 qeIdentity,
		RootCaCrl:                  rootCrl,
		PckCrl:                     pckCrl,
		PckCrlIntermediateCert:     pckCrlIntermediateCert,
		PckCrlRootCert:             pckCrlRootCert,
		TcbInfoIntermediateCert:    tcbInfoIntermediateCert,
		TcbInfoRootCert:            tcbInfoRootCert,
		QeIdentityIntermediateCert: qeIdentityIntermediateCert,
		QeIdentityRootCert:         qeIdentityRootCert,
	}, nil
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

	log.Tracef("Parsing %v certificates", len(certs))
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
		default:
			return SgxCertificates{}, fmt.Errorf("unknown certificate type %v", v.Subject.CommonName)
		}
		log.Tracef("Parsed certificate CN=%v", v.Subject.CommonName)
	}

	return certChain, nil
}

// Verifies the quote signature
// Params: QuoteType = 0x00 (SGX) or 0x81 (TDX)
func VerifyIntelQuoteSignature(reportRaw []byte, quoteSignature any,
	quoteSignatureSize uint32, quoteSignatureType int, certs SgxCertificates,
	quoteType QuoteType, pckCrl, rootCrl *x509.RevocationList) (ar.SignatureResult, bool) {
	result := ar.SignatureResult{}
	var digest [32]byte
	var ak_pub [64]byte // attestation public key (generated by the QE)
	var reportData [64]byte
	var hash_ref [32]byte
	var err error

	// Check signature type and size
	if quoteType != SGX_QUOTE_TYPE && quoteType != TDX_QUOTE_TYPE {
		log.Debugf("Quote type not supported %v", quoteType)
		result.SignCheck.Fail(ar.EvidenceType)
		return result, false
	}
	log.Tracef("Quote type is 0x%x", quoteType)

	// For now only ECDSA_P_256 support
	if quoteSignatureType != ECDSA_P_256 {
		log.Debugf("Signature Algorithm %v not supported", quoteSignatureType)
		result.SignCheck.Fail(ar.UnsupportedAlgorithm)
		return result, false
	}
	log.Tracef("Quote signature type is ECDSA P-256")

	// Verify ISV Enclave Report Signature
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
		log.Debugf("Failed to extract ECDSA public key from certificate")
		result.SignCheck.Fail(ar.ExtractPubKey)
		return result, false
	}

	// Get x and y from public key
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
		log.Debugf("Failed to verify quote signature")
		result.SignCheck.Fail(ar.VerifySignature)
		return result, false
	}
	log.Debug("Successfully verified quote signature")
	result.SignCheck.Status = ar.StatusSuccess

	// Verify QE Report Signature (Get QE Report from QE Report Signature Data)
	switch quoteSig := quoteSignature.(type) {
	case ECDSA256QuoteSignatureDataStructure: // for SGX
		digest = sha256.Sum256(reportRaw[SGX_QUOTE_SIGNATURE_OFFSET+128 : SGX_QUOTE_SIGNATURE_OFFSET+128+SGX_QUOTE_BODY_SIZE])
		r.SetBytes(quoteSig.QEReportSignature[:32])
		s.SetBytes(quoteSig.QEReportSignature[32:])
		reportData = quoteSig.QEReport.ReportData
		hash_ref = sha256.Sum256(append(ak_pub[:], quoteSig.QEAuthData...))
	case ECDSA256QuoteSignatureDataStructureV4: // for TDX
		digest = sha256.Sum256(reportRaw[TDX_QUOTE_SIGNATURE_OFFSET+128+6 : TDX_QUOTE_SIGNATURE_OFFSET+128+6+SGX_QUOTE_BODY_SIZE])
		r.SetBytes(quoteSig.QECertificationData.QEReportCertificationData.QEReportSignature[:32])
		s.SetBytes(quoteSig.QECertificationData.QEReportCertificationData.QEReportSignature[32:])
		reportData = quoteSig.QECertificationData.QEReportCertificationData.QEReport.ReportData
		hash_ref = sha256.Sum256(append(ak_pub[:], quoteSig.QECertificationData.QEReportCertificationData.QEAuthData...))
	}

	// Extract the PCK public key from the PCK certificate
	pckPub, ok := certs.PCKCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Debugf("Failed to extract PCK public key from certificate")
		result.SignCheck.Fail(ar.ExtractPubKey)
		return result, false
	}

	// Verify the ECDSA QEReportSignature
	ok = ecdsa.Verify(pckPub, digest[:], r, s)
	if !ok {
		log.Debugf("Failed to verify QE report signature")
		result.SignCheck.Fail(ar.VerifySignature)
		return result, false
	}

	log.Debug("Successfully verified QE report signature")
	result.SignCheck.Status = ar.StatusSuccess

	// Verify Report Data: SHA256(ECDSA Attestation Key || QE Authentication Data) || 32-0x00’s)
	reportDataRef := append(hash_ref[:], make([]byte, 32)...)

	if !bytes.Equal(reportData[:], reportDataRef[:]) {
		log.Debugf("invalid SHA256(ECDSA Attestation Key || QE Authentication Data) || 32*0x00) in QEReport.ReportData. expected: %v, got: %v\n", reportDataRef, reportData)
		result.CertChainCheck.Fail(ar.VerifyCertChain)
		return result, false
	}

	// Parse and verify the entire PCK certificate chain
	x509Chains, code := VerifyPckCertChain(certs, pckCrl, rootCrl)
	if code != ar.NotSpecified {
		log.Debugf("Failed to verify certificate chain: %v", err)
		result.CertChainCheck.Fail(code)
		return result, false
	}
	result.CertChainCheck.Status = ar.StatusSuccess

	// Store details from (all) validated certificate chain(s) in the report
	for _, chain := range x509Chains {
		chainExtracted := []ar.X509CertExtracted{}
		for _, cert := range chain {
			chainExtracted = append(chainExtracted, ar.ExtractX509Infos(cert))
		}
		result.Certs = append(result.Certs, chainExtracted)
	}

	return result, true
}

func verifyCollateralElem(elem []byte, signature string, cn, tbsJsonKey string, cert, ca *x509.Certificate) ar.ErrorCode {

	// Check issuer certificate
	if err := internal.CheckCert(cert, cn, x509.ECDSAWithSHA256); err != nil {
		log.Debugf("Failed to check collateral issuer cert: %v", err)
		return ar.VerifyCertChain
	}

	// Verify issuer certificate chain
	_, err := internal.VerifyCertChain(
		[]*x509.Certificate{cert},
		[]*x509.Certificate{ca})
	if err != nil {
		log.Debugf("Failed to collateral issuer certificate chain: %v", err)
		return ar.VerifyCertChain
	}
	log.Debugf("Successfully verified collateral issuer certificate chain")

	tbs, err := extractTbsArea(elem, tbsJsonKey)
	if err != nil {
		log.Debugf("Failed to extract signed part of collateral element: %v", err)
		return ar.VerifySignature
	}

	digest := sha256.Sum256(tbs)

	sig, err := hex.DecodeString(signature)
	if err != nil {
		log.Debugf("failed to extract signature: %v", err)
		return ar.Parse
	}

	log.Debugf("Extracting %v public key", cert.PublicKeyAlgorithm.String())
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Debugf("failed to extract public key from certificate")
		return ar.ParseCert
	}

	// Get signature
	r := new(big.Int)
	s := new(big.Int)
	r.SetBytes(sig[:32])
	s.SetBytes(sig[32:])

	// Verify signature
	ok = ecdsa.Verify(pubKey, digest[:], r, s)
	if !ok {
		log.Debugf("failed to verify ECDSA TCB Info signature")
		return ar.VerifySignature
	}
	log.Tracef("Successfully verified %q ECDSA signature", tbsJsonKey)

	return ar.NotSpecified
}

func extractTbsArea(elem []byte, key string) ([]byte, error) {

	if len(elem) == 0 {
		return nil, fmt.Errorf("internal error: element %v is nil", key)
	}

	var rawMsg map[string]json.RawMessage
	if err := json.Unmarshal(elem, &rawMsg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %v: %w", key, err)
	}
	tbs, ok := rawMsg[key]
	if !ok {
		return nil, fmt.Errorf("failed to extract TBS property for key %v from raw element", key)
	}

	return tbs, nil
}

// teeTcbSvn is only required for TDX (from TdxReportBody)
func ValidateTcbInfo(tcbInfo *pcs.TdxTcbInfo, tcbInfoBodyRaw []byte,
	signingCert, caCert *x509.Certificate,
	sgxExtensions SGXExtensionsValue, teeTcbSvn [16]byte, quoteType QuoteType,
) ar.TcbInfoResult {

	result := ar.TcbInfoResult{}

	if tcbInfo == nil {
		log.Debugf("internal error: tcb info is nil")
		result.Summary.Fail(ar.Internal)
		return result
	}
	if signingCert == nil {
		log.Debugf("internal error: tcb key cert is nil")
		result.Summary.Fail(ar.Internal)
		return result
	}

	errCode := verifyCollateralElem(tcbInfoBodyRaw, tcbInfo.Signature, CN_TCB_SIGNING, TCB_INFO_JSON_KEY, signingCert, caCert)
	if errCode != ar.NotSpecified {
		result.Summary.Fail(errCode)
		return result
	}

	// Verify version
	result.Version = ar.Result{
		Status:   ar.StatusFromBool(tcbInfo.TcbInfo.Version == TCB_INFO_VERSION),
		Got:      fmt.Sprintf("%v", tcbInfo.TcbInfo.Version),
		Expected: fmt.Sprintf("%v", TCB_INFO_VERSION),
	}

	// Verify ID
	result.Id = ar.Result{
		Status:   ar.StatusFromBool(tcbInfo.TcbInfo.ID == TCB_INFO_ID),
		Got:      tcbInfo.TcbInfo.ID,
		Expected: TCB_INFO_ID,
	}

	// Verify expiration
	now := time.Now()
	if now.After(tcbInfo.TcbInfo.NextUpdate) {
		log.Debugf("TCB info has expired since: %v", tcbInfo.TcbInfo.NextUpdate)
		result.Summary.Fail(ar.TcbInfoExpired)
		return result
	}
	log.Tracef("Successfully verified expiration status (next update due: %v)", tcbInfo.TcbInfo.NextUpdate)

	tcbInfoFmspc, err := hex.DecodeString(tcbInfo.TcbInfo.Fmspc)
	if err != nil {
		log.Debugf("failed to deode TCB info FMSPC: %v", err)
		result.Summary.Fail(ar.Parse)
		return result
	}
	if !bytes.Equal(tcbInfoFmspc, sgxExtensions.Fmspc.Value) {
		log.Debugf("FMSPC value from TCB info (%v) and FMSPC value from SGX Extensions in PCK Cert (%v) do not match",
			tcbInfo.TcbInfo.Fmspc, hex.EncodeToString(sgxExtensions.Fmspc.Value))
		result.Summary.Fail(ar.SgxFmpcMismatch)
		return result

	}
	log.Tracef("Successfully verified TCB info FMSPC (%v)", tcbInfo.TcbInfo.Fmspc)

	tcbInfoPceId, err := hex.DecodeString(tcbInfo.TcbInfo.PceID)
	if err != nil {
		log.Debugf("failed to deode TCB info PCE ID: %v", err)
		result.Summary.Fail(ar.Parse)
		return result
	}

	if !bytes.Equal(tcbInfoPceId, sgxExtensions.PceId.Value) {
		log.Debugf("PCEID value from TcbInfo (%v) and PCEID value from SGX Extensions in PCK Cert (%v) do not match",
			tcbInfo.TcbInfo.PceID, sgxExtensions.PceId.Value)
		result.Summary.Fail(ar.SgxPceidMismatch)
		return result
	}
	log.Tracef("Successfully verified TCB info PCE ID (%v)", tcbInfo.TcbInfo.PceID)

	// Checking TCB level: https://api.portal.trustedservices.intel.com/content/documentation.html
	log.Tracef("Checking %v TCB info levels", len(tcbInfo.TcbInfo.TcbLevels))
	tcbLevelCheck := false
	for _, tcbLevel := range tcbInfo.TcbInfo.TcbLevels {

		tcbLevelIteration := true

		log.Tracef("Verifying against TCB level date %v, status %v", tcbLevel.TcbDate, tcbLevel.TcbStatus)

		result.TcbLevel.Date = tcbLevel.TcbDate
		result.TcbLevel.Status = string(tcbLevel.TcbStatus)

		// Compare SGX TCB Comp SVNs from PCK Certificate with TCB Level
		sgxCompResult, ok := compareSgxTcbCompSvns(sgxExtensions, tcbLevel.Tcb.SgxTcbcomponents)
		if !ok {
			log.Debugf("\tComparison against current SGX TCB Info (component levels) not successful")
			tcbLevelIteration = false
		} else {
			log.Debugf("\tSuccessfully verified SGX TCB component SVNs")
		}

		// Compare PCESVN value
		pceSvnResult := ar.Result{
			Status:   ar.StatusFail,
			Expected: fmt.Sprintf("%v", tcbLevel.Tcb.Pcesvn),
			Got:      fmt.Sprintf("%v", sgxExtensions.Tcb.Value.PceSvn.Value),
		}
		if sgxExtensions.Tcb.Value.PceSvn.Value < int(tcbLevel.Tcb.Pcesvn) {
			log.Debugf("\tPCK cert PCE SVN (%v) lower then expected TCB INFO PCE SVN (%v)",
				sgxExtensions.Tcb.Value.PceSvn.Value, tcbLevel.Tcb.Pcesvn)
			log.Debugf("\tComparison against current TCB Info (PCE SVN) not successful")
			tcbLevelIteration = false
		} else {
			log.Debugf("\tSuccessfully verified PCE SVN")
			pceSvnResult.Status = ar.StatusSuccess
		}

		// Only TDX: Compare TEE TCB SVNs from TDX Report with TCB Level and fail if the TCB
		// component was revoked
		var tdxCompResult []ar.Result
		if quoteType == TDX_QUOTE_TYPE {
			tdxCompResult, ok = compareTeeTcbSvns(teeTcbSvn, tcbLevel.Tcb.TdxTcbcomponents)
			if !ok {
				log.Debugf("\tComparison against current TDX TCB Info (component levels) not successful")
				tcbLevelIteration = false
			} else {
				log.Debugf("\tSuccessfully verified Quote TEE TCB component SVNs")
			}
		}

		// Check the revocation status of the component
		if tcbLevel.TcbStatus != pcs.TcbComponentStatusUpToDate {
			log.Debugf("\tCurrent TCB Info level status not up to date (%v)", tcbLevel.TcbStatus)
			tcbLevelIteration = false
		} else {
			log.Debugf("\tSuccessfully verified TCB info status (%v)", tcbLevel.TcbStatus)
		}

		result.TcbLevel = ar.TcbLevelResult{
			Date:          tcbLevel.TcbDate,
			Status:        string(tcbLevel.TcbStatus),
			SgxComponents: sgxCompResult,
			PceSvn:        pceSvnResult,
			TdxComponents: tdxCompResult,
		}

		if tcbLevelIteration {
			tcbLevelCheck = true
			break
		} else {
			log.Debugf("Failed to verify against TCB level date %v", tcbLevel.TcbDate)
		}
	}
	if !tcbLevelCheck {
		result.Summary.Fail(ar.TcbLevelUnsupported)
		return result
	}

	log.Debugf("Successfully validated TCB info")

	result.Summary.Status = ar.StatusSuccess

	return result
}

// verify QE Identity and compare the values to the QE (SGX/TDX)
func ValidateQEIdentity(qeReportBody *EnclaveReportBody, qeIdentity *pcs.QeIdentity,
	qeIdentityBodyRaw []byte, signingCert, caCert *x509.Certificate,
	teeType QuoteType,
) ar.QeReportResult {

	if qeIdentity == nil {
		result := ar.QeReportResult{}
		result.Summary.Fail(ar.Internal, fmt.Errorf("internal error: QE identity is nil"))
		return result
	}
	if signingCert == nil {
		result := ar.QeReportResult{}
		result.Summary.Fail(ar.Internal, fmt.Errorf("internal error: TCB key certificate is nil"))
		return result
	}

	errCode := verifyCollateralElem(qeIdentityBodyRaw, qeIdentity.Signature, CN_TCB_SIGNING, QE_IDENTITY_JSON_KEY,
		signingCert, caCert)
	if errCode != ar.NotSpecified {
		result := ar.QeReportResult{}
		result.Summary.Fail(errCode)
		return result
	}

	return validateQEIdentityProperties(qeReportBody, qeIdentity, teeType)
}

func validateQEIdentityProperties(qeReportBody *EnclaveReportBody, qeIdentity *pcs.QeIdentity, teeType QuoteType) ar.QeReportResult {

	result := ar.QeReportResult{
		Summary: ar.Result{
			Status: ar.StatusSuccess,
		},
	}

	if qeReportBody == nil {
		result.Summary.Fail(ar.Internal, fmt.Errorf("internal error: QE report body is nil"))
		return result
	}
	if qeIdentity == nil {
		result.Summary.Fail(ar.Internal, fmt.Errorf("internal error: QE identity is nil"))
		return result
	}

	switch teeType {

	case TDX_QUOTE_TYPE:
		if qeIdentity.EnclaveIdentity.Version == 2 {
			if qeIdentity.EnclaveIdentity.ID != QE_ID {
				result.Summary.Fail(ar.VerifyQEIdentityErr,
					fmt.Errorf("enclave Identity is not generated for TDX and does not match Quote's TEE"))
				return result
			}
		} else {
			result.Summary.Fail(ar.VerifyQEIdentityErr, fmt.Errorf("unsupported quote type %v", teeType))
			return result
		}

	case SGX_QUOTE_TYPE:
		if qeIdentity.EnclaveIdentity.ID != QE {
			result.Summary.Fail(ar.VerifyQEIdentityErr,
				fmt.Errorf("enclave Identity is not generated for SGX and does not match Quote's TEE"))
			return result
		}

	default:
		result.Summary.Fail(ar.VerifyQEIdentityErr, fmt.Errorf("unknown quote type %v", teeType))
		return result
	}

	now := time.Now()
	if now.After(qeIdentity.EnclaveIdentity.NextUpdate) {
		result.Summary.Fail(ar.VerifyQEIdentityErr,
			fmt.Errorf("qeIdentity has expired since: %v", qeIdentity.EnclaveIdentity.NextUpdate))
	}

	// Check MRSIGNER
	result.MrSigner = ar.Result{
		Expected: hex.EncodeToString(qeIdentity.EnclaveIdentity.Mrsigner.Bytes),
		Got:      hex.EncodeToString(qeReportBody.MRSIGNER[:]),
	}
	if !bytes.Equal(qeIdentity.EnclaveIdentity.Mrsigner.Bytes, qeReportBody.MRSIGNER[:]) {
		log.Debugf("MRSIGNER mismatch. Expected: %v, Got: %v",
			hex.EncodeToString(qeIdentity.EnclaveIdentity.Mrsigner.Bytes),
			hex.EncodeToString(qeReportBody.MRSIGNER[:]))
		result.Summary.Status = ar.StatusFail
		result.MrSigner.Status = ar.StatusFail

	} else {
		log.Tracef("MRSIGNER matches collateral (%v)", hex.EncodeToString(qeReportBody.MRSIGNER[:]))
		result.MrSigner.Status = ar.StatusSuccess
	}

	// Check ISVPRODID
	result.IsvProdId = ar.Result{
		Expected: strconv.FormatUint(uint64(qeIdentity.EnclaveIdentity.IsvProdID), 10),
		Got:      strconv.FormatUint(uint64(qeReportBody.ISVProdID), 10),
	}
	if qeReportBody.ISVProdID != uint16(qeIdentity.EnclaveIdentity.IsvProdID) {
		log.Debugf("IsvProdId mismatch. Expected: %v, Got: %v", qeIdentity.EnclaveIdentity.IsvProdID, qeReportBody.ISVProdID)
		result.Summary.Status = ar.StatusFail
		result.IsvProdId.Status = ar.StatusFail
	} else {
		result.IsvProdId.Status = ar.StatusSuccess
	}

	// Check MISCSELECT
	miscselectMask := binary.LittleEndian.Uint32(qeIdentity.EnclaveIdentity.MiscselectMask.Bytes)
	refMiscSelect := binary.LittleEndian.Uint32(qeIdentity.EnclaveIdentity.Miscselect.Bytes)
	reportMiscSelect := qeReportBody.MISCSELECT & miscselectMask
	result.MiscSelect = ar.Result{
		Expected: strconv.FormatUint(uint64(refMiscSelect), 10),
		Got:      strconv.FormatUint(uint64(reportMiscSelect), 10),
	}
	if refMiscSelect != reportMiscSelect {
		log.Debugf("miscSelect value from QEIdentity: 0x%x does not match miscSelect value from QE Report: 0x%x",
			refMiscSelect, reportMiscSelect)
		result.Summary.Status = ar.StatusFail
		result.MiscSelect.Status = ar.StatusFail
	} else {
		result.MiscSelect.Status = ar.StatusSuccess
	}

	// Check attributes
	attributes_quote := qeReportBody.Attributes
	attributes_mask := qeIdentity.EnclaveIdentity.AttributesMask
	if len(attributes_mask.Bytes) == len(attributes_quote) {
		for i := range attributes_quote {
			attributes_quote[i] &= attributes_mask.Bytes[i]
		}
	}
	result.Attributes = ar.Result{
		Expected: hex.EncodeToString(qeIdentity.EnclaveIdentity.Attributes.Bytes),
		Got:      hex.EncodeToString(attributes_quote[:]),
	}
	if !bytes.Equal([]byte(qeIdentity.EnclaveIdentity.Attributes.Bytes), attributes_quote[:]) {
		log.Debugf("attributes mismatch. Expected: %v, Got: %v",
			hex.EncodeToString(qeIdentity.EnclaveIdentity.Attributes.Bytes),
			hex.EncodeToString(attributes_quote[:]))
		result.Summary.Status = ar.StatusFail
		result.Attributes.Status = ar.StatusFail
	} else {
		result.Attributes.Status = ar.StatusSuccess
	}

	tcbStatus, tcbDate, err := getTcbStatusAndDateQE(qeIdentity, qeReportBody)
	if err != nil {
		result.Summary.Fail(ar.VerifyQEIdentityErr, err)
		result.TcbLevelStatus = "Unknown"
		result.TcbLevelDate = "Unknown"
	}
	log.Debugf("TcbStatus for Enclave Identity TCB Level (ISVSVN: %v): %q",
		qeReportBody.ISVSVN, tcbStatus)

	switch tcbStatus {
	case pcs.TcbComponentStatusRevoked:
		result.TcbLevelStatus = string(tcbStatus)
		result.TcbLevelDate = tcbDate
		result.Summary.Fail(ar.VerifyQEIdentityErr, fmt.Errorf("TCB status: %q", tcbStatus))
	default:
		result.TcbLevelStatus = string(tcbStatus)
		result.TcbLevelDate = tcbDate
	}

	return result
}

// helper function for verifyTcbInfo
func compareSgxTcbCompSvns(sgxExtensions SGXExtensionsValue, sgxTcbComps []pcs.TcbComponent) ([]ar.Result, bool) {
	if len(sgxTcbComps) != 16 {
		log.Debugf("\tUnexpected SGX TCB components length %v", len(sgxTcbComps))
		return nil, false
	}
	// Compare all of the SGX TCB Comp SVNs retrieved from the SGX PCK Certificate (from 01 to 16)
	// with the corresponding values of SVNs in sgxtcbcomponents array of TCB Level.
	ok := true
	results := make([]ar.Result, 16)
	for i := 0; i < 16; i++ {
		tcbFromCert := getTCBCompByIndex(sgxExtensions.Tcb, i+1)
		results[i] = ar.Result{
			Status:   ar.StatusSuccess,
			Got:      fmt.Sprintf("%v", tcbFromCert.Value),
			Expected: fmt.Sprintf("%v", sgxTcbComps[i].Svn),
		}
		if sgxTcbComps[i].Category != "" {
			results[i].Details = fmt.Sprintf("%v: %v", sgxTcbComps[i].Category, sgxTcbComps[i].Type)
		}
		if byte(tcbFromCert.Value) < sgxTcbComps[i].Svn {
			log.Tracef("\tComp_%02v PCK cert SVN %v lower than TCB info SVN %v (Category: %q, Type: %q)",
				i+1, tcbFromCert.Value, sgxTcbComps[i].Svn,
				sgxTcbComps[i].Category, sgxTcbComps[i].Type)
			ok = false
			results[i].Status = ar.StatusFail
		}
	}
	return results, ok
}

// helper function for verifyTcbInfo
func compareTeeTcbSvns(teeTcbSvn [16]byte, tdxTcbComps []pcs.TcbComponent) ([]ar.Result, bool) {
	if len(tdxTcbComps) != 16 {
		log.Debugf("\tUnexpected TDX TCB components length %v", len(tdxTcbComps))
		return nil, false
	}
	// Compare all of the SVNs in TEE TCB SVN array retrieved from TD Report in Quote (from index 0 to 15)
	// with the corresponding values of SVNs in tdxtcbcomponents array of TCB Level
	ok := true
	results := make([]ar.Result, 16)
	for i := 0; i < 16; i++ {
		results[i] = ar.Result{
			Status:   ar.StatusSuccess,
			Got:      fmt.Sprintf("%v", teeTcbSvn[i]),
			Expected: fmt.Sprintf("%v", tdxTcbComps[i].Svn),
		}
		if tdxTcbComps[i].Category != "" {
			results[i].Details = fmt.Sprintf("%v: %v", tdxTcbComps[i].Category, tdxTcbComps[i].Type)
		}
		if teeTcbSvn[i] < tdxTcbComps[i].Svn {
			log.Tracef("\tQuote TEE TCB SVN ID %v (%v) lower than expected TCB info SVN (%v)",
				i, teeTcbSvn[i], tdxTcbComps[i].Svn)
			ok = false
			results[i].Status = ar.StatusFail
		}
	}
	return results, ok
}

func getTcbStatusAndDateQE(qeIdentity *pcs.QeIdentity, body *EnclaveReportBody) (pcs.TcbComponentStatus, string, error) {
	for i := len(qeIdentity.EnclaveIdentity.TcbLevels) - 1; i >= 0; i-- {
		tcbLevel := qeIdentity.EnclaveIdentity.TcbLevels[i]
		if uint16(tcbLevel.Tcb.Isvsvn) <= body.ISVSVN {
			return tcbLevel.TcbStatus, tcbLevel.TcbDate, nil
		}
	}
	return "", "", fmt.Errorf("failed to get TCB status and data QE")
}

// Verifies a given SGX certificate chain, fetches CRLs and checks if the certs are outdated
func VerifyPckCertChain(quoteCerts SgxCertificates, pckCrl, rootCrl *x509.RevocationList) ([][]*x509.Certificate, ar.ErrorCode) {

	// Check PCK certificate
	if err := internal.CheckCert(quoteCerts.PCKCert, CN_PCK_CERT, x509.ECDSAWithSHA256); err != nil {
		log.Debugf("Failed to check PCK cert: %v", err)
		return nil, ar.VerifyPCKChain
	}

	// Check intermediate CA certificate (accept both platform CA and processor CA from PCK Cert issuer)
	if err := internal.CheckCert(quoteCerts.IntermediateCert, quoteCerts.PCKCert.Issuer.CommonName, x509.ECDSAWithSHA256); err != nil {
		log.Debugf("Failed to check intermediate CA cert: %v", err)
		return nil, ar.VerifyPCKChain
	}

	// Check Intel SGX root CA certificate
	if err := internal.CheckCert(quoteCerts.RootCACert, CN_ROOT_CERT, x509.ECDSAWithSHA256); err != nil {
		log.Debugf("Failed to check root CA cert: %v", err)
		return nil, ar.VerifyPCKChain
	}

	// verify PCK certificate chain
	x509CertChains, err := internal.VerifyCertChain(
		[]*x509.Certificate{quoteCerts.PCKCert, quoteCerts.IntermediateCert},
		[]*x509.Certificate{quoteCerts.RootCACert})
	if err != nil {
		log.Debugf("Failed to verify pck certificate chain: %v", err)
		return nil, ar.VerifyPCKChain
	}
	log.Debugf("Successfully verified PCK certificate chain")

	// Verify PCK CRL against intermediate certificate and check PCK cert against CRL
	err = internal.CheckRevocation(pckCrl, quoteCerts.PCKCert, quoteCerts.IntermediateCert)
	if err != nil {
		log.Debugf("CRL check of PCK Cert failed: %v", err)
		return nil, ar.CRLCheckPCK
	}
	log.Debugf("Successfully checked PCK revocation list")

	// Verify Root CRL against root CA certificate and check intermediate cert against CRL
	err = internal.CheckRevocation(rootCrl, quoteCerts.IntermediateCert, quoteCerts.RootCACert)
	if err != nil {
		log.Debugf("CRL check of root CA cert failed: %v", err)
		return nil, ar.CRLCheckRoot
	}
	log.Tracef("Successfully checked root CA revocation list")

	return x509CertChains, ar.NotSpecified
}

func verifyQuoteVersion(quoteVersion, expectedVersion uint16) (ar.Result, bool) {
	r := ar.Result{}
	ok := quoteVersion == expectedVersion
	if !ok {
		log.Debugf("Quote version mismatch: Report = %v, supplied = %v", quoteVersion, expectedVersion)
		r.Status = ar.StatusFail
		r.Expected = strconv.FormatUint(uint64(expectedVersion), 10)
		r.Got = strconv.FormatUint(uint64(quoteVersion), 10)
	} else {
		r.Status = ar.StatusSuccess
	}

	log.Tracef("Quote version %v matches expected version", quoteVersion)

	return r, ok
}

func verifyRootCas(quoteCerts *SgxCertificates, collateral *Collateral, fingerprints []string) ar.ErrorCode {

	if quoteCerts == nil {
		log.Debugf("internal error: quote certs nil")
		return ar.Internal
	}
	if collateral == nil {
		log.Debugf("internal error: collateral is nil")
		return ar.Internal
	}

	// Decode fingerprints
	refFingerprints := make([][]byte, 0, len(fingerprints))
	for _, fingerprint := range fingerprints {
		fp, err := hex.DecodeString(fingerprint)
		if err != nil {
			log.Debugf("Failed to decode CA fingerprint %v: %v", fingerprint, err)
			return ar.ParseCAFingerprint
		}
		refFingerprints = append(refFingerprints, fp)
	}

	log.Debugf("Verify root CAs against %v trusted fingerprints", len(refFingerprints))

	// Verify that the quote CA fingerprint matches a reference CA fingerprint
	pckCaFingerprint := sha256.Sum256(quoteCerts.RootCACert.Raw)
	fpMatch := false
	for _, refFingerprint := range refFingerprints {
		if !bytes.Equal(refFingerprint, pckCaFingerprint[:]) {
			log.Debugf("PCK CA fingerprint %q does not match reference CA fingerprint %q",
				hex.EncodeToString(pckCaFingerprint[:]), hex.EncodeToString(refFingerprint))
			continue
		} else {
			log.Debugf("Found Matching PCK CA fingerprint %q", hex.EncodeToString(refFingerprint))
			fpMatch = true
		}
	}
	if !fpMatch {
		log.Debugf("Failed to find matching fingerprint for PCK CA")
		return ar.CaFingerprint
	}

	// Verify that the TCB info root cert matches a reference CA fingerprint
	tcbInfoCaFingerprint := sha256.Sum256(collateral.TcbInfoRootCert.Raw)
	fpMatch = false
	for _, refFingerprint := range refFingerprints {
		if !bytes.Equal(refFingerprint, tcbInfoCaFingerprint[:]) {
			log.Debugf("TCB info CA fingerprint %q does not match reference CA fingerprint %q",
				hex.EncodeToString(tcbInfoCaFingerprint[:]), hex.EncodeToString(refFingerprint))
			continue
		} else {
			log.Debugf("Found Matching TCB Info CA fingerprint %q", hex.EncodeToString(refFingerprint))
			fpMatch = true
		}
	}
	if !fpMatch {
		log.Debugf("Failed to find matching fingerprint for TCB Info CA")
		return ar.CaFingerprint
	}

	// Verify that the QE identity root cert matches a reference CA fingerprint
	qeIdentityCaFingerprint := sha256.Sum256(collateral.QeIdentityRootCert.Raw)
	fpMatch = false
	for _, refFingerprint := range refFingerprints {
		if !bytes.Equal(refFingerprint, qeIdentityCaFingerprint[:]) {
			log.Debugf("QE identity fingerprint %q does not match reference CA fingerprint %q",
				hex.EncodeToString(qeIdentityCaFingerprint[:]), hex.EncodeToString(refFingerprint))
			continue
		} else {
			log.Debugf("Found Matching QE identity CA fingerprint %q", hex.EncodeToString(refFingerprint))
			fpMatch = true
		}
	}
	if !fpMatch {
		log.Debugf("Failed to find matching fingerprint for QE identity CA")
		return ar.CaFingerprint
	}

	// Verify that the TCB info root cert matches a reference CA fingerprint
	pckCrlCaFingerprint := sha256.Sum256(collateral.PckCrlRootCert.Raw)
	fpMatch = false
	for _, refFingerprint := range refFingerprints {
		if !bytes.Equal(refFingerprint, pckCrlCaFingerprint[:]) {
			log.Debugf("PCK CRL CA fingerprint %q does not match reference CA fingerprint %q",
				hex.EncodeToString(pckCrlCaFingerprint[:]), hex.EncodeToString(refFingerprint))
			continue
		} else {
			log.Debugf("Found Matching PCK CRL CA fingerprint %q", hex.EncodeToString(refFingerprint))
			fpMatch = true
		}
	}
	if !fpMatch {
		log.Debugf("Failed to find matching fingerprint for PCK CRL CA")
		return ar.CaFingerprint
	}

	return ar.NotSpecified
}
