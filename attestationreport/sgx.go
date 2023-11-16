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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"time"

	"github.com/Fraunhofer-AISEC/cmc/internal"
)

const (
	SGX_QUOTE_TYPE uint32 = 0x0
	TDX_QUOTE_TYPE uint32 = 0x81

	ecdsa_p_256    = 2
	QUOTE_MIN_SIZE = 1020 // value from Intel SGX QVL

	QUOTE_HEADER_SIZE          = 48
	SGX_QUOTE_BODY_SIZE        = 384
	SGX_QUOTE_SIGNATURE_OFFSET = 436
	TDX_QUOTE_BODY_SIZE        = 584
	TDX_QUOTE_SIGNATURE_OFFSET = 636

	TDX_ID = "TDX"
	SGX_ID = "SGX"

	// Params: ca = processor or platform, encoding = pem or der
	PCS_PCK_CERT_CRL_URI = "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=%v&encoding=der"
	PCS_ROOT_CA_CRL_URI  = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
	ROOT_CA_CRL_NAME     = "RootCaCRL"
	PCK_CERT_CRL_NAME    = "PCKCertCRL"

	SGX_EXTENSION_INDEX = 5
)

// main function to very a SGX Quote + Measurements
func verifySgxMeasurements(sgxM *SgxMeasurement, nonce []byte, referenceValues []ReferenceValue) (*SgxMeasurementResult, bool) {
	var err error
	result := &SgxMeasurementResult{}
	ok := true

	// If the attestationreport does contain neither SGX measurements, nor SGX Reference Values
	// there is nothing to to
	if sgxM == nil && len(referenceValues) == 0 {
		return nil, true
	}

	if len(referenceValues) == 0 {
		msg := "Could not find SGX Reference Value"
		result.Summary.setFalse(&msg)
		return result, false
	} else if len(referenceValues) > 1 {
		msg := fmt.Sprintf("Report contains %v reference values. Currently, only one SGX Reference Value is supported",
			len(referenceValues))
		result.Summary.setFalse(&msg)
		return result, false
	}
	sgxReferenceValue := referenceValues[0]

	// If the attestationreport contains SGX Reference Values, but no SGX measurement, the attestation must fail
	if sgxM == nil {
		for _, v := range referenceValues {
			result.Artifacts = append(result.Artifacts,
				DigestResult{
					Name:    v.Name,
					Digest:  hex.EncodeToString(v.Sha256),
					Success: false,
					Type:    "Reference Value",
				})
		}
		result.Summary.Success = false
		return result, false
	}

	// Validate Parameters:
	if sgxM.Report == nil || len(sgxM.Report) < QUOTE_MIN_SIZE {
		msg := "Invalid SGX Report."
		result.Summary.setFalse(&msg)
		return result, false
	}

	if sgxReferenceValue.Type != "SGX Reference Value" {
		msg := fmt.Sprintf("SGX Reference Value invalid type %v", sgxReferenceValue.Type)
		result.Summary.setFalse(&msg)
		return result, false
	}

	if sgxReferenceValue.Sgx == nil {
		msg := "SGX Reference Value is null"
		result.Summary.setFalse(&msg)
		return result, false
	}

	var sgxQuote SgxReport
	var quoteType uint32 = sgxReferenceValue.Sgx.Collateral.TeeType
	if quoteType == SGX_QUOTE_TYPE {
		// extract the attestation report into the SGXReport data structure
		sgxQuote, err = DecodeSgxReport(sgxM.Report)
		if err != nil {
			msg := fmt.Sprintf("Failed to decode SGX report: %v", err)
			result.Summary.setFalse(&msg)
			return result, false
		}
	} else {
		log.Tracef("Unknown quote type (tee_type: %X)\n", quoteType)
		return result, false
	}
	fmt.Println("QuoteSignatureDataLen: ", sgxQuote.QuoteSignatureDataLen)

	// Compare Nonce for Freshness (called Report Data in the SNP Attestation Report Structure)
	// ReportData contains: nonce in ReportData field
	nonce64 := make([]byte, 64)
	copy(nonce64, nonce[:])

	if cmp := bytes.Compare(sgxQuote.ISVEnclaveReport.ReportData[:], nonce64); cmp != 0 {
		msg := fmt.Sprintf("Nonces mismatch: Plain Nonce: %v, Expected: %v, Got = %v",
			nonce, hex.EncodeToString(nonce64), hex.EncodeToString(sgxQuote.ISVEnclaveReport.ReportData[:]))
		result.Freshness.setFalse(&msg)
		result.Summary.Success = false
		return result, false
	} else {
		result.Freshness.Success = true
	}

	// parse cert chain
	referenceCerts, err := ParseCertificates(sgxM.Certs, true)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse reference certificates: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}
	fmt.Println("certs:", referenceCerts)

	var current_time time.Time = time.Now()
	log.Trace("current time: ", current_time)

	// (from DCAP Library): parse PCK Cert chain (from the quote) into CertificateChain object. return error in case of failure
	// TODO: handle other QECertDataTypes (for now: throw an error)
	var quoteCerts SgxCertificates
	if sgxQuote.QuoteSignatureData.QECertDataType == 5 {
		quoteCerts, err = ParseCertificates(sgxQuote.QuoteSignatureData.QECertData, true)
		if err != nil {
			msg := fmt.Sprintf("Failed to parse certificate chain from QECertData: %v", err)
			result.Summary.setFalse(&msg)
			return result, false
		}
	} else {
		msg := fmt.Sprintf("QECertDataType not supported: %v", sgxQuote.QuoteSignatureData.QECertDataType)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// (from DCAP Library): extract root CA from PCK cert chain in quote -> compare nullptr
	if quoteCerts.RootCACert == nil {
		msg := "root cert is null"
		result.Summary.setFalse(&msg)
		return result, false
	}

	// (from DCAP Library): check root public key
	if !reflect.DeepEqual(quoteCerts.RootCACert.PublicKey, referenceCerts.RootCACert.PublicKey) {
		msg := "root cert public key didn't match"
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
	tcbInfo, err := ParseTcbInfo(sgxReferenceValue.Sgx.Collateral.TcbInfo)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse tcbInfo: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	tcbInfoResult, err := verifyTcbInfo(&tcbInfo, string(sgxReferenceValue.Sgx.Collateral.TcbInfo), referenceCerts.TCBSigningCert, sgxExtensions,
		[16]byte{}, SGX_QUOTE_TYPE)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify TCB info structure: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}
	result.TcbInfoCheck = tcbInfoResult

	// (from DCAP Library): parse and verify QE Identity object
	qeIdentity, err := ParseQEIdentity(sgxReferenceValue.Sgx.Collateral.QeIdentity)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse tcbInfo: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	qeIdentityResult, err := VerifyQEIdentity(&sgxQuote.QuoteSignatureData.QEReport, &qeIdentity,
		string(sgxReferenceValue.Sgx.Collateral.QeIdentity), referenceCerts.TCBSigningCert, SGX_QUOTE_TYPE)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify QE Identity structure: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}
	result.QeIdentityCheck = qeIdentityResult

	// Verify Quote Signature
	sig, ret := VerifyIntelQuoteSignature(sgxM.Report, sgxQuote.QuoteSignatureData,
		sgxQuote.QuoteSignatureDataLen, int(sgxQuote.QuoteHeader.AttestationKeyType), referenceCerts,
		sgxReferenceValue.Sgx.CaFingerprint, quoteType)
	if !ret {
		msg := fmt.Sprintf("Failed to verify Quote Signature: %v", sig)
		result.Summary.setFalse(&msg)
		return result, false
	}

	result.Signature = sig

	// Verify Quote Body values
	err = VerifySgxQuoteBody(&sgxQuote.ISVEnclaveReport, &tcbInfo, &quoteCerts, &sgxReferenceValue, result)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify Enclave Report Values: %v", err)
		result.Summary.setFalse(&msg)
		result.Summary.Success = false
		return result, false
	} else {
		result.Artifacts = append(result.Artifacts,
			DigestResult{
				Name:    sgxReferenceValue.Name,
				Digest:  hex.EncodeToString(sgxQuote.ISVEnclaveReport.MRENCLAVE[:]),
				Success: true,
			})
		ok = true
	}

	// Compare SGX Parameters
	result.VersionMatch, ret = verifyQuoteVersion(sgxQuote.QuoteHeader, sgxReferenceValue.Sgx.Version)
	if !ret {
		return result, false
	}

	result.PolicyCheck, ret = verifySgxPolicy(sgxQuote, sgxReferenceValue.Sgx.Policy)
	if !ret {
		ok = false
	}

	result.Summary.Success = ok

	return result, ok
}

// TODO: implement this function
func verifySgxPolicy(s SgxReport, v SgxPolicy) (PolicyCheck, bool) {
	r := PolicyCheck{}

	return r, true
}

func verifyQuoteVersion(quote QuoteHeader, version uint16) (Result, bool) {
	r := Result{}
	ok := quote.Version == version
	if !ok {
		msg := fmt.Sprintf("Quote version mismatch: Report = %v, supplied = %v", quote.Version, version)
		r.setFalse(&msg)
	} else {
		r.Success = true
	}
	return r, ok
}

// verifies the quote signature
// Can be used by SGX/TDX: QuoteType = 0x00 (sgx) or 0x81 (TDX)
// TODO: Handle different QE Cert Data Types in here
func VerifyIntelQuoteSignature(reportRaw []byte, quoteSignature any,
	quoteSignatureSize uint32, quoteSignatureType int, certs SgxCertificates,
	fingerprint string, quoteType uint32) (SignatureResult, bool) {
	result := SignatureResult{}
	var digest [32]byte
	var ak_pub [64]byte // attestation public key (generated by the QE)
	var reportData [64]byte
	var hash_ref [32]byte

	// check signature type and size
	if quoteType == SGX_QUOTE_TYPE {
		if uint32(len(reportRaw)-SGX_QUOTE_SIGNATURE_OFFSET) != quoteSignatureSize {
			msg := fmt.Sprintf("parsed QuoteSignatureData size doesn't match QuoteSignatureDataLen. expected: %v, got: %v\n",
				quoteSignatureSize, uint32(len(reportRaw)-signature_offset))
			result.SignCheck.setFalse(&msg)
			return result, false
		}
	} else if quoteType == TDX_QUOTE_TYPE {
		if uint32(len(reportRaw)-TDX_QUOTE_SIGNATURE_OFFSET) != quoteSignatureSize {
			msg := fmt.Sprintf("parsed QuoteSignatureData size doesn't match QuoteSignatureDataLen. expected: %v, got: %v\n",
				quoteSignatureSize, uint32(len(reportRaw)-signature_offset))
			result.SignCheck.setFalse(&msg)
			return result, false
		}
	} else {
		msg := fmt.Sprintf("Quote Type not supported %v", quoteType)
		result.SignCheck.setFalse(&msg)
		return result, false
	}

	// for now: check attestation signature type = key type
	if quoteSignatureType != ecdsa_p_256 {
		msg := fmt.Sprintf("Signature Algorithm %v not supported", quoteSignatureType)
		result.SignCheck.setFalse(&msg)
		return result, false
	}

	// Step 1: Verify ISV Enclave Report Signature
	// Convert r, s to Big Int
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
		msg := "Failed to extract ECDSA public key from certificate"
		result.SignCheck.setFalse(&msg)
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
		msg := "Failed to verify ISV Enclave report signature"
		result.SignCheck.setFalse(&msg)
		return result, false
	}
	log.Trace("Successfully verified ISV Enclave report signature")
	result.SignCheck.Success = true

	// Step 2: Verify QE Report Signature
	// get QE Report from QE Report Signature Data
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
		msg := "Failed to extract PCK public key from certificate"
		result.SignCheck.setFalse(&msg)
		return result, false
	}

	// Verify the ECDSA QEReportSignature
	ok = ecdsa.Verify(pck_pub, digest[:], r, s)
	if !ok {
		msg := "Failed to verify QE report signature"
		result.SignCheck.setFalse(&msg)
		return result, false
	}

	log.Trace("Successfully verified QE report signature")
	result.SignCheck.Success = true

	// Step 3: Verify Report Data: SHA256(ECDSA Attestation Key || QE Authentication Data) || 32-0x00’s)

	reportDataRef := append(hash_ref[:], make([]byte, 32)...)

	if !bytes.Equal(reportData[:], reportDataRef[:]) {
		msg := fmt.Sprintf("invalid SHA256(ECDSA Attestation Key || QE Authentication Data) || 32*0x00) in QEReport.ReportData. expected: %v, got: %v\n", reportDataRef, reportData)
		result.CertChainCheck.setFalse(&msg)
		return result, false
	}

	// Step 4: Parse and verify the entire PCK certificate chain
	x509Chains, err := VerifyIntelCertChainFull(certs)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify certificate chain: %v", err)
		result.CertChainCheck.setFalse(&msg)
		return result, false
	}

	// Step 5: Verify that the reference value fingerprint matches the certificate fingerprint
	refFingerprint, err := hex.DecodeString(fingerprint)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode CA fingerprint %v: %v", fingerprint, err)
		result.CertChainCheck.setFalse(&msg)
		return result, false
	}
	caFingerprint := sha256.Sum256(certs.RootCACert.Raw)
	if !bytes.Equal(refFingerprint, caFingerprint[:]) {
		msg := fmt.Sprintf("CA fingerprint %v does not match measurement CA fingerprint %v",
			fingerprint, hex.EncodeToString(caFingerprint[:]))
		result.CertChainCheck.setFalse(&msg)
		return result, false
	}
	result.CertChainCheck.Success = true

	// Step 6: Store details from (all) validated certificate chain(s) in the report
	for _, chain := range x509Chains {
		chainExtracted := []X509CertExtracted{}
		for _, cert := range chain {
			chainExtracted = append(chainExtracted, ExtractX509Infos(cert))
		}
		result.ValidatedCerts = append(result.ValidatedCerts, chainExtracted)
	}

	return result, true
}

// teeTcbSvn is only required for TDX (from TdxReportBody)
func verifyTcbInfo(tcbInfo *TcbInfo, tcbInfoBodyRaw string, tcbKeyCert *x509.Certificate,
	sgxExtensions SGXExtensionsValue, teeTcbSvn [16]byte, quoteType uint32) (TcbLevelCheck, error) {
	var result TcbLevelCheck

	if tcbInfo == nil || tcbKeyCert == nil {
		return result, fmt.Errorf("invalid function parameter (null pointer exception)")
	}

	regex := regexp.MustCompile(`\s+`)
	regex.ReplaceAllString(tcbInfoBodyRaw, "")                       // remove whitespace
	tcbInfoBodyRaw = tcbInfoBodyRaw[11 : len(tcbInfoBodyRaw)-128-16] // remove "{"tcbInfo":" from beginning and signature + rest from the end

	// get checksum of tcb info body
	digest := sha256.Sum256([]byte(tcbInfoBodyRaw))

	// get signature
	r := new(big.Int)
	s := new(big.Int)
	r.SetBytes(tcbInfo.Signature[:32])
	s.SetBytes(tcbInfo.Signature[32:])

	pub_key, ok := tcbKeyCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		result.Summary.Success = false
		result.Summary.Details = "failed to extract public key from certificate"
		return result, fmt.Errorf("failed to extract public key from certificate")
	}

	// verify signature
	ok = ecdsa.Verify(pub_key, digest[:], r, s)
	if !ok {
		result.Summary.Success = false
		result.Summary.Details = "failed to verify tcbInfo signature"
		return result, fmt.Errorf("failed to verify tcbInfo signature")
	}

	now := time.Now()

	if now.After(tcbInfo.TcbInfo.NextUpdate) {
		result.Summary.Success = false
		result.Summary.Details = fmt.Sprintf("tcbInfo has expired since: %v", tcbInfo.TcbInfo.NextUpdate)
		return result, fmt.Errorf("tcbInfo has expired since: %v", tcbInfo.TcbInfo.NextUpdate)
	}

	if !reflect.DeepEqual([]byte(tcbInfo.TcbInfo.Fmspc), sgxExtensions.Fmspc.Value) {
		result.Summary.Success = false
		result.Summary.Details = fmt.Sprintf("FMSPC value from TcbInfo (%v) and FMSPC value from SGX Extensions in PCK Cert (%v) do not match",
			tcbInfo.TcbInfo.Fmspc, sgxExtensions.Fmspc.Value)
		return result, fmt.Errorf("FMSPC value from TcbInfo (%v) and FMSPC value from SGX Extensions in PCK Cert (%v) do not match",
			tcbInfo.TcbInfo.Fmspc, sgxExtensions.Fmspc.Value)
	}

	if !reflect.DeepEqual([]byte(tcbInfo.TcbInfo.PceId), sgxExtensions.PceId.Value) {
		result.Summary.Success = false
		result.Summary.Details = fmt.Sprintf("PCEID value from TcbInfo (%v) and PCEID value from SGX Extensions in PCK Cert (%v) do not match",
			tcbInfo.TcbInfo.PceId, sgxExtensions.PceId.Value)
		return result, fmt.Errorf("PCEID value from TcbInfo (%v) and PCEID value from SGX Extensions in PCK Cert (%v) do not match",
			tcbInfo.TcbInfo.PceId, sgxExtensions.PceId.Value)
	}

	// checking tcb level
	for _, tcbLevel := range tcbInfo.TcbInfo.TcbLevels {
		// Compare SGX TCB Comp SVNs from PCK Certificate with TCB Level
		if compareSgxTcbCompSvns(sgxExtensions, tcbLevel) {
			// Compare PCESVN value
			if sgxExtensions.Tcb.Value.PceSvn.Value >= int(tcbLevel.Tcb.PceSvn) {
				if quoteType == SGX_QUOTE_TYPE {
					result.Summary.Success = true
					result.TcbLevelDate = tcbLevel.TcbDate
					result.TcbLevelStatus = tcbLevel.TcbStatus
					return result, nil
				} else {
					// Compare TEE TCB SVNs from TDX Report with TCB Level
					if compareTeeTcbSvns(teeTcbSvn, tcbLevel) {
						if tcbLevel.Tcb.TdxTcbComponents[1].Svn == teeTcbSvn[1] {
							// fail if Status == REVOKED
							if tcbLevel.TcbStatus == string(Revoked) {
								result.Summary.Success = false
								result.TcbLevelStatus = string(Revoked)
								result.TcbLevelDate = tcbLevel.TcbDate
								return result, fmt.Errorf("TCB Level status: REVOKED")
							}
							result.Summary.Success = true
							result.TcbLevelDate = tcbLevel.TcbDate
							result.TcbLevelStatus = tcbLevel.TcbStatus
							return result, nil
						} else {
							result.Summary.Success = false
							result.Summary.Details = "TCB Level rejected: unsupported"
							return result, fmt.Errorf("TCB Level rejected: unsupported")
						}
					}
				}
			}
		}
	}
	// - Check if TCB Level status is OutOfDate/REVOKED/ConfigurationNeeded/ConfigurationAndSWHardeningNeeded/UpToDate/SWHardeningNeeded/OutOfDateConfigurationNeeded/TCB Level error status is unrecognized
	// - handle result of TCB Status based on policy

	result.Summary.Success = false
	result.Summary.Details = "TCB Level not supported"
	return result, fmt.Errorf("TCB Level not supported")
}

// helper function for verifyTcbInfo
func compareSgxTcbCompSvns(sgxExtensions SGXExtensionsValue, tcbLevel TcbLevel) bool {
	// Compare all of the SGX TCB Comp SVNs retrieved from the SGX PCK Certificate (from 01 to 16)
	// with the corresponding values of SVNs in sgxtcbcomponents array of TCB Level.
	for i := 0; i < 16; i++ {
		tcbFromCert := GetTCBCompByIndex(sgxExtensions.Tcb, i+1)
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

// Only for SGX report body
func VerifySgxQuoteBody(body *EnclaveReportBody, tcbInfo *TcbInfo,
	certs *SgxCertificates, sgxReferenceValue *ReferenceValue, result *SgxMeasurementResult) error {
	if body == nil || tcbInfo == nil || certs == nil || sgxReferenceValue == nil || result == nil {
		return fmt.Errorf("invalid function parameter (null pointer exception)")
	}

	// check MRENCLAVE reference value
	if !reflect.DeepEqual(body.MRENCLAVE[:], []byte(sgxReferenceValue.Sha256)) {
		result.Artifacts = append(result.Artifacts,
			DigestResult{
				Name:    sgxReferenceValue.Name,
				Digest:  hex.EncodeToString(sgxReferenceValue.Sha256[:]),
				Success: false,
			})
		return fmt.Errorf("MRENCLAVE mismatch. Expected: %v, Got. %v", sgxReferenceValue.Sha256, body.MRENCLAVE)
	} else {
		result.Artifacts = append(result.Artifacts,
			DigestResult{
				Name:    sgxReferenceValue.Name,
				Digest:  hex.EncodeToString(body.MRENCLAVE[:]),
				Success: true,
			})
	}

	// check attributes
	attributes_quote := body.Attributes

	if !reflect.DeepEqual(sgxReferenceValue.Sgx.Attributes[:], attributes_quote[:]) {
		return fmt.Errorf("attributes mismatch. Expected: %v, Got: %v", sgxReferenceValue.Sgx.Attributes, attributes_quote)
	}

	// check mrsigner value
	refSigner, err := hex.DecodeString(sgxReferenceValue.Sgx.MRSIGNER)
	if err != nil {
		return fmt.Errorf("decoding MRSIGNER reference value failed: %v", err)
	}

	if !reflect.DeepEqual(refSigner, body.MRSIGNER[:]) {
		return fmt.Errorf("MRSIGNER mismatch. Expected: %v, Got: %v", []byte(sgxReferenceValue.Sgx.MRSIGNER), body.MRSIGNER)
	}

	// check isvProdId value
	if body.ISVProdID != sgxReferenceValue.Sgx.IsvProdId {
		return fmt.Errorf("IsvProdId mismatch. Expected: %v, Got: %v", sgxReferenceValue.Sgx.IsvProdId, body.ISVProdID)
	}

	// TODO: check CPUSVN from report body

	return nil
}

// verify QE Identity and compare the values to the QE (SGX/TDX)
func VerifyQEIdentity(qeReportBody *EnclaveReportBody, qeIdentity *QEIdentity, qeIdentityBodyRaw string, tcbKeyCert *x509.Certificate, teeType uint32) (TcbLevelCheck, error) {
	result := TcbLevelCheck{}
	if qeReportBody == nil || qeIdentity == nil || tcbKeyCert == nil {
		return result, fmt.Errorf("invalid function parameter (null pointer exception)")
	}

	regex := regexp.MustCompile(`\s+`)
	regex.ReplaceAllString(qeIdentityBodyRaw, "")                             // remove whitespace
	qeIdentityBodyRaw = qeIdentityBodyRaw[19 : len(qeIdentityBodyRaw)-128-16] // remove "{"enclaveIdentity":" from beginning and signature + rest from the end

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

	// from Intel SGX DCAP Library
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
		msg := fmt.Sprintf("MRSIGNER mismatch. Expected: %v, Got: %v", qeIdentity.EnclaveIdentity.Mrsigner, qeReportBody.MRSIGNER)
		result.Summary.Details = msg
		result.Summary.Success = false
		return result, nil
	}

	// check isvProdId
	if qeReportBody.ISVProdID != uint16(qeIdentity.EnclaveIdentity.IsvProdId) {
		msg := fmt.Sprintf("IsvProdId mismatch. Expected: %v, Got: %v", qeIdentity.EnclaveIdentity.IsvProdId, qeReportBody.ISVProdID)
		result.Summary.Details = msg
		result.Summary.Success = false
		return result, nil
	}

	// check miscselect
	miscselectMask := binary.LittleEndian.Uint32(qeIdentity.EnclaveIdentity.MiscselectMask)
	if binary.LittleEndian.Uint32(qeIdentity.EnclaveIdentity.Miscselect) != (qeReportBody.MISCSELECT & miscselectMask) {
		msg := fmt.Sprintf("miscSelect value from QEIdentity: %v does not match miscSelect value from QE Report: %v",
			qeIdentity.EnclaveIdentity.Miscselect, (qeReportBody.MISCSELECT & miscselectMask))
		result.Summary.Details = msg
		result.Summary.Success = false
		return result, nil
	}

	// check attributes
	attributes_quote := qeReportBody.Attributes
	attributes_mask := qeIdentity.EnclaveIdentity.AttributesMask
	if len(attributes_mask) == len(attributes_quote) {
		for i := range attributes_quote {
			attributes_quote[i] &= attributes_mask[i]
		}
	}
	if !reflect.DeepEqual([]byte(qeIdentity.EnclaveIdentity.Attributes), attributes_quote[:]) {
		msg := fmt.Sprintf("attributes mismatch. Expected: %v, Got: %v", qeIdentity.EnclaveIdentity.Attributes, attributes_quote)
		result.Summary.Details = msg
		result.Summary.Success = false
		return result, nil
	}

	tcbStatus, tcbDate := getTcbStatusAndDateQE(qeIdentity, qeReportBody)
	log.Tracef("TcbStatus for Enclave's Identity tcbLevel (isvSvn: %v): '%v'", qeReportBody.ISVSVN, tcbStatus)

	switch tcbStatus {
	case Revoked:
		fallthrough
	case NotSupported:
		result.Summary.Details = "invalid tcbStatus"
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

	if !reflect.DeepEqual(crl.RawIssuer, cert.RawIssuer) {
		return false, fmt.Errorf("CRL RawIssuer is invalid. got: %v, expected: %v ", crl.RawIssuer, cert.RawIssuer)
	}

	// Check if certificate has been revoked
	for _, revokedCert := range crl.RevokedCertificates {
		if cert.SerialNumber == revokedCert.SerialNumber {
			return false, fmt.Errorf("certificate has been revoked since: %v", revokedCert.RevocationTime)
		}
	}

	return true, nil
}

// fetch the CRL either from cache or download it from PCS
// TODO (important): implement dedicated update mechanism (currently only retrieved once from PCS and stored on the filesystem for testing)
func fetchCRL(uri string, name string) (*x509.RevocationList, error) {
	_, err := os.Stat(name)
	if err == nil {
		fmt.Printf("File %s exists.\n", name)
		// Read CRL
		crl_raw, err := os.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("failed to read quote.dat: %w", err)
		}
		// Parse CRL
		crl, err := x509.ParseRevocationList(crl_raw)
		if err != nil {
			return nil, err
		}
		return crl, nil
	} else if os.IsNotExist(err) {
		return downloadCRL(uri, name)
	} else {
		return nil, err
	}
}

func downloadCRL(uri string, name string) (*x509.RevocationList, error) {
	// Download CRL from PCS
	resp, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status code: %d", resp.StatusCode)
	}

	// Read response body into a byte slice
	crlData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// Store CRL in file
	err = os.WriteFile(name, crlData, 0644)
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

// verifies the given SGX certificate chain, fetches CRLs and chechs if the certs are outdated
// writes results back to verification report
func VerifyIntelCertChainFull(quoteCerts SgxCertificates) ([][]*x509.Certificate, error) {
	// verify PCK certificate chain
	x509CertChains, err := internal.VerifyCertChain(
		[]*x509.Certificate{quoteCerts.PCKCert, quoteCerts.IntermediateCert},
		[]*x509.Certificate{quoteCerts.RootCACert})
	if err != nil {
		msg := fmt.Sprintf("Failed to verify pck certificate chain: %v", err)
		return nil, errors.New(msg)
	}

	// download CRLs from PCS
	root_ca_crl, err := fetchCRL(PCS_ROOT_CA_CRL_URI, ROOT_CA_CRL_NAME)
	if err != nil {
		msg := fmt.Sprintf("downloading ROOT CA CRL from PCS failed: %v", err)
		return nil, errors.New(msg)
	}

	pck_crl_uri := fmt.Sprintf(PCS_PCK_CERT_CRL_URI, "processor")
	pck_crl, err := fetchCRL(pck_crl_uri, PCK_CERT_CRL_NAME)
	if err != nil {
		msg := fmt.Sprintf("downloading PCK Cert CRL from PCS failed: %v", err)
		return nil, errors.New(msg)
	}

	// perform CRL checks (signature + values)
	res, err := CrlCheck(root_ca_crl, quoteCerts.RootCACert, quoteCerts.RootCACert)
	if !res || err != nil {
		msg := fmt.Sprintf("CRL check on rootCert failed: %v", err)
		return nil, errors.New(msg)
	}

	res, err = CrlCheck(pck_crl, quoteCerts.PCKCert, quoteCerts.IntermediateCert)
	if !res || err != nil {
		msg := fmt.Sprintf("CRL check on pckCert failed: %v", err)
		return nil, errors.New(msg)
	}

	return x509CertChains, nil
}

func VerifyTCBSigningCertChain(quoteCerts SgxCertificates) ([][]*x509.Certificate, error) {
	// verify TCB Signing cert chain
	tcbSigningCertChain, err := internal.VerifyCertChain(
		[]*x509.Certificate{quoteCerts.TCBSigningCert},
		[]*x509.Certificate{quoteCerts.RootCACert})
	if err != nil {
		msg := fmt.Sprintf("Failed to verify TCB Signing certificate chain: %v", err)
		return nil, errors.New(msg)
	}

	root_ca_crl, err := fetchCRL(PCS_ROOT_CA_CRL_URI, ROOT_CA_CRL_NAME)
	if err != nil {
		msg := fmt.Sprintf("downloading Root CA CRL from PCS failed: %v", err)
		return nil, errors.New(msg)
	}

	// perform CRL checks (signature + values)
	res, err := CrlCheck(root_ca_crl, quoteCerts.TCBSigningCert, quoteCerts.RootCACert)
	if !res || err != nil {
		msg := fmt.Sprintf("CRL check on TcbSigningCert failed: %v", err)
		return nil, errors.New(msg)
	}

	return tcbSigningCertChain, nil
}
