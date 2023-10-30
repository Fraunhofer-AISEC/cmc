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
	"fmt"
	"io/ioutil"
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
	TDX_QUOTE_SIGNATURE_OFFSET = 632

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
	certs, err := ParseCertificates(sgxM.Certs, true)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse certificates: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}
	fmt.Println("certs:", certs)

	var current_time time.Time = time.Now()
	log.Trace("current time: ", current_time)

	// (from DCAP Library): parse PCK Cert chain (from the quote) into CertificateChain object. return error in case of failure
	// TODO: handle other QECertDataTypes (for now: throw an error)
	var certChain SgxCertificates
	if sgxQuote.QuoteSignatureData.QECertDataType == 5 {
		certChain, err = ParseCertificates(sgxQuote.QuoteSignatureData.QECertData, true)
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
	if certChain.RootCACert == nil {
		msg := "root cert is null"
		result.Summary.setFalse(&msg)
		return result, false
	}

	// (from DCAP Library): check root public key
	if !reflect.DeepEqual(certChain.RootCACert.PublicKey, certs.RootCACert.PublicKey) {
		msg := "root cert public key didn't match"
		result.Summary.setFalse(&msg)
		return result, false
	}

	// (from DCAP Library): parse and verify PCK certificate chain
	x509CertChains, err := internal.VerifyCertChain(
		[]*x509.Certificate{certChain.PCKCert, certChain.IntermediateCert},
		[]*x509.Certificate{certChain.RootCACert})
	if err != nil {
		msg := fmt.Sprintf("Failed to verify pck certificate chain: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// download CRLs from PCS
	root_ca_crl, err := fetchCRL(PCS_ROOT_CA_CRL_URI, ROOT_CA_CRL_NAME)
	if err != nil {
		msg := fmt.Sprintf("downloading ROOT CA CRL from PCS failed: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	pck_crl_uri := fmt.Sprintf(PCS_PCK_CERT_CRL_URI, "processor")
	pck_crl, err := fetchCRL(pck_crl_uri, PCK_CERT_CRL_NAME)
	if err != nil {
		msg := fmt.Sprintf("downloading PCK Cert CRL from PCS failed: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// perform CRL checks (signature + values)
	res, err := CrlCheck(root_ca_crl, certChain.RootCACert, certChain.RootCACert)
	if !res || err != nil {
		msg := fmt.Sprintf("CRL check on rootCert failed: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	res, err = CrlCheck(pck_crl, certChain.PCKCert, certChain.IntermediateCert)
	if !res || err != nil {
		msg := fmt.Sprintf("CRL check on pckCert failed: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Store details from validated certificate chain(s) in the report
	for _, chain := range x509CertChains {
		chainExtracted := []X509CertExtracted{}
		for _, cert := range chain {
			chainExtracted = append(chainExtracted, ExtractX509Infos(cert))
		}
		result.Signature.ValidatedCerts = append(result.Signature.ValidatedCerts, chainExtracted)
	}

	// (from DCAP Library): parse and verify TcbInfo object
	tcbInfo, err := ParseTcbInfo(sgxReferenceValue.Sgx.Collateral.TcbInfo)
	if err != nil {
		log.Trace("tcb_info:", sgxReferenceValue.Sgx.Collateral.TcbInfo)
		msg := fmt.Sprintf("Failed to parse tcbInfo: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	err = verifyTcbInfo(&tcbInfo, string(sgxReferenceValue.Sgx.Collateral.TcbInfo), certs.TCBSigningCert)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify TCB info structure: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// (from DCAP Library): parse and verify QE Identity object
	qeIdentity, err := ParseQEIdentity(sgxReferenceValue.Sgx.Collateral.QeIdentity)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse tcbInfo: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	err = VerifyQEIdentity(&sgxQuote.QuoteSignatureData.QEReport, &qeIdentity,
		string(sgxReferenceValue.Sgx.Collateral.QeIdentity), certs.TCBSigningCert, SGX_QUOTE_TYPE)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify QE Identity structure: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Verify Quote Signature
	sig, ret := VerifyIntelQuoteSignature(sgxM.Report, sgxQuote.QuoteSignatureData,
		sgxQuote.QuoteSignatureDataLen, int(sgxQuote.QuoteHeader.AttestationKeyType), certs,
		sgxReferenceValue.Sgx.CAfingerprint, SGX_QUOTE_TYPE)
	if !ret {
		msg := fmt.Sprintf("Failed to verify Quote Signature: %v", sig)
		result.Summary.setFalse(&msg)
		return result, false
	}

	result.Signature = sig

	// check version
	result.VersionMatch, ret = verifySgxVersion(sgxQuote.QuoteHeader, sgxReferenceValue.Sgx.Version)
	if !ret {
		return result, false
	}

	// Verify Quote Body values
	err = VerifyEnclaveReportValues(&sgxQuote.ISVEnclaveReport, &tcbInfo, &certChain, &sgxReferenceValue, result)
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

	result.Summary.Success = ok

	return result, ok
}

func verifySgxVersion(quote QuoteHeader, version uint16) (Result, bool) {
	r := Result{}
	ok := quote.Version == version
	if !ok {
		msg := fmt.Sprintf("SGX report version mismatch: Report = %v, supplied = %v", quote.Version, version)
		r.setFalse(&msg)
	} else {
		r.Success = true
	}
	return r, ok
}

// verifies the quote signature
// Can be used by SGX/TDX: QuoteType = 0x00 (sgx) or 0x81 (TDX)
// TODO: Handle different QE Cert Data Types in here
func VerifyIntelQuoteSignature(reportRaw []byte, quoteSignature ECDSA256QuoteSignatureDataStructure,
	quoteSignatureSize uint32, quoteSignatureType int, certs SgxCertificates,
	fingerprint string, quoteType uint32) (SignatureResult, bool) {
	result := SignatureResult{}
	var digest [32]byte

	if quoteType != SGX_QUOTE_TYPE && quoteType != TDX_QUOTE_TYPE {
		msg := fmt.Sprintf("Quote Type not supported %v", quoteType)
		result.SignCheck.setFalse(&msg)
		return result, false
	}

	// check signature size
	if uint32(len(reportRaw)-SGX_QUOTE_SIGNATURE_OFFSET) != quoteSignatureSize {
		msg := fmt.Sprintf("parsed QuoteSignatureData size doesn't match QuoteSignatureDataLen. expected: %v, got: %v\n",
			quoteSignatureSize, uint32(len(reportRaw)-signature_offset))
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
	if quoteType == SGX_QUOTE_TYPE {
		digest = sha256.Sum256(reportRaw[:QUOTE_HEADER_SIZE+SGX_QUOTE_BODY_SIZE])
	} else {
		digest = sha256.Sum256(reportRaw[:QUOTE_HEADER_SIZE+TDX_QUOTE_BODY_SIZE])
	}

	// Convert r, s to Big Int
	r := new(big.Int)
	r.SetBytes(quoteSignature.ISVEnclaveReportSignature[:32])
	s := new(big.Int)
	s.SetBytes(quoteSignature.ISVEnclaveReportSignature[32:])

	// Extract the attestation public key (generated by the QE) from the certificate
	ak_pub := quoteSignature.ECDSAAttestationKey
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
	if quoteType == SGX_QUOTE_TYPE {
		digest = sha256.Sum256(reportRaw[SGX_QUOTE_SIGNATURE_OFFSET+128 : SGX_QUOTE_SIGNATURE_OFFSET+128+SGX_QUOTE_BODY_SIZE])
	} else {
		digest = sha256.Sum256(reportRaw[TDX_QUOTE_SIGNATURE_OFFSET+128 : TDX_QUOTE_SIGNATURE_OFFSET+128+TDX_QUOTE_BODY_SIZE])
	}

	// extract r and s from ECDSA QEReportSignature
	r.SetBytes(quoteSignature.QEReportSignature[:32])
	s.SetBytes(quoteSignature.QEReportSignature[32:])

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
	reportData := quoteSignature.QEReport.ReportData
	hash_ref := sha256.Sum256(append(ak_pub[:], quoteSignature.QEAuthData...))
	reportDataRef := append(hash_ref[:], make([]byte, 32)...)

	if !bytes.Equal(reportData[:], reportDataRef[:]) {
		msg := fmt.Sprintf("invalid SHA256(ECDSA Attestation Key || QE Authentication Data) || 32*0x00) in QEReport.ReportData. expected: %v, got: %v\n", reportDataRef, reportData)
		result.CertChainCheck.setFalse(&msg)
		return result, false
	}

	// Step 4: Verify the SGX certificate chain
	x509Chains, err := internal.VerifyCertChain([]*x509.Certificate{certs.PCKCert, certs.IntermediateCert},
		[]*x509.Certificate{certs.RootCACert})
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

	//Step 6: Store details from (all) validated certificate chain(s) in the report
	for _, chain := range x509Chains {
		chainExtracted := []X509CertExtracted{}
		for _, cert := range chain {
			chainExtracted = append(chainExtracted, ExtractX509Infos(cert))
		}
		result.ValidatedCerts = append(result.ValidatedCerts, chainExtracted)
	}

	return result, true
}

func verifyTcbInfo(tcbInfo *TcbInfo, tcbInfoBodyRaw string, tcbKeyCert *x509.Certificate) error {
	if tcbInfo == nil || tcbKeyCert == nil {
		return fmt.Errorf("invalid function parameter (null pointer exception)")
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
		return fmt.Errorf("failed to extract public key from certificate")
	}

	// verify signature
	ok = ecdsa.Verify(pub_key, digest[:], r, s)
	if !ok {
		return fmt.Errorf("failed to verify tcbInfo signature")
	}

	now := time.Now()

	if now.After(tcbInfo.TcbInfo.NextUpdate) {
		return fmt.Errorf("tcbInfo has expired since: %v", tcbInfo.TcbInfo.NextUpdate)
	}

	return nil
}

// Only for SGX report body
func VerifyEnclaveReportValues(body *EnclaveReportBody, tcbInfo *TcbInfo,
	certs *SgxCertificates, sgxReferenceValue *ReferenceValue, result *SgxMeasurementResult) error {
	if body == nil || tcbInfo == nil || certs == nil || sgxReferenceValue == nil || result == nil {
		return fmt.Errorf("invalid function parameter (null pointer exception)")
	}

	// Parse and verify PCK certificate extensions
	sgxExtensions, err := ParseSGXExtensions(certs.PCKCert.Extensions[SGX_EXTENSION_INDEX].Value[4:]) // skip the first value (not relevant)
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
	// TODO: check TCB level (call GetTcbStatusEnclave):
	// - Check if TCB Level status is OutOfDate/REVOKED/ConfigurationNeeded/ConfigurationAndSWHardeningNeeded/UpToDate/SWHardeningNeeded/OutOfDateConfigurationNeeded/TCB Level error status is unrecognized
	// - handle result of TCB Status based on policy
	return nil
}

// verify QE Identity and compare the values to the QE
// Can be used by SGX/TDX
func VerifyQEIdentity(qeReportBody *EnclaveReportBody, qeIdentity *QEIdentity, qeIdentityBodyRaw string, tcbKeyCert *x509.Certificate, teeType uint32) error {
	if qeReportBody == nil || qeIdentity == nil || tcbKeyCert == nil {
		return fmt.Errorf("invalid function parameter (null pointer exception)")
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
		return fmt.Errorf("failed to extract public key from certificate")
	}

	// verify signature
	ok = ecdsa.Verify(pub_key, digest[:], r, s)
	if !ok {
		return fmt.Errorf("failed to verify QE Identity signature")
	}

	now := time.Now()

	if now.After(qeIdentity.EnclaveIdentity.NextUpdate) {
		return fmt.Errorf("qeIdentity has expired since: %v", qeIdentity.EnclaveIdentity.NextUpdate)
	}

	// from Intel SGX DCAP Library
	if teeType == TDX_QUOTE_TYPE {
		if qeIdentity.EnclaveIdentity.Version == 1 {
			return fmt.Errorf("enclave Identity version 1 is invalid for TDX TEE")
		} else if qeIdentity.EnclaveIdentity.Version == 2 {
			if qeIdentity.EnclaveIdentity.Id != TD_QE {
				return fmt.Errorf("enclave Identity is not generated for TDX and does not match Quote's TEE")
			}
		}
	} else if teeType == SGX_QUOTE_TYPE {
		if qeIdentity.EnclaveIdentity.Id != QE {
			return fmt.Errorf("enclave Identity is not generated for SGX and does not match Quote's TEE")
		}
	} else {
		return fmt.Errorf("unknown Quote's TEE. Enclave Identity cannot be valid")
	}

	miscselect_qe_identity := binary.LittleEndian.Uint32(qeIdentity.EnclaveIdentity.Miscselect)
	miscselectMask_qe_identity := binary.LittleEndian.Uint32(qeIdentity.EnclaveIdentity.MiscselectMask)

	if qeReportBody.MISCSELECT != (miscselect_qe_identity & miscselectMask_qe_identity) {
		return fmt.Errorf("miscSelect value from Enclave Report: %v does not match miscSelect value from QE Identity: %v",
			qeReportBody.MISCSELECT, (miscselect_qe_identity & miscselectMask_qe_identity))
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
		return fmt.Errorf("attributes mismatch. Expected: %v, Got: %v", qeIdentity.EnclaveIdentity.Attributes, attributes_quote)
	}

	// check mrsigner value
	mrsigner_quote := qeReportBody.MRSIGNER
	mrsigner_qe_identity := qeIdentity.EnclaveIdentity.Mrsigner
	if mrsigner_qe_identity != nil &&
		!reflect.DeepEqual([]byte(mrsigner_qe_identity), mrsigner_quote[:]) {
		return fmt.Errorf("MRSIGNER mismatch. Expected: %v, Got: %v", mrsigner_qe_identity, mrsigner_quote)
	}

	// check isvProdId value
	if qeReportBody.ISVProdID != uint16(qeIdentity.EnclaveIdentity.IsvProdId) {
		return fmt.Errorf("IsvProdId mismatch. Expected: %v, Got: %v", qeIdentity.EnclaveIdentity.IsvProdId, qeReportBody.ISVProdID)
	}

	// TODO: return a corresponding result based on a policy.
	switch GetTcbStatusQE(qeIdentity, qeReportBody) {
	case Revoked:
		log.Tracef("Value of tcbStatus for the selected Enclave's Identity tcbLevel (isvSvn: %v) is 'Revoked'", qeReportBody.ISVSVN)
	case OutOfDate:
		log.Tracef("Value of tcbStatus for the selected Enclave's Identity tcbLevel (isvSvn: %v) is 'OutOfDate'", qeReportBody.ISVSVN)
	default:
	}

	return nil
}

func GetTcbStatusQE(qeIdentity *QEIdentity, body *EnclaveReportBody) TcbStatus {
	for _, level := range qeIdentity.EnclaveIdentity.TcbLevels {
		if uint16(level.Tcb.Isvsvn) <= body.ISVSVN {
			return level.TcbStatus
		}
	}
	return Revoked
}

// TODO (important): implement this function (from DCAP QuoteVerifier.cpp: function checkTcbLevel())
func GetTcbStatusEnclave(tcb_info *TcbInfo, quote *SgxReport, sgxExtensions SGXExtensionsValue) TcbStatus {
	//tcbLevel := getMatchingTcbLevel(tcb_info, quote, sgxExtensions)
	return Revoked
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
	crlData, err := ioutil.ReadAll(resp.Body)
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
