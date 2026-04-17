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
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/google/go-tdx-guest/pcs"
)

// Overall structure: table 2 from https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
// Endianess: Little Endian (all Integer fields)
type SgxQuote struct {
	QuoteHeader           QuoteHeader
	ISVEnclaveReport      EnclaveReportBody
	QuoteSignatureDataLen uint32
	QuoteSignatureData    ECDSA256QuoteSignatureDataStructure // variable size
}

func VerifySgx(
	evidence ar.Evidence,
	collateral ar.Collateral,
	nonce []byte,
	policy *ar.SgxPolicy,
	caFingerprints []string,
	refComponents []ar.Component,
) (*ar.MeasurementResult, bool) {

	var err error
	result := &ar.MeasurementResult{
		Type:      "SGX Result",
		SgxResult: &ar.SgxResult{},
	}
	success := true

	log.Debug("Verifying SGX measurements")

	if len(refComponents) == 0 {
		log.Debugf("Could not find SGX reference value")
		result.Summary.Fail(ar.RefValNotPresent)
		return result, false
	} else if len(refComponents) > 1 {
		log.Debugf("Report contains %v reference values. Currently, only one SGX reference value is supported",
			len(refComponents))
		result.Summary.Fail(ar.RefValMultiple)
		return result, false
	}
	sgxReferenceValue := refComponents[0]

	// Validate Parameters:
	if len(evidence.Data) < SGX_QUOTE_MIN_SIZE {
		log.Debugf("Invalid SGX Report")
		result.Summary.Fail(ar.ParseEvidence)
		return result, false
	}

	if sgxReferenceValue.Type != ar.TYPE_REFVAL_SGX {
		log.Debugf("SGX reference value invalid type %v", sgxReferenceValue.Type)
		result.Summary.Fail(ar.RefValType)
		return result, false
	}

	if policy == nil {
		result.Summary.Fail(ar.PolicyNotPresent)
		return result, false
	}

	// Extract the attestation report into the SGXReport data structure
	sgxQuote, err := DecodeSgxReport(evidence.Data)
	if err != nil {
		log.Debugf("Failed to decode SGX report: %v", err)
		result.Summary.Fail(ar.ParseEvidence)
		return result, false
	}

	if ar.IntelQuoteType(sgxQuote.QuoteHeader.TeeType) != ar.SGX_QUOTE_TYPE {
		log.Debugf("Unsupported SGX quote type (tee_type: %X)\n", sgxQuote.QuoteHeader.TeeType)
		return result, false
	}

	// Compare nonce for freshness
	nonce64 := make([]byte, 64)
	copy(nonce64, nonce[:])
	result.Freshness = verifyNonce(sgxQuote.ISVEnclaveReport.ReportData[:], nonce64)
	if result.Freshness.Status != ar.StatusSuccess {
		result.Summary.Status = ar.StatusFail
		return result, false
	}

	// Obtain collateral from measurements
	if len(collateral.Artifacts) == 0 ||
		len(collateral.Artifacts[0].Events) == 0 ||
		collateral.Artifacts[0].Events[0].IntelCollateral == nil {
		log.Debugf("Could not find TDX collateral")
		result.Summary.Fail(ar.CollateralNotPresent)
		return result, false
	}
	intelCollateralRaw := collateral.Artifacts[0].Events[0].IntelCollateral
	intelCollateral, err := ParseCollateral(intelCollateralRaw)
	if err != nil {
		log.Debugf("Could not parse SGX collateral")
		result.Summary.Fail(ar.ParseCollateral)
		return result, false
	}

	// Extract quote PCK certificate chain. Currently only support for QECertDataType 5
	log.Debugf("Retrieving certificate chain from quote")
	var quoteCerts SgxCertificates
	if sgxQuote.QuoteSignatureData.QECertDataType == 5 {
		quoteCerts, err = ParseCertificates(sgxQuote.QuoteSignatureData.QECertData, true)
		if err != nil {
			log.Debugf("Failed to parse certificate chain from QECertData: %v", err)
			result.Summary.Fail(ar.ParseCert)
			return result, false
		}
	} else {
		log.Debugf("QECertDataType not supported: %v", sgxQuote.QuoteSignatureData.QECertDataType)
		result.Summary.Fail(ar.ParseCert)
		return result, false
	}

	// Check that root CA from PCK cert chain is present in quote
	if quoteCerts.RootCACert == nil {
		log.Debugf("root cert is null")
		result.Summary.Fail(ar.ParseCA)
		return result, false
	}

	// Match collateral root CAs against reference root CA fingerprint
	errCode := verifyRootCas(&quoteCerts, intelCollateral, caFingerprints)
	if errCode != ar.NotSpecified {
		result.Summary.Fail(errCode)
		return result, false
	}

	// Parse and verify PCK certificate extensions
	sgxExtensions, err := ParseSGXExtensions(quoteCerts.PCKCert.Extensions[SGX_EXTENSION_INDEX].Value[4:]) // skip the first value (not relevant)
	if err != nil {
		log.Debugf("failed to parse SGX Extensions from PCK Certificate: %v", err)
		result.Summary.Fail(ar.ParseExtensions)
		return result, false
	}

	// Verify TcbInfo
	log.Debugf("Verifying TCB info")
	result.SgxResult.TcbInfoCheck = ValidateTcbInfo(
		&intelCollateral.TcbInfo, intelCollateralRaw.TcbInfo,
		intelCollateral.TcbInfoIntermediateCert, intelCollateral.TcbInfoRootCert,
		sgxExtensions, [16]byte{}, ar.SGX_QUOTE_TYPE, policy.AcceptedTcbStatuses)
	if result.SgxResult.TcbInfoCheck.Summary.Status != ar.StatusSuccess {
		log.Debugf("Failed to verify TCB info structure")
		result.Summary.Fail(ar.VerifyTcbInfo)
		return result, false
	}

	// Verify QE Identity
	log.Debugf("Verifying quoting enclave identity")
	qeIdentityResult := ValidateQEIdentity(
		&sgxQuote.QuoteSignatureData.QEReport,
		&intelCollateral.QeIdentity, intelCollateralRaw.QeIdentity,
		intelCollateral.QeIdentityIntermediateCert, intelCollateral.QeIdentityRootCert,
		ar.SGX_QUOTE_TYPE)
	if qeIdentityResult.Summary.Status != ar.StatusSuccess {
		result.Summary.Fail(ar.VerifyQEIdentityErr)
		return result, false
	}
	result.SgxResult.QeReportCheck = qeIdentityResult

	// Verify Quote Signature
	log.Debugf("Verifying SGX quote signature")
	sig, ret := VerifyIntelQuoteSignature(evidence.Data, sgxQuote.QuoteSignatureData,
		sgxQuote.QuoteSignatureDataLen, int(sgxQuote.QuoteHeader.AttestationKeyType), quoteCerts,
		ar.IntelQuoteType(sgxQuote.QuoteHeader.TeeType), intelCollateral.PckCrl, intelCollateral.RootCaCrl)
	if !ret {
		success = false
	}
	result.Signature = sig

	// Verify Quote Body values
	log.Debugf("Verifying SGX quote body")
	err = VerifySgxQuoteBody(&sgxQuote.ISVEnclaveReport, &intelCollateral.TcbInfo, &sgxExtensions,
		&sgxReferenceValue, policy, result)
	if err != nil {
		log.Debugf("Failed to verify SGX Report Body: %v", err)
		result.Summary.Fail(ar.VerifySignature)
		result.Summary.Status = ar.StatusFail
		return result, false
	}

	// Check version
	log.Debugf("Verifying SGX quote version")
	result.SgxResult.VersionMatch, ret = verifyQuoteVersion(sgxQuote.QuoteHeader.Version, policy.QuoteVersion)
	if !ret {
		log.Debugf("Failed to verify ")
		return result, false
	}

	result.Summary.Status = ar.StatusFromBool(success)

	return result, success
}

// Parses the report into the SgxReport structure
func DecodeSgxReport(report []byte) (SgxQuote, error) {
	var reportStruct SgxQuote
	var header QuoteHeader
	var body EnclaveReportBody
	var sig ECDSA256QuoteSignatureDataStructure
	var sigLen uint32

	// parse header
	buf := bytes.NewBuffer(report)
	err := binary.Read(buf, binary.LittleEndian, &header)
	if err != nil {
		return SgxQuote{}, fmt.Errorf("failed to decode SGX report header: %v", err)
	}

	// parse body
	err = binary.Read(buf, binary.LittleEndian, &body)
	if err != nil {
		return SgxQuote{}, fmt.Errorf("failed to decode SGX report body: %v", err)
	}

	// parse signature size
	err = binary.Read(buf, binary.LittleEndian, &sigLen)
	if err != nil {
		return SgxQuote{}, fmt.Errorf("failed to decode SGX report QuoteSignatureDataLen: %v", err)
	}

	// parse signature
	err = parseECDSASignature(buf, &sig)
	if err != nil {
		return SgxQuote{}, fmt.Errorf("failed to decode SGX report ECDSA256QuotesignatureDataStructure: %v", err)
	}

	// compose the final report struct
	reportStruct.QuoteHeader = header
	reportStruct.ISVEnclaveReport = body
	reportStruct.QuoteSignatureDataLen = sigLen
	reportStruct.QuoteSignatureData = sig

	return reportStruct, nil
}

func VerifySgxQuoteBody(body *EnclaveReportBody, tcbInfo *pcs.TdxTcbInfo,
	sgxExtensions *SGXExtensionsValue, refval *ar.Component,
	sgxReferencePolicy *ar.SgxPolicy, result *ar.MeasurementResult,
) error {

	if tcbInfo == nil {
		return fmt.Errorf("internal error: SGX tcb info is nil")
	}
	if sgxExtensions == nil {
		return fmt.Errorf("internal error: SGX certs is nil")
	}
	if refval == nil {
		return fmt.Errorf("internal error: SGX reference value is nil")
	}
	if result == nil {
		return fmt.Errorf("internal error: SGX measurement result is nil")
	}

	// check MRENCLAVE reference value
	if !bytes.Equal(body.MRENCLAVE[:], []byte(refval.GetHash(crypto.SHA256))) {
		result.Artifacts = append(result.Artifacts,
			ar.DigestResult{
				Type:       ar.TYPE_REFVAL_IAS,
				Name:       refval.Name,
				Digest:     refval.GetHash(crypto.SHA256),
				Success:    false,
				Launched:   false,
				PackageUrl: refval.PackageUrl,
			})
		result.Artifacts = append(result.Artifacts,
			ar.DigestResult{
				Type:       "Measurement",
				Name:       refval.Name,
				Digest:     body.MRENCLAVE[:],
				Success:    false,
				Launched:   false,
				PackageUrl: refval.PackageUrl,
			})
		return fmt.Errorf("MRENCLAVE mismatch. Expected: %q, Got: %q",
			hex.EncodeToString(refval.GetHash(crypto.SHA256)), hex.EncodeToString(body.MRENCLAVE[:]))
	} else {
		result.Artifacts = append(result.Artifacts,
			ar.DigestResult{
				Type:       "Measurement",
				Name:       refval.Name,
				Digest:     body.MRENCLAVE[:],
				Success:    true,
				Launched:   true,
				PackageUrl: refval.PackageUrl,
			})
	}
	log.Debugf("Successfully verified MRENCLAVE (%q)", hex.EncodeToString(refval.GetHash(crypto.SHA256)))

	result.Artifacts = append(result.Artifacts,
		ar.DigestResult{
			Type:     ar.TYPE_REFVAL_IAS,
			Name:     "MrSigner",
			Digest:   sgxReferencePolicy.MrSigner,
			Measured: hex.EncodeToString(body.MRSIGNER[:]),
			Success:  bytes.Equal(sgxReferencePolicy.MrSigner, body.MRSIGNER[:]),
			Launched: true,
		},
	)
	log.Debugf("Successfully verified MRSIGNER (%q)", sgxReferencePolicy.MrSigner)

	for _, v := range result.Artifacts {
		if !v.Success {
			return fmt.Errorf("SGX Quote Body Verification failed. %v: (Expected: %v Got: %v)", v.Name, v.Digest, v.Measured)
		}
	}

	// Check CPUSVN
	statusCpuSvn := ar.StatusFail
	if bytes.Compare(sgxExtensions.Tcb.Value.CpuSvn.Value, body.CPUSVN[:]) <= 0 {
		statusCpuSvn = ar.StatusSuccess
	}
	result.SgxResult.QeReportCheck.CpuSvn = ar.Result{
		Got:      hex.EncodeToString(sgxExtensions.Tcb.Value.CpuSvn.Value),
		Expected: hex.EncodeToString(body.CPUSVN[:]),
		Status:   statusCpuSvn,
	}
	if statusCpuSvn != ar.StatusSuccess {
		return fmt.Errorf("failed to verify CPUSVN: Expected: %v, Got: %v", body.CPUSVN[:],
			sgxExtensions.Tcb.Value.CpuSvn.Value)
	}

	// Check ISV SVN
	statusIsvSvn := ar.StatusFail
	if sgxReferencePolicy.IsvSvn == body.ISVSVN {
		statusIsvSvn = ar.StatusSuccess
	}
	result.SgxResult.QeReportCheck.IsvSvn = ar.Result{
		Got:      strconv.Itoa(int(sgxReferencePolicy.IsvSvn)),
		Expected: strconv.Itoa(int(body.ISVSVN)),
		Status:   statusIsvSvn,
	}
	if statusIsvSvn != ar.StatusSuccess {
		return fmt.Errorf("failed to verify ISVSVN. Expected: %v, got %v", sgxReferencePolicy.IsvSvn,
			body.ISVSVN)
	}

	result.SgxResult.SgxAttributesCheck = ar.SgxAttributesCheck{
		Initted: ar.BooleanMatch{
			Success:  getBit(body.Attributes[:], 0) == sgxReferencePolicy.Attributes.Initted,
			Claimed:  sgxReferencePolicy.Attributes.Initted,
			Measured: getBit(body.Attributes[:], 0),
		},
		Debug: ar.BooleanMatch{
			Success:  getBit(body.Attributes[:], 1) == sgxReferencePolicy.Attributes.Debug,
			Claimed:  sgxReferencePolicy.Attributes.Debug,
			Measured: getBit(body.Attributes[:], 1),
		},
		Mode64Bit: ar.BooleanMatch{
			Success:  getBit(body.Attributes[:], 2) == sgxReferencePolicy.Attributes.Mode64Bit,
			Claimed:  sgxReferencePolicy.Attributes.Mode64Bit,
			Measured: getBit(body.Attributes[:], 2),
		},
		ProvisionKey: ar.BooleanMatch{
			Success:  getBit(body.Attributes[:], 5) == sgxReferencePolicy.Attributes.ProvisionKey,
			Claimed:  sgxReferencePolicy.Attributes.ProvisionKey,
			Measured: getBit(body.Attributes[:], 5),
		},
		EInitToken: ar.BooleanMatch{
			Success:  getBit(body.Attributes[:], 6) == sgxReferencePolicy.Attributes.EInitToken,
			Claimed:  sgxReferencePolicy.Attributes.EInitToken,
			Measured: getBit(body.Attributes[:], 6),
		},
		Kss: ar.BooleanMatch{
			Success:  getBit(body.Attributes[:], 8) == sgxReferencePolicy.Attributes.Kss,
			Claimed:  sgxReferencePolicy.Attributes.Kss,
			Measured: getBit(body.Attributes[:], 8),
		},
		Legacy: ar.BooleanMatch{
			Success:  (body.Attributes[8] == 3) == sgxReferencePolicy.Attributes.Legacy,
			Claimed:  sgxReferencePolicy.Attributes.Legacy,
			Measured: body.Attributes[8] == 3,
		},
		Avx: ar.BooleanMatch{
			Success:  (body.Attributes[8] == 6) == sgxReferencePolicy.Attributes.Avx,
			Claimed:  sgxReferencePolicy.Attributes.Avx,
			Measured: body.Attributes[8] == 6,
		},
	}

	ok := result.SgxResult.SgxAttributesCheck.Initted.Success &&
		result.SgxResult.SgxAttributesCheck.Debug.Success &&
		result.SgxResult.SgxAttributesCheck.Mode64Bit.Success &&
		result.SgxResult.SgxAttributesCheck.ProvisionKey.Success &&
		result.SgxResult.SgxAttributesCheck.EInitToken.Success &&
		result.SgxResult.SgxAttributesCheck.Kss.Success &&
		result.SgxResult.SgxAttributesCheck.Legacy.Success &&
		result.SgxResult.SgxAttributesCheck.Avx.Success
	if !ok {
		return fmt.Errorf("SGXAttributesCheck failed: Initted: %v, Debug: %v, Mode64Bit: %v, ProvisionKey: %v, EInitToken: %v, Kss: %v, Legacy: %v, Avx: %v",
			result.SgxResult.SgxAttributesCheck.Initted.Success,
			result.SgxResult.SgxAttributesCheck.Debug.Success,
			result.SgxResult.SgxAttributesCheck.Mode64Bit.Success,
			result.SgxResult.SgxAttributesCheck.ProvisionKey.Success,
			result.SgxResult.SgxAttributesCheck.EInitToken.Success,
			result.SgxResult.SgxAttributesCheck.Kss.Success,
			result.SgxResult.SgxAttributesCheck.Legacy.Success,
			result.SgxResult.SgxAttributesCheck.Avx.Success,
		)
	}

	return nil
}

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

func getBit(data []byte, i int) bool {
	byteIndex := i / 8
	bitIndex := uint(i % 8)

	return (data[byteIndex]>>bitIndex)&1 == 1
}
