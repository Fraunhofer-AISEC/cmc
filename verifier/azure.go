// Copyright (c) 2025 Fraunhofer AISEC
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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"gopkg.in/square/go-jose.v2"
)

type AzureReportType int

const (
	UNKNOWN   AzureReportType = 0
	SnpReport AzureReportType = 2
	TdxReport AzureReportType = 4
)

type AzureReport struct {
	Header        AzureHeader        // The Azure custom report header
	ReportPayload [1184]byte         // The SNP attestation report or TDX TDREPORT
	RuntimeData   AzureRuntimeData   // Runtime data includes claims endorsed by hw report
	RuntimeClaims AzureRuntimeClaims // Runtime claims in JSON format
}

type AzureHeader struct {
	Signature   [4]byte  // Expected: 0x414c4348 (HCLA)
	Version     uint32   // Expected: 2
	PayloadSize uint32   // Expected: 1184 (AMD SEV-SNP), 1024 (Intel TDX).
	RequestType uint32   // Expected: 2
	Status      [4]byte  // Reserved
	Reserved    [12]byte // Reserved
}

type AzureRuntimeData struct {
	DataSize   uint32 // Size of runtime data
	Version    uint32 // Format version. Expected: 1
	ReportType uint32 // Expected: 2 (AMD SEV-SNP), 4 (Intel TDX)
	HashType   uint32 // Runtime data hash. Expected: 1 (SHA-256), 2 (SHA-384), 3 (SHA-512)
	ClaimSize  uint32 // The size of the runtime claims
}

type AzureRuntimeClaims struct {
	Keys     []jose.JSONWebKey `json:"keys"`             // Array JWK keys. Expected kid: HCLAkPub (vTPM AK public), HCLEkPub (vTPM EK public)
	VmConfig AzureVmConfig     `json:"vm-configuration"` // Azure confidential VM configuration.
	UserData string            `json:"user-data"`        // Hardware report user data (nonce)
}

type AzureVmConfig struct {
	RootCertThumbPrint string `json:"root-cert-thumbprint"`
	ConsoleEnabled     bool   `json:"console-enabled"`
	SecureBoot         bool   `json:"secure-boot"`
	TpmEnabled         bool   `json:"tpm-enabled"`
	TpmPersisted       bool   `json:"tpm-persisted"`
	VmUniqueId         string `json:"vmUniqueId"`
}

func VerifyAzure(
	evidences []ar.Evidence,
	collaterals []ar.Collateral,
	nonce []byte,
	tdxPolicy *ar.TdxPolicy,
	snpPolicy *ar.SnpPolicy,
	caFingerprints []string,
	tdxRefVals, snpRefVals, vtpmRefVals []ar.ReferenceValue,
	s ar.Serializer,
) ([]ar.MeasurementResult, bool) {

	log.Debug("Verifying Azure measurements...")

	// Extract evidences, collateral and nonce, perform basic sanity checks
	foundCcEvidence := false
	foundVtpmEvidence := false
	var ccEvidence ar.Evidence
	var vtpmEvidence ar.Evidence
	for i := range evidences {
		switch evidences[i].Type {
		case ar.TYPE_EVIDENCE_AZURE_SNP, ar.TYPE_EVIDENCE_AZURE_TDX:
			ccEvidence = evidences[i]
			foundCcEvidence = true
		case ar.TYPE_EVIDENCE_AZURE_TPM:
			vtpmEvidence = evidences[i]
			foundVtpmEvidence = true
		default:
			r := ar.MeasurementResult{
				Type: evidences[i].Type,
			}
			r.Summary.Fail(ar.VerifyMeasurement, fmt.Errorf("unexpected Azure evidence type %v",
				evidences[i].Type))
			return []ar.MeasurementResult{r}, false
		}
	}
	if !foundCcEvidence {
		r := ar.MeasurementResult{}
		r.Summary.Fail(ar.VerifyMeasurement, fmt.Errorf("CC measurement missing"))
		return []ar.MeasurementResult{r}, false
	}
	if !foundVtpmEvidence {
		r := ar.MeasurementResult{}
		r.Summary.Fail(ar.VerifyMeasurement, fmt.Errorf("vTPM measurement missing"))
		return []ar.MeasurementResult{r}, false
	}

	foundCcCollateral := false
	foundVtpmCollateral := false
	var ccCollateral ar.Collateral
	var vtpmCollateral ar.Collateral
	for i := range collaterals {
		switch collaterals[i].Type {
		case ar.TYPE_EVIDENCE_AZURE_SNP, ar.TYPE_EVIDENCE_AZURE_TDX:
			ccCollateral = collaterals[i]
			foundCcCollateral = true
		case ar.TYPE_EVIDENCE_AZURE_TPM:
			vtpmCollateral = collaterals[i]
			foundVtpmCollateral = true
		default:
			r := ar.MeasurementResult{
				Type: collaterals[i].Type,
			}
			r.Summary.Fail(ar.VerifyMeasurement, fmt.Errorf("unexpected Azure collateral type %v",
				collaterals[i].Type))
			return []ar.MeasurementResult{r}, false
		}
	}
	if !foundCcCollateral {
		r := ar.MeasurementResult{}
		r.Summary.Fail(ar.VerifyMeasurement, fmt.Errorf("CC measurement missing"))
		return []ar.MeasurementResult{r}, false
	}
	if !foundVtpmCollateral {
		r := ar.MeasurementResult{}
		r.Summary.Fail(ar.VerifyMeasurement, fmt.Errorf("vTPM measurement missing"))
		return []ar.MeasurementResult{r}, false
	}
	if len(vtpmCollateral.Certs) != 1 {
		r := ar.MeasurementResult{
			Type: vtpmCollateral.Type,
		}
		r.Summary.Fail(ar.VerifyMeasurement, fmt.Errorf("unexpected length of vTPM certs %v", len(vtpmCollateral.Certs)))
		return []ar.MeasurementResult{r}, false
	}

	// Parse AK cert
	vtpmAkCert, err := x509.ParseCertificate(vtpmCollateral.Certs[0])
	if err != nil {
		r := ar.MeasurementResult{
			Type: vtpmCollateral.Type,
		}
		r.Summary.Fail(ar.VerifyMeasurement, fmt.Errorf("failed to parse vTPM cert: %w", err))
		return []ar.MeasurementResult{r}, false
	}

	// Extract nonce from report to verify against vTPM AK public
	hwreportNonce, err := GetReportNonce(&ccEvidence)
	if err != nil {
		r := ar.MeasurementResult{
			Type: ccEvidence.Type,
		}
		r.Summary.Fail(ar.VerifyMeasurement, fmt.Errorf("failed to extract CC report nonce: %w", err))
		return []ar.MeasurementResult{r}, false
	}
	log.Tracef("Extracted HW report nonce: %v", hex.EncodeToString(hwreportNonce))

	// Verify Azure Chain of Trust: hash of azure claims including user supplied nonce and vTPM akpublic
	// must match CC report nonce, user supplied nonce in claims must match provided nonce
	err = VerifyAzureCoT(ccEvidence.AddData, nonce, hwreportNonce, vtpmAkCert)
	if err != nil {
		r := ar.MeasurementResult{
			Type: ccCollateral.Type,
		}
		r.Summary.Fail(ar.VerifyMeasurement, fmt.Errorf("failed to verify Azure CoT: %w", err))
		return []ar.MeasurementResult{r}, false
	}

	// Create results structure and verify all measurements
	success := true
	results := make([]ar.MeasurementResult, 0)

	// Verify TDX measurements with verified hwreport nonce
	if ccEvidence.Type == ar.TYPE_EVIDENCE_AZURE_TDX {
		tdxResult, ok := VerifyTdx(ccEvidence, ccCollateral, hwreportNonce, tdxPolicy,
			caFingerprints, tdxRefVals)
		if !ok {
			success = false
		}
		results = append(results, *tdxResult)
	}

	// Verify SNP measurement with with verified hwreport nonce
	if ccEvidence.Type == ar.TYPE_EVIDENCE_AZURE_SNP {
		snpResult, ok := VerifySnp(ccEvidence, ccCollateral, hwreportNonce, snpPolicy,
			caFingerprints, snpRefVals)
		if !ok {
			success = false
		}
		results = append(results, *snpResult)
	}

	// Verify vTPM measurements with provided nonce
	vtpmResult, ok := VerifyTpm(vtpmEvidence, vtpmCollateral, nonce, []*x509.Certificate{vtpmAkCert}, vtpmRefVals, s)
	if !ok {
		success = false
	}
	results = append(results, *vtpmResult)

	if success {
		log.Debugf("Successfully verified Azure measurements")
	} else {
		log.Debugf("Failed to verify Azure measurements")
	}

	return results, success
}

func DecodeAzureRtData(data []byte) (*AzureRuntimeData, *AzureRuntimeClaims, error) {

	buf := bytes.NewBuffer(data)

	// Parse runtime data
	var rtdata AzureRuntimeData
	err := binary.Read(buf, binary.LittleEndian, &rtdata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode Azure report payload: %w", err)
	}

	log.Debug("Parsed runtime data")
	log.Debugf("\tRuntimeData data size  : %v", rtdata.DataSize)
	log.Debugf("\tRuntimeData version    : %v", rtdata.Version)
	log.Debugf("\tRuntimeData report type: %v", rtdata.ReportType)
	log.Debugf("\tRuntimeData hash type  : %v", rtdata.HashType)
	log.Debugf("\tRuntimeData claim size : %v", rtdata.ClaimSize)

	if rtdata.Version != 1 {
		return nil, nil, fmt.Errorf("unsupported runtime data version %v. Expected %v", rtdata.Version, 1)
	}

	// Parse runtime claims
	rawClaims := buf.Bytes()[:rtdata.ClaimSize]
	log.Debugf("Parsing claims size %v", len(rawClaims))
	var claims AzureRuntimeClaims
	err = json.Unmarshal(rawClaims, &claims)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	log.Debug("Parsed runtime claims")
	log.Debugf("\tRoot cert thumbprint   : %q", claims.VmConfig.RootCertThumbPrint)
	log.Debugf("\tConsole enabled        : %v", claims.VmConfig.ConsoleEnabled)
	log.Debugf("\tSecure boot enabled    : %v", claims.VmConfig.SecureBoot)
	log.Debugf("\tTPM enabled            : %v", claims.VmConfig.TpmEnabled)
	log.Debugf("\tTPM persisted          : %v", claims.VmConfig.TpmPersisted)
	log.Debugf("\tVM unique ID           : %q", claims.VmConfig.VmUniqueId)
	log.Debugf("\tUser data              : %q", claims.UserData)
	for _, key := range claims.Keys {
		log.Debugf("\tJWK KeyID              : %v", key.KeyID)
	}

	return &rtdata, &claims, nil
}

// Verifies the Azure Chain of Trust (CoT): Verify that the TDX Quote / SNP report nonce equals
// the hash of the runtime claims including the AK public which was used to sign the vTPM quote.
// The vTPM is part of the OpenHCL firmware and thus measured into the TDX MRTD / SNP report
// AK, EK := vTPM.Create()
// RuntimeClaims := GenerateClaims(AK_pub, EK_pub)
// Quote := GenerateQuote(nonce: RuntimeClaims)
func VerifyAzureCoT(rtdataRaw, suppliedNonce, reportNonce []byte, vtpmAkCert *x509.Certificate) error {

	log.Debug("Verifying Azure Chain of Trust...")

	// Make sure we compare the full 64 bytes, even if nonce is shorter
	fullSuppliedNonce := make([]byte, 64)
	copy(fullSuppliedNonce, suppliedNonce)

	rtdata, rtclaims, err := DecodeAzureRtData(rtdataRaw)
	if err != nil {
		return fmt.Errorf("failed to decode azure runtime data: %w", err)
	}

	// Hash runtime claims without the first 20 bytes of header
	// https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design
	rawRuntimeClaims := rtdataRaw[20 : 20+rtdata.ClaimSize]
	log.Debugf("Length raw runtime claims: %v", len(rawRuntimeClaims))
	hashRuntimeClaims := sha256.Sum256(rawRuntimeClaims)
	log.Debugf("Hash runtime claims: %v", hex.EncodeToString(hashRuntimeClaims[:]))

	// Compare report data with runtime claims
	if !bytes.Equal(hashRuntimeClaims[:], reportNonce[:32]) {
		return fmt.Errorf("HASH(runtime_claims) != REPORTDATA: %v vs. %v",
			hex.EncodeToString(hashRuntimeClaims[:]), hex.EncodeToString(reportNonce[:32]))
	}
	log.Debugf("HASH(runtime_claims) matches REPORTDATA: %v", hex.EncodeToString(hashRuntimeClaims[:]))

	// Compare supplied nonce with runtime claims nonce
	claimsNonce, err := hex.DecodeString(rtclaims.UserData)
	if err != nil {
		return fmt.Errorf("failed to decode runtime claims nonce: %w", err)
	}
	if !bytes.Equal(claimsNonce, fullSuppliedNonce) {
		return fmt.Errorf("claims nonce %v does not match supplied nonce %x",
			rtclaims.UserData, fullSuppliedNonce)
	}
	log.Debugf("Claims nonce matches supplied nonce: %v", rtclaims.UserData)

	// Extract vTPM AK Public from runtime claims
	if len(rtclaims.Keys) != 2 {
		return fmt.Errorf("unexpected JWK keys length %v (expected %v)", len(rtclaims.Keys), 2)
	}
	claimAkPub, ok := rtclaims.Keys[0].Public().Key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("failed to extract claims ak pub")
	}

	// Extract public key from x509 certificate
	vTpmAkPub, ok := vtpmAkCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("failed to extract public key from certificate")
	}

	// Compare AK cert public key with runtime claims public key
	if !reflect.DeepEqual(claimAkPub, vTpmAkPub) {
		return fmt.Errorf("vTPM AK pub does not match claims AK pub")
	}
	log.Debugf("vTPM AK pub matches claims AK pub")

	log.Debugf("Successfully verified Azure Chain of Trust")

	return nil
}

func GetReportNonce(evidence *ar.Evidence) ([]byte, error) {

	log.Debug("Extracting nonce from hardware report...")

	switch evidence.Type {
	case ar.TYPE_EVIDENCE_AZURE_SNP:
		return getSnpNonce(evidence.Data)
	case ar.TYPE_EVIDENCE_AZURE_TDX:
		return getTdxNonce(evidence.Data)
	default:
		return nil, fmt.Errorf("failed to extract nonce")
	}
}

func getSnpNonce(data []byte) ([]byte, error) {
	log.Debug("Detected SNP report")
	report, err := DecodeSnpReport(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SNP report: %w", err)
	}
	log.Debug("Successfully extracted nonce")
	return report.ReportData[:], nil
}

func getTdxNonce(data []byte) ([]byte, error) {
	log.Debug("Detected TDX report")
	quote, err := DecodeTdxReportV4(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TDX quote: %w", err)
	}
	log.Debug("Successfully extracted nonce")
	return quote.QuoteBody.ReportData[:], nil
}
