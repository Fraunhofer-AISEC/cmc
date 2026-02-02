// Copyright (c) 2021 - 2024 Fraunhofer AISEC
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
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

type snpreport struct {
	// Table 23 @ https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf
	Version         uint32    // 000h
	GuestSvn        uint32    // 004h
	Policy          uint64    // 008h
	FamilyId        [16]byte  // 010h
	ImageId         [16]byte  // 020h
	Vmpl            uint32    // 030h
	SignatureAlgo   uint32    // 034h
	CurrentTcb      uint64    // 038h, platform_version
	PlatformInfo    uint64    // 040h
	KeySelection    uint32    // 048h
	Reserved1       uint32    // 04Ch
	ReportData      [64]byte  // 040h
	Measurement     [48]byte  // 090h
	HostData        [32]byte  // 0C0h
	IdKeyDigest     [48]byte  // 0E0h
	AuthorKeyDigest [48]byte  // 110h
	ReportId        [32]byte  // 140h
	ReportIdMa      [32]byte  // 160h
	ReportedTcb     uint64    // 180h
	CpuFamilyId     uint8     // 188h (Only Report Version >= 3)
	CpuModelId      uint8     // 189h (Only Report Version >= 3)
	CpuStepping     uint8     // 18Ah (Only Report Version >= 3)
	Reserved2       [21]byte  // 18bh (Offset 188h, Length 24 for Report Version < 3)
	ChipId          [64]byte  // 1A0h
	CommittedTcb    uint64    // 1E0h
	CurrentBuild    uint8     // 1E8h
	CurrentMinor    uint8     // 1E9h
	CurrentMajor    uint8     // 1EAh
	Reserved3a      uint8     // 1EBh
	CommittedBuild  uint8     // 1ECh
	CommittedMinor  uint8     // 1EDh
	CommittedMajor  uint8     // 1EEh
	Reserved3b      uint8     // 1EFh
	LaunchTcb       uint64    // 1F0h
	LaunchMitVector uint64    // 1F8h (Only Report Version >= 5)
	CurrMitVector   uint64    // 200h (Only Report Version >= 5)
	Reserved3c      [152]byte // 208h (Offset 1F8h, Length 168 for Report Version < 5)
	SignatureR      [72]byte  // 2A0h
	SignatureS      [72]byte
	Reserved4       [368]byte
}

const (
	ecdsa384_with_sha384 = 1
)

const (
	signature_offset = 0x2A0
)

func verifySnpMeasurements(measurement ar.Measurement, nonce []byte, manifests []ar.MetadataResult,
	referenceValues []ar.ReferenceValue,
) (*ar.MeasurementResult, bool) {

	log.Debug("Verifying SNP measurements")

	result := &ar.MeasurementResult{
		Type:      "SNP Result",
		SnpResult: &ar.SnpResult{},
	}
	ok := true

	// Extract the SNP attestation report data structure
	s, err := DecodeSnpReport(measurement.Evidence)
	if err != nil {
		log.Debugf("Failed to decode SNP report: %v", err)
		result.Summary.Fail(ar.ParseEvidence)
		return result, false
	}

	certs, err := internal.ParseCertsDer(measurement.Certs)
	if err != nil {
		log.Debugf("Failed to parse certificates: %v", err)
		result.Summary.Fail(ar.ParseCert)
		return result, false
	}

	if len(referenceValues) == 0 {
		log.Debug("Could not find SNP Reference Value")
		result.Summary.Fail(ar.RefValNotPresent)
		return result, false
	} else if len(referenceValues) > 1 {
		log.Debugf("Report contains %v reference values. Currently, only 1 SNP Reference Value is supported",
			len(referenceValues))
		result.Summary.Fail(ar.RefValMultiple)
		return result, false
	}

	snpReferenceValue := referenceValues[0]
	if snpReferenceValue.Type != "SNP Reference Value" {
		log.Debugf("SNP Reference Value invalid type %v", snpReferenceValue.Type)
		result.Summary.Fail(ar.RefValType)
		return result, false
	}

	if len(manifests) == 0 {
		result.Summary.Fail((ar.NoRootManifest))
		return result, false
	}
	rootManifest := manifests[0]

	if rootManifest.SnpPolicy == nil {
		log.Debugf("SNP manifest %v does not contain SNP policy", rootManifest.Name)
		result.Summary.Fail(ar.PolicyNotPresent)
		return result, false
	}

	// Determine AMD EPYC CPU generation and fetch corresponding version policy
	versionPolicy, codeName, err := getSnpVersionPolicy(&s, certs[0], rootManifest.SnpPolicy)
	if err != nil {
		log.Debugf("SNP manifest %v does not contain SNP policy: %v", rootManifest.Name, err)
		result.Summary.Fail(ar.PolicyNotPresent)
		return result, false
	}

	// Compare nonce for freshness (called report data in the SNP attestation report structure)
	nonce64 := make([]byte, 64)
	copy(nonce64, nonce)
	if cmp := bytes.Compare(s.ReportData[:], nonce64); cmp != 0 {
		log.Debugf("Nonces mismatch: Supplied Nonce = %v, Nonce in SNP Report = %v)",
			hex.EncodeToString(nonce), hex.EncodeToString(s.ReportData[:]))
		result.Freshness.Status = ar.StatusFail
		result.Freshness.Expected = hex.EncodeToString(nonce)
		result.Freshness.Got = hex.EncodeToString(s.ReportData[:])
		ok = false
	} else {
		result.Freshness.Got = hex.EncodeToString(nonce)
		result.Freshness.Status = ar.StatusSuccess
	}

	// Verify Signature, created with SNP VCEK private key
	sig, ret := verifySnpSignature(measurement.Evidence, s, certs, rootManifest.CaFingerprints)
	if !ret {
		ok = false
	}
	result.Signature = sig

	// Compare Measurements
	if cmp := bytes.Compare(s.Measurement[:], snpReferenceValue.Sha384); cmp != 0 {
		log.Debugf("Failed to verify SNP reference value. Expected %x, got %x",
			snpReferenceValue.Sha384, s.Measurement[:])
		result.Artifacts = append(result.Artifacts,
			ar.DigestResult{
				Type:     "Reference Value",
				SubType:  snpReferenceValue.SubType,
				Digest:   hex.EncodeToString(snpReferenceValue.Sha384),
				Success:  false,
				Launched: false,
			})
		result.Artifacts = append(result.Artifacts,
			ar.DigestResult{
				Type:     "Measurement",
				SubType:  snpReferenceValue.SubType,
				Digest:   hex.EncodeToString(s.Measurement[:]),
				Success:  false,
				Launched: true,
			})

		ok = false
	} else {
		log.Debug("Successfully verified SNP reference value")
		// As we previously checked, that the attestation report contains exactly one
		// SNP Reference Value, we can set this here:
		result.Artifacts = append(result.Artifacts,
			ar.DigestResult{
				SubType:  snpReferenceValue.SubType,
				Digest:   hex.EncodeToString(s.Measurement[:]),
				Success:  true,
				Launched: true,
			})
	}

	// Verify the SNP report version
	result.SnpResult.VersionMatch, ret = verifySnpVersion(rootManifest.SnpPolicy.ReportMinVersion,
		rootManifest.SnpPolicy.ReportMaxVersion, s.Version)
	if !ret {
		ok = false
	}
	// Verify SNP VM configuration
	result.SnpResult.PolicyCheck, ret = verifySnpPolicy(s.Policy, rootManifest.SnpPolicy.GuestPolicy)
	if !ret {
		ok = false
	}
	// Verify the SNP firmware version
	result.SnpResult.FwCheck, ret = verifySnpFw(s, versionPolicy.Fw)
	if !ret {
		ok = false
	}
	// Verify the SNP TCB against the specified minimum versions
	result.SnpResult.TcbCheck, ret = verifySnpTcb(codeName, s, versionPolicy.Tcb)
	if !ret {
		ok = false
	}
	// Examine SNP x509 extensions
	result.SnpResult.ExtensionsCheck, ret = verifySnpExtensions(codeName, certs[0], &s)
	if !ret {
		ok = false
	}

	result.Summary.Status = ar.StatusFromBool(ok)

	return result, ok
}

func verifySnpVersion(min, max, got uint32) (ar.Result, bool) {
	r := ar.Result{}
	ok := (got >= min && got <= max)
	if !ok {
		log.Debugf("SNP report version mismatch: Report = %v, min = %v, max = %v", got, min, max)
		r.Status = ar.StatusFail
		r.ExpectedBetween = []string{
			strconv.FormatUint(uint64(min), 10),
			strconv.FormatUint(uint64(max), 10),
		}
		r.Got = strconv.FormatUint(uint64(got), 10)
	} else {
		r.Status = ar.StatusSuccess
	}
	return r, ok
}

func verifySnpPolicy(policy uint64, v ar.SnpGuestPolicy) (ar.PolicyCheck, bool) {

	abiMajor := uint8(policy & 0xFF)
	abiMinor := uint8((policy >> 8) & 0xFF)
	smt := (policy & (1 << 16)) != 0
	migration := (policy & (1 << 18)) != 0
	debug := (policy & (1 << 19)) != 0
	singleSocket := (policy & (1 << 20)) != 0

	// Convert to int, as json.Marshal otherwise interprets the values as strings
	r := ar.PolicyCheck{
		Abi: ar.VersionCheck{
			Success:  checkMinVersion([]uint8{abiMajor, abiMinor}, []uint8{v.AbiMajor, v.AbiMinor}),
			Claimed:  []int{int(v.AbiMajor), int(v.AbiMinor)},
			Measured: []int{int(abiMajor), int(abiMinor)},
		},
		Smt: ar.BooleanMatch{
			Success:  smt == v.Smt,
			Claimed:  v.Smt,
			Measured: smt,
		},
		Migration: ar.BooleanMatch{
			Success:  migration == v.Migration,
			Claimed:  v.Migration,
			Measured: migration,
		},
		Debug: ar.BooleanMatch{
			Success:  debug == v.Debug,
			Claimed:  v.Debug,
			Measured: debug,
		},
		SingleSocket: ar.BooleanMatch{
			Success:  singleSocket == v.SingleSocket,
			Claimed:  v.SingleSocket,
			Measured: singleSocket,
		},
	}
	ok := r.Abi.Success &&
		r.Smt.Success &&
		r.Migration.Success &&
		r.Debug.Success &&
		r.SingleSocket.Success
	if !ok {
		log.Debugf("SNP policies do not match: Abi: %v, Smt: %v, Migration: %v, Debug: %v, SingleSocket: %v",
			r.Abi.Success, r.Smt.Success, r.Migration.Success, r.Debug.Success, r.SingleSocket.Success)
	}
	r.Summary.Status = ar.StatusFromBool(ok)

	return r, ok
}

func verifySnpFw(s snpreport, v ar.SnpFw) (ar.VersionCheck, bool) {

	build := min([]uint8{s.CurrentBuild, s.CommittedBuild})
	major := min([]uint8{s.CurrentMajor, s.CommittedMajor})
	minor := min([]uint8{s.CurrentMinor, s.CommittedMinor})

	ok := checkMinVersion([]uint8{major, minor, build}, []uint8{v.Major, v.Minor, v.Build})
	if !ok {
		log.Debugf("SNP FW version check failed. Expected: %v.%v.%v, got %v.%v.%v",
			v.Major, v.Minor, v.Build, major, minor, build)
	}

	// Convert to int, as json.Marshal otherwise interprets the values as strings
	r := ar.VersionCheck{
		Success:  ok,
		Claimed:  []int{int(v.Major), int(v.Minor), int(v.Build)},
		Measured: []int{int(major), int(minor), int(build)},
	}
	return r, ok
}

func verifySnpTcb(codeName string, s snpreport, v ar.SnpTcb) (ar.TcbCheck, bool) {

	log.Tracef("Verifying %q TCB", codeName)

	curr := ar.GetSnpTcb(codeName, s.CurrentTcb)
	comm := ar.GetSnpTcb(codeName, s.CommittedTcb)
	laun := ar.GetSnpTcb(codeName, s.LaunchTcb)
	repo := ar.GetSnpTcb(codeName, s.ReportedTcb)

	fmc := min([]uint8{curr.Fmc, comm.Fmc, laun.Fmc, repo.Fmc})
	bl := min([]uint8{curr.Bl, comm.Bl, laun.Bl, repo.Bl})
	tee := min([]uint8{curr.Tee, comm.Tee, laun.Tee, repo.Tee})
	snp := min([]uint8{curr.Snp, comm.Snp, laun.Snp, repo.Snp})
	ucode := min([]uint8{curr.Ucode, comm.Ucode, laun.Ucode, repo.Ucode})

	log.Tracef("Using minimum report TCB: FMC %v, BL %v, TEE %v, SNP %v, UCode %v",
		fmc, bl, tee, snp, ucode)

	log.Tracef("Verifiying against TCB: FMC %v, BL %v, TEE %v, SNP %v, UCode %v",
		v.Fmc, v.Bl, v.Tee, v.Snp, v.Ucode)

	// Convert to int, as json.Marshal otherwise interprets the values as strings
	r := ar.TcbCheck{
		Fmc: ar.VersionCheck{
			Success:  fmc >= v.Fmc,
			Claimed:  []int{int(v.Fmc)},
			Measured: []int{int(fmc)},
		},
		Bl: ar.VersionCheck{
			Success:  bl >= v.Bl,
			Claimed:  []int{int(v.Bl)},
			Measured: []int{int(bl)},
		},
		Tee: ar.VersionCheck{
			Success:  tee >= v.Tee,
			Claimed:  []int{int(v.Tee)},
			Measured: []int{int(tee)},
		},
		Snp: ar.VersionCheck{
			Success:  snp >= v.Snp,
			Claimed:  []int{int(v.Snp)},
			Measured: []int{int(snp)},
		},
		Ucode: ar.VersionCheck{
			Success:  ucode >= v.Ucode,
			Claimed:  []int{int(v.Ucode)},
			Measured: []int{int(ucode)},
		},
	}
	ok := r.Bl.Success && r.Tee.Success && r.Snp.Success && r.Ucode.Success
	if !ok {
		log.Debugf("SNP TCB check failed: BL: %v, TEE: %v, SNP: %v, UCODE: %v",
			r.Bl.Success, r.Tee.Success, r.Snp.Success, r.Ucode.Success)
	}
	r.Summary.Status = ar.StatusFromBool(ok)

	return r, ok
}

func verifySnpSignature(
	reportRaw []byte, report snpreport,
	certs []*x509.Certificate, fingerprints []string,
) (ar.SignatureResult, bool) {

	result := ar.SignatureResult{}

	if len(reportRaw) < signature_offset {
		log.Warn("Internal Error: Report buffer too small")
		result.SignCheck.Fail(ar.Internal)
		return result, false
	}

	// Strip the signature from the report and hash for signature verification
	// Table 23 @ https://www.amd.com/system/files/TechDocs/56860.pdf: signature 0x2A0 - 0x49F
	digest := sha512.Sum384(reportRaw[:signature_offset])

	// Golang SetBytes expects BigEndian byte array, but SNP values are little endian
	rRaw := report.SignatureR[:]
	for i := 0; i < len(rRaw)/2; i++ {
		rRaw[i], rRaw[len(rRaw)-i-1] = rRaw[len(rRaw)-i-1], rRaw[i]
	}
	sRaw := report.SignatureS[:]
	for i := 0; i < len(sRaw)/2; i++ {
		sRaw[i], sRaw[len(sRaw)-i-1] = sRaw[len(sRaw)-i-1], sRaw[i]
	}

	// Convert r, s to Big Int
	r := new(big.Int)
	r.SetBytes(rRaw)
	s := new(big.Int)
	s.SetBytes(sRaw)

	// Check that the algorithm is supported
	if report.SignatureAlgo != ecdsa384_with_sha384 {
		log.Debugf("Signature Algorithm %v not supported", report.SignatureAlgo)
		result.SignCheck.Fail(ar.UnsupportedAlgorithm)
		return result, false
	}

	// Extract the public key from the certificate
	pub, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Debug("Failed to extract ECDSA public key from certificate")
		result.SignCheck.Fail(ar.ExtractPubKey)
		return result, false
	}

	// Verify ECDSA Signature represented by r and s
	ok = ecdsa.Verify(pub, digest[:], r, s)
	if !ok {
		log.Debug("Failed to verify SNP report signature")
		result.SignCheck.Fail(ar.VerifySignature)
		return result, false
	}
	log.Debug("Successfully verified SNP report signature")
	result.SignCheck.Status = ar.StatusSuccess

	// Verify the SNP certificate chain
	ca := certs[len(certs)-1]
	x509Chains, err := internal.VerifyCertChain(certs[:len(certs)-1], []*x509.Certificate{ca})
	if err != nil {
		log.Debugf("Failed to verify certificate chain: %v", err)
		result.CertChainCheck.Fail(ar.VerifyCertChain)
		return result, false
	}
	log.Debug("Successfully verified SNP certificate chain")

	// Verify that the certificate fingerprint matches one of the manifest fingerprints
	result.CertChainCheck = verifyCaFingerprint(ca, fingerprints)
	if result.CertChainCheck.Status != ar.StatusSuccess {
		result.CertChainCheck.Fail(ar.CaFingerprint)
		return result, false
	}

	//Store details from validated certificate chains in the report
	for _, chain := range x509Chains {
		chainExtracted := []ar.X509CertExtracted{}
		for _, cert := range chain {
			chainExtracted = append(chainExtracted, ar.ExtractX509Infos(cert))
		}
		result.Certs = append(result.Certs, chainExtracted)
	}

	return result, true
}

const (
	structVersion = "1.3.6.1.4.1.3704.1.1"
	productName   = "1.3.6.1.4.1.3704.1.2"
	oidFmc        = "1.3.6.1.4.1.3704.1.3.9" // Only structVersion = 1 (Turin)
	oidBl         = "1.3.6.1.4.1.3704.1.3.1"
	oidTee        = "1.3.6.1.4.1.3704.1.3.2"
	oidSnp        = "1.3.6.1.4.1.3704.1.3.3"
	oidUcode      = "1.3.6.1.4.1.3704.1.3.8"
	oidChipId     = "1.3.6.1.4.1.3704.1.4"
	oidCspId      = "1.3.6.1.4.1.3704.1.5" // Only VLEK
)

func oidDesc(oid string) string {
	switch oid {
	case oidFmc:
		return "OID FMC SPL"
	case oidBl:
		return "OID BL SPL"
	case oidTee:
		return "OID TEE SPL"
	case oidSnp:
		return "OID SNP SPL"
	case oidUcode:
		return "OID uCode SPL"
	case oidChipId:
		return "OID CHIP ID"
	case oidCspId:
		return "OID CSP ID"
	default:
		return "OID UNKNOWN"
	}
}

func verifySnpExtensions(codeName string, cert *x509.Certificate, report *snpreport) ([]ar.Result, bool) {
	success := true
	var ok bool
	var r ar.Result

	// Checked extensions depend on the key type
	akType, err := internal.GetAkType(report.KeySelection)
	if err != nil {
		log.Debugf("Could not determine SNP attestation report attestation key type")
		success = false
	}

	// The x509 extensions must match the reported TCB
	tcb := ar.GetSnpTcb(codeName, report.ReportedTcb)

	results := make([]ar.Result, 0)

	if codeName == "Turin" {
		if r, ok = checkExtensionUint8(cert, oidFmc, tcb.Fmc); !ok {
			log.Debugf("SEV FMC extension check failed")
			success = false
		}
		results = append(results, r)
	}

	if r, ok = checkExtensionUint8(cert, oidBl, tcb.Bl); !ok {
		log.Debugf("SEV BL extension check failed")
		success = false
	}
	results = append(results, r)

	if r, ok = checkExtensionUint8(cert, oidTee, tcb.Tee); !ok {
		log.Debugf("SEV TEE extension check failed")
		success = false
	}
	results = append(results, r)

	if r, ok = checkExtensionUint8(cert, oidSnp, tcb.Snp); !ok {
		log.Debugf("SEV SNP extension check failed")
		success = false
	}
	results = append(results, r)

	if r, ok = checkExtensionUint8(cert, oidUcode, tcb.Ucode); !ok {
		log.Debugf("SEV UCODE extension check failed")
		success = false
	}
	results = append(results, r)

	// If the VCEK was used, we must compare the reported Chip ID against the extension Chip ID
	if akType == internal.VCEK {
		// For Milan and Genoa, the ChipID is 64 bytes. For Turin and later, it
		// is 8 bytes
		log.Debugf("VCEK Issuer CN=%q", cert.Issuer.CommonName)
		len := 64
		if strings.Contains(cert.Issuer.CommonName, "Turin") {
			log.Debug("set chip ID length to 8 for Turin")
			len = 8
		}
		if r, ok = checkExtensionBuf(cert, oidChipId, report.ChipId[:len]); !ok {
			log.Debugf("Chip ID extension check failed")
			success = false
		}
		results = append(results, r)
	}

	// If the VLEK was used, the CSP extensions must be present
	// TODO currently we simply accept all CSPs, discuss if we need to match here
	if akType == internal.VLEK {
		csp, ok := getExtensionString(cert, oidCspId)
		if !ok {
			log.Debug("CSP ID extension check failed")
			success = false
		}
		log.Debugf("CSP ID extension present: %v", csp)
		results = append(results, ar.Result{Status: ar.StatusFromBool(ok), Got: csp})
	}

	return results, success
}

func DecodeSnpReport(report []byte) (snpreport, error) {
	var s snpreport
	b := bytes.NewBuffer(report)
	err := binary.Read(b, binary.LittleEndian, &s)
	if err != nil {
		return snpreport{}, fmt.Errorf("failed to decode SNP report: %w", err)
	}
	return s, nil
}

func GetSnpCodeName(familyId, modelId uint8) string {

	log.Debugf("Get code name for combined family ID 0x%x, combined model id 0x%x",
		familyId, modelId)

	// Siena/Bergamo use the same root keys as Genoa:
	// https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/57230.pdf
	// The expected family is the combined family, which is extendedFamily + baseFamily
	// The expected model is the combined model, which is (extendedModel << 4) | baseModel
	switch familyId {
	case 0x19:
		switch {
		case modelId <= 0xF:
			return "Milan"
		case modelId >= 0x10 && modelId <= 0x1F:
			return "Genoa"
		case modelId >= 0xA0 && modelId <= 0xAF:
			// Bergamo and Siena also use Genoa PKI
			return "Genoa"
		}
	case 0x1A:
		if modelId < 0x1F {
			return "Turin"
		}
	default:
		return "Milan"
	}

	// Use default Milan (Milan servers do not support these attestation report fields
	// and are the oldest servers we support)
	return "Milan"
}

func min(v []uint8) uint8 {
	if len(v) == 0 {
		return 0
	}
	min := v[0]
	for _, v := range v {
		if v < min {
			min = v
		}
	}
	return min
}

func checkMinVersion(version []uint8, ref []uint8) bool {
	if len(version) != len(ref) {
		log.Warn("Internal Error: Version arrays differ in length")
		return false
	}
	for i := range version {
		if version[i] > ref[i] {
			return true
		} else if version[i] < ref[i] {
			return false
		}
	}
	return true
}

func getSnpVersionPolicy(report *snpreport, cert *x509.Certificate, policy *ar.SnpPolicy) (*ar.SnpVersion, string, error) {

	if cert == nil {
		return nil, "", fmt.Errorf("failed to get versioned SNP policy: certificate is nil")
	}

	codeName := strings.ToLower(GetSnpCodeName(report.CpuFamilyId, report.CpuModelId))
	codeNameCert := strings.ToLower(cert.Issuer.CommonName)
	log.Debugf("EPYC Code Name: %v / %v", codeName, codeNameCert)

	if !strings.Contains(codeNameCert, codeName) {
		return nil, "", fmt.Errorf("report code name (%v) does not match VCEK code name (%v)", codeName, codeNameCert)
	}

	// Extract correct policy for AMD EPYC generation
	for _, version := range policy.VersionPolicy {
		log.Tracef("Found policy for %v", version.Name)
		if strings.EqualFold(codeName, version.Name) {
			log.Tracef("Returning policy for %v", version.Name)
			return &version, codeName, nil
		}
	}
	return nil, "", fmt.Errorf("failed to find SNP policy for code name %v", codeName)
}

func checkExtensionUint8(cert *x509.Certificate, oid string, value uint8) (ar.Result, bool) {

	for _, ext := range cert.Extensions {

		if ext.Id.String() == oid {
			log.Debugf("Found %v, length %v, values %v", oid, len(ext.Value), ext.Value)
			if len(ext.Value) != 3 && len(ext.Value) != 4 {
				result := ar.Result{}
				result.Fail(ar.OidLength, fmt.Errorf("extension %v value unexpected length %v (expected 3 or 4)",
					oid, len(ext.Value)))
				return result, false
			}
			if ext.Value[0] != 0x2 {
				result := ar.Result{}
				result.Fail(ar.OidTag, fmt.Errorf("extension %v value[0]: %v does not match expected value 2 (tag Integer)",
					oid, ext.Value[0]))
				return result, false
			}
			if ext.Value[1] == 0x1 {
				if ext.Value[2] != value {
					log.Debugf("extension %v value[2]: %v does not match expected value %v",
						oid, ext.Value[2], value)
					return ar.Result{
						Status:   ar.StatusFail,
						Expected: fmt.Sprintf("%v: %v", oidDesc(oid), strconv.FormatUint(uint64(value), 10)),
						Got:      strconv.FormatUint(uint64(ext.Value[2]), 10),
					}, false
				}
			} else if ext.Value[1] == 0x2 {
				// Due to openssl, the sign bit must remain zero for positive integers
				// even though this field is defined as unsigned int in the AMD spec
				// Thus, if the most significant bit is required, one byte of additional 0x00 padding is added
				if ext.Value[2] != 0x00 || ext.Value[3] != value {
					log.Debugf("extension %v value = %v%v does not match expected value  %v",
						oid, ext.Value[2], ext.Value[3], value)
					return ar.Result{
						Status:   ar.StatusFail,
						Expected: fmt.Sprintf("%v: %v", oidDesc(oid), strconv.FormatUint(uint64(value), 10)),
						Got:      strconv.FormatUint(uint64(ext.Value[3]), 10),
					}, false
				}
			} else {
				result := ar.Result{}
				result.Fail(ar.OidLength, fmt.Errorf(
					"extension %v value[1]: %v does not match expected value 1 or 2 (length of integer)",
					oid, ext.Value[1]))
				return result, false
			}
			return ar.Result{
				Status: ar.StatusSuccess,
				Got:    fmt.Sprintf("%v: %v", oidDesc(oid), strconv.FormatUint(uint64(value), 10)),
			}, true
		}
	}

	result := ar.Result{}
	result.Fail(ar.OidNotPresent, fmt.Errorf("extension %v not present in certificate", oid))

	return result, false
}

func checkExtensionBuf(cert *x509.Certificate, oid string, buf []byte) (ar.Result, bool) {

	for _, ext := range cert.Extensions {

		if ext.Id.String() == oid {
			if cmp := bytes.Compare(ext.Value, buf); cmp != 0 {
				log.Debugf("extension %v value %v does not match expected value %v",
					oid, hex.EncodeToString(ext.Value), hex.EncodeToString(buf))
				return ar.Result{
					Status:   ar.StatusFail,
					Expected: fmt.Sprintf("%v: %v", oidDesc(oid), hex.EncodeToString(buf)),
					Got:      hex.EncodeToString(ext.Value),
				}, false
			}
			return ar.Result{
				Status: ar.StatusSuccess,
				Got:    fmt.Sprintf("%v: %v", oidDesc(oid), hex.EncodeToString(ext.Value)),
			}, true
		}
	}

	result := ar.Result{}
	result.Fail(ar.OidNotPresent, fmt.Errorf("extension %v not present in certificate", oid))
	return result, false
}

func getExtensionString(cert *x509.Certificate, oid string) (string, bool) {

	for _, ext := range cert.Extensions {
		if ext.Id.String() == oid {
			return string(ext.Value), true
		}
	}
	log.Debugf("extension %v: %v not present in certificate", oid, oidDesc(oid))
	return "", false
}
