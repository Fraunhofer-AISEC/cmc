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

package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

type snpreport struct {
	// Table 24 @ https://www.amd.com/system/files/TechDocs/56860.pdf
	Status     uint32
	ReportSize uint32
	Reserved0  [24]byte
	// Table 21 @ https://www.amd.com/system/files/TechDocs/56860.pdf
	Version         uint32
	GuestSvn        uint32
	Policy          uint64
	FamilyId        [16]byte
	ImageId         [16]byte
	Vmpl            uint32
	SignatureAlgo   uint32
	CurrentTcb      uint64 // platform_version
	PlatformInfo    uint64
	AuthorKeyEn     uint32
	Reserved1       uint32
	ReportData      [64]byte
	Measurement     [48]byte
	HostData        [32]byte
	IdKeyDigest     [48]byte
	AuthorKeyDigest [48]byte
	ReportId        [32]byte
	ReportIdMa      [32]byte
	ReportedTcb     uint64
	Reserved2       [24]byte
	ChipId          [64]byte
	//Reserved3 [192]byte
	CommittedTcb   uint64
	CurrentBuild   uint8
	CurrentMinor   uint8
	CurrentMajor   uint8
	Reserved3a     uint8
	CommittedBuild uint8
	CommittedMinor uint8
	CommittedMajor uint8
	Reserved3b     uint8
	LaunchTcb      uint64
	Reserved3c     [168]byte
	// Table 23 @ https://www.amd.com/system/files/TechDocs/56860.pdf
	SignatureR [72]byte
	SignatureS [72]byte
	Reserved4  [368]byte
}

const (
	ecdsa384_with_sha384 = 1
)

const (
	header_offset    = 0x20
	signature_offset = 0x2A0
)

func verifySnpMeasurements(snpM ar.Measurement, nonce []byte, referenceValues []ar.ReferenceValue,
) (*ar.MeasurementResult, bool) {

	log.Trace("Verifying SNP measurements")

	result := &ar.MeasurementResult{
		Type:      "SNP Result",
		SnpResult: &ar.SnpResult{},
	}
	ok := true

	if len(referenceValues) == 0 {
		log.Trace("Could not find SNP Reference Value")
		result.Summary.SetErr(ar.RefValNotPresent)
		return result, false
	} else if len(referenceValues) > 1 {
		log.Tracef("Report contains %v reference values. Currently, only 1 SNP Reference Value is supported",
			len(referenceValues))
		result.Summary.SetErr(ar.RefValMultiple)
		return result, false
	}
	snpReferenceValue := referenceValues[0]

	if snpReferenceValue.Type != "SNP Reference Value" {
		log.Tracef("SNP Reference Value invalid type %v", snpReferenceValue.Type)
		result.Summary.SetErr(ar.RefValType)
		return result, false
	}
	if snpReferenceValue.Snp == nil {
		log.Trace("SNP Reference Value does not contain policy")
		result.Summary.SetErr(ar.DetailsNotPresent)
		return result, false
	}

	// Extract the SNP attestation report data structure
	s, err := DecodeSnpReport(snpM.Evidence)
	if err != nil {
		log.Tracef("Failed to decode SNP report: %v", err)
		result.Summary.SetErr(ar.ParseEvidence)
		return result, false
	}

	// Compare nonce for freshness (called report data in the SNP attestation report structure)
	nonce64 := make([]byte, 64)
	copy(nonce64, nonce)
	if cmp := bytes.Compare(s.ReportData[:], nonce64); cmp != 0 {
		log.Tracef("Nonces mismatch: Supplied Nonce = %v, Nonce in SNP Report = %v)",
			hex.EncodeToString(nonce), hex.EncodeToString(s.ReportData[:]))
		result.Freshness.Success = false
		result.Freshness.Expected = hex.EncodeToString(nonce)
		result.Freshness.Got = hex.EncodeToString(s.ReportData[:])
		ok = false
	} else {
		result.Freshness.Success = true
	}

	certs, err := internal.ParseCertsDer(snpM.Certs)
	if err != nil {
		log.Tracef("Failed to parse certificates: %v", err)
		result.Summary.SetErr(ar.ParseCert)
		return result, false
	}

	// Verify Signature, created with SNP VCEK private key
	sig, ret := verifySnpSignature(snpM.Evidence, s, certs, snpReferenceValue.Snp.CaFingerprint)
	if !ret {
		ok = false
	}
	result.Signature = sig

	// Compare Measurements
	if cmp := bytes.Compare(s.Measurement[:], snpReferenceValue.Sha384); cmp != 0 {
		log.Trace("Failed to verify SNP reference value")
		result.Artifacts = append(result.Artifacts,
			ar.DigestResult{
				Name:    snpReferenceValue.Name,
				Digest:  hex.EncodeToString(snpReferenceValue.Sha384),
				Success: false,
				Type:    "Reference Value",
			})
		result.Artifacts = append(result.Artifacts,
			ar.DigestResult{
				Name:    snpReferenceValue.Name,
				Digest:  hex.EncodeToString(s.Measurement[:]),
				Success: false,
				Type:    "Measurement",
			})

		ok = false
	} else {
		log.Trace("Successfully verified SNP reference value")
		// As we previously checked, that the attestation report contains exactly one
		// SNP Reference Value, we can set this here:
		result.Artifacts = append(result.Artifacts,
			ar.DigestResult{
				Name:    snpReferenceValue.Name,
				Digest:  hex.EncodeToString(s.Measurement[:]),
				Success: true,
			})
	}

	// Compare SNP parameters
	result.SnpResult.VersionMatch, ret = verifySnpVersion(s, snpReferenceValue.Snp.Version)
	if !ret {
		ok = false
	}
	result.SnpResult.PolicyCheck, ret = verifySnpPolicy(s, snpReferenceValue.Snp.Policy)
	if !ret {
		ok = false
	}
	result.SnpResult.FwCheck, ret = verifySnpFw(s, snpReferenceValue.Snp.Fw)
	if !ret {
		ok = false
	}
	result.SnpResult.TcbCheck, ret = verifySnpTcb(s, snpReferenceValue.Snp.Tcb)
	if !ret {
		ok = false
	}

	result.Summary.Success = ok

	return result, ok
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

func verifySnpVersion(s snpreport, version uint32) (ar.Result, bool) {
	r := ar.Result{}
	ok := s.Version == version
	if !ok {
		log.Tracef("SNP report version mismatch: Report = %v, supplied = %v", s.Version, version)
		r.Success = false
		r.Expected = strconv.FormatUint(uint64(version), 10)
		r.Got = strconv.FormatUint(uint64(s.Version), 10)
	} else {
		r.Success = true
	}
	return r, ok
}

func verifySnpPolicy(s snpreport, v ar.SnpPolicy) (ar.PolicyCheck, bool) {

	abiMajor := uint8(s.Policy & 0xFF)
	abiMinor := uint8((s.Policy >> 8) & 0xFF)
	smt := (s.Policy & (1 << 16)) != 0
	migration := (s.Policy & (1 << 18)) != 0
	debug := (s.Policy & (1 << 19)) != 0
	singleSocket := (s.Policy & (1 << 20)) != 0

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
		log.Tracef("SNP policies do not match: Abi: %v, Smt: %v, Migration: %v, Debug: %v, SingleSocket: %v",
			r.Abi.Success, r.Smt.Success, r.Migration.Success, r.Debug.Success, r.SingleSocket.Success)
	}
	r.Summary.Success = ok

	return r, ok
}

func verifySnpFw(s snpreport, v ar.SnpFw) (ar.VersionCheck, bool) {

	build := min([]uint8{s.CurrentBuild, s.CommittedBuild})
	major := min([]uint8{s.CurrentMajor, s.CommittedMajor})
	minor := min([]uint8{s.CurrentMinor, s.CommittedMinor})

	ok := checkMinVersion([]uint8{major, minor, build}, []uint8{v.Major, v.Minor, v.Build})
	if !ok {
		log.Tracef("SNP FW version check failed. Expected: %v.%v.%v, got %v.%v.%v",
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

func verifySnpTcb(s snpreport, v ar.SnpTcb) (ar.TcbCheck, bool) {

	currBl := uint8(s.CurrentTcb & 0xFF)
	commBl := uint8(s.CommittedTcb & 0xFF)
	launBl := uint8(s.LaunchTcb & 0xFF)
	repoBl := uint8(s.ReportedTcb & 0xFF)
	currTee := uint8((s.CurrentTcb >> 8) & 0xFF)
	commTee := uint8((s.CommittedTcb >> 8) & 0xFF)
	launTee := uint8((s.LaunchTcb >> 8) & 0xFF)
	repoTee := uint8((s.ReportedTcb >> 8) & 0xFF)
	currSnp := uint8((s.CurrentTcb >> 48) & 0xFF)
	commSnp := uint8((s.CommittedTcb >> 48) & 0xFF)
	launSnp := uint8((s.LaunchTcb >> 48) & 0xFF)
	repoSnp := uint8((s.ReportedTcb >> 48) & 0xFF)
	currUcode := uint8((s.CurrentTcb >> 56) & 0xFF)
	commUcode := uint8((s.CommittedTcb >> 56) & 0xFF)
	launUcode := uint8((s.LaunchTcb >> 56) & 0xFF)
	repoUcode := uint8((s.ReportedTcb >> 56) & 0xFF)

	bl := min([]uint8{currBl, commBl, launBl, repoBl})
	tee := min([]uint8{currTee, commTee, launTee, repoTee})
	snp := min([]uint8{currSnp, commSnp, launSnp, repoSnp})
	ucode := min([]uint8{currUcode, commUcode, launUcode, repoUcode})

	// Convert to int, as json.Marshal otherwise interprets the values as strings
	r := ar.TcbCheck{
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
		log.Tracef("SNP TCB check failed: BL: %v, TEE: %v, SNP: %v, UCODE: %v",
			r.Bl.Success, r.Tee.Success, r.Snp.Success, r.Ucode.Success)
	}
	r.Summary.Success = ok

	return r, ok
}

func verifySnpSignature(
	reportRaw []byte, report snpreport,
	certs []*x509.Certificate, fingerprint string,
) (ar.SignatureResult, bool) {

	result := ar.SignatureResult{}

	if len(reportRaw) < (header_offset + signature_offset) {
		log.Warn("Internal Error: Report buffer too small")
		result.SignCheck.SetErr(ar.Internal)
		return result, false
	}

	// Strip the header and the signature from the report and hash for signature verification
	// Table 21, 23 @ https://www.amd.com/system/files/TechDocs/56860.pdf
	digest := sha512.Sum384(reportRaw[0x20 : 0x20+0x2A0])

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

	// Examine SNP x509 extensions
	extensionResults, ok := verifySnpExtensions(certs[0], &report)
	result.ExtensionsCheck = extensionResults
	if !ok {
		return result, false
	}

	// Check that the algorithm is supported
	if report.SignatureAlgo != ecdsa384_with_sha384 {
		log.Tracef("Signature Algorithm %v not supported", report.SignatureAlgo)
		result.SignCheck.SetErr(ar.UnsupportedAlgorithm)
		return result, false
	}

	// Extract the public key from the certificate
	pub, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Trace("Failed to extract ECDSA public key from certificate")
		result.SignCheck.SetErr(ar.ExtractPubKey)
		return result, false
	}

	// Verify ECDSA Signature represented by r and s
	ok = ecdsa.Verify(pub, digest[:], r, s)
	if !ok {
		log.Trace("Failed to verify SNP report signature")
		result.SignCheck.SetErr(ar.VerifySignature)
		return result, false
	}
	log.Trace("Successfully verified SNP report signature")
	result.SignCheck.Success = true

	// Verify the SNP certificate chain
	ca := certs[len(certs)-1]
	x509Chains, err := internal.VerifyCertChain(certs[:len(certs)-1], []*x509.Certificate{ca})
	if err != nil {
		log.Tracef("Failed to verify certificate chain: %v", err)
		result.CertChainCheck.SetErr(ar.VerifyCertChain)
		return result, false
	}
	// Verify that the reference value fingerprint matches the certificate fingerprint
	if fingerprint == "" {
		log.Trace("Reference value SNP CA fingerprint not present")
		result.CertChainCheck.SetErr(ar.NotPresent)
		return result, false
	}
	refFingerprint, err := hex.DecodeString(fingerprint)
	if err != nil {
		log.Tracef("Failed to decode CA fingerprint %v: %v", fingerprint, err)
		result.CertChainCheck.SetErr(ar.ParseCAFingerprint)
		return result, false
	}
	caFingerprint := sha256.Sum256(ca.Raw)
	if !bytes.Equal(refFingerprint, caFingerprint[:]) {
		log.Tracef("Reference Values CA fingerprint '%v' does not match trusted CA fingerprint '%v'",
			fingerprint, hex.EncodeToString(caFingerprint[:]))
		result.CertChainCheck.Success = false
		result.CertChainCheck.Expected = fingerprint
		result.CertChainCheck.Got = hex.EncodeToString(caFingerprint[:])
		return result, false
	}
	result.CertChainCheck.Success = true

	//Store details from (all) validated certificate chain(s) in the report
	for _, chain := range x509Chains {
		chainExtracted := []ar.X509CertExtracted{}
		for _, cert := range chain {
			chainExtracted = append(chainExtracted, ar.ExtractX509Infos(cert))
		}
		result.ValidatedCerts = append(result.ValidatedCerts, chainExtracted)
	}

	return result, true
}

func verifySnpExtensions(cert *x509.Certificate, report *snpreport) ([]ar.Result, bool) {
	success := true
	var ok bool
	var r ar.Result
	tcb := report.CurrentTcb

	results := make([]ar.Result, 0)

	if r, ok = checkExtensionUint8(cert, "1.3.6.1.4.1.3704.1.3.1", uint8(tcb)); !ok {
		log.Tracef("SEV BL Extension Check failed:")
		success = false
	}
	results = append(results, r)

	if r, ok = checkExtensionUint8(cert, "1.3.6.1.4.1.3704.1.3.2", uint8(tcb>>8)); !ok {
		log.Tracef("SEV TEE Extension Check failed")
		success = false
	}
	results = append(results, r)

	if r, ok = checkExtensionUint8(cert, "1.3.6.1.4.1.3704.1.3.3", uint8(tcb>>48)); !ok {
		log.Tracef("SEV SNP Extension Check failed")
		success = false
	}
	results = append(results, r)

	if r, ok = checkExtensionUint8(cert, "1.3.6.1.4.1.3704.1.3.8", uint8(tcb>>56)); !ok {
		log.Tracef("SEV UCODE Extension Check failed")
		success = false
	}
	results = append(results, r)

	if r, ok = checkExtensionBuf(cert, "1.3.6.1.4.1.3704.1.4", report.ChipId[:]); !ok {
		log.Tracef("Chip ID Extension Check failed")
		success = false
	}
	results = append(results, r)

	return results, success
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
