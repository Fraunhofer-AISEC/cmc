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
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	log "github.com/sirupsen/logrus"
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
	Currentcb       uint64 // platform_version
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

func verifySnpMeasurements(snpM *SnpMeasurement, nonce []byte, verifications []Verification) (*SnpMeasurementResult, bool) {
	result := &SnpMeasurementResult{}
	ok := true

	// If the attestationreport does contain neither SNP measurements, nor SNP verifications
	// there is nothing to to
	if snpM == nil && len(verifications) == 0 {
		return nil, true
	}

	// If the attestationreport contains SNP verifications, but no SNP measurement, the
	// attestation must fail
	if snpM == nil {
		for _, v := range verifications {
			msg := fmt.Sprintf("SNP Measurement not present. Cannot verify SNP verification (hash: %v)", v.Sha384)
			result.VerificationsCheck.setFalseMulti(&msg)
		}
		result.Summary.Success = false
		return result, false
	}

	if len(verifications) == 0 {
		msg := fmt.Sprintf("Could not find SNP verification")
		result.Summary.setFalse(&msg)
		return result, false
	} else if len(verifications) > 1 {
		msg := fmt.Sprintf("Report contains %v verifications. Currently, only 1 SNP verification is supported", len(verifications))
		result.Summary.setFalse(&msg)
		return result, false
	}
	snpVerification := verifications[0]

	if snpVerification.Type != "SNP Verification" {
		msg := fmt.Sprintf("SNP Verification invalid type %v", snpVerification.Type)
		result.Summary.setFalse(&msg)
		return result, false
	}
	if snpVerification.Policy == nil {
		msg := fmt.Sprintf("SNP Verification does not contain policy")
		result.Summary.setFalse(&msg)
		return result, false
	}
	if snpVerification.Version == nil {
		msg := fmt.Sprintf("SNP Verification does not contain version")
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Extract the SNP attestation report data structure
	s, err := decodeSnpReport(snpM.Report)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode SNP report: %v", err)
		result.Summary.setFalse(&msg)
		return result, false
	}

	// Compare Nonce for Freshness (called Report Data in the SNP Attestation Report Structure)
	if cmp := bytes.Compare(s.ReportData[:], nonce); cmp != 0 {
		msg := fmt.Sprintf("Nonces mismatch: Supplied Nonce = %v, Nonce in SNP Report = %v)", hex.EncodeToString(nonce), hex.EncodeToString(s.ReportData[:]))
		result.Freshness.setFalse(&msg)
		ok = false
	}

	// Verify Signature, created with SNP VCEK private key
	sig, ret := verifySnpSignature(snpM.Report, s, []byte(snpM.Certs.Leaf))
	if !ret {
		ok = false
	}
	result.Signature = sig

	// Verify the SNP certificate chain
	err = verifyCertChain(&snpM.Certs)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify certificate chain: %v", err)
		result.Signature.CertCheck.setFalse(&msg)
		ok = false
	} else {
		result.Signature.CertCheck.Success = true
	}

	// Compare Measurements
	m, err := hex.DecodeString(snpVerification.Sha384)
	if err != nil {
		msg := fmt.Sprintf("Failed to decode SNP Verification: %v", err)
		result.Summary.setFalse(&msg)
		ok = false
	}
	if cmp := bytes.Compare(s.Measurement[:], m); cmp != 0 {
		msg := fmt.Sprintf("SNP Measurement mismatch: Supplied measurement = %v, SNP report measurement = %v", snpVerification.Sha384, hex.EncodeToString(s.Measurement[:]))
		result.MeasurementMatch.setFalse(&msg)
		ok = false
	}

	// Compare SNP parameters
	result.ParamsMatch, ret = verifySnpParams(&s, &snpVerification)
	if !ret {
		ok = false
	}

	result.Summary.Success = ok

	return result, ok
}

func decodeSnpReport(report []byte) (snpreport, error) {
	var s snpreport
	b := bytes.NewBuffer(report)
	err := binary.Read(b, binary.LittleEndian, &s)
	if err != nil {
		return snpreport{}, fmt.Errorf("Failed to decode SNP report: %w", err)
	}
	return s, nil
}

func verifySnpParams(s *snpreport, v *Verification) (Result, bool) {
	result := Result{
		Success: true,
	}

	if s.Version != *v.Version {
		msg := fmt.Sprintf("SNP report version mismatch: Report = %v, supplied = %v", s.Version, *v.Version)
		result.setFalse(&msg)
	}

	abiMajor := uint8(s.Policy & 0xFF)
	abiMinor := uint8((s.Policy >> 8) & 0xFF)
	smt := (s.Policy & (1 << 16)) != 0
	migration := (s.Policy & (1 << 18)) != 0
	debug := (s.Policy & (1 << 19)) != 0
	singleSocket := (s.Policy & (1 << 20)) != 0

	if abiMajor != v.Policy.AbiMajor {
		msg := fmt.Sprintf("SNP report AbiMinor mismatch: Report = %v, supplied = %v", abiMajor, v.Policy.AbiMajor)
		result.setFalse(&msg)
	}
	if abiMinor != v.Policy.AbiMinor {
		msg := fmt.Sprintf("SNP report AbiMinor mismatch: Report = %v, supplied = %v", abiMinor, v.Policy.AbiMinor)
		result.setFalse(&msg)
	}
	if smt != v.Policy.Smt {
		msg := fmt.Sprintf("SNP report SMT mismatch: Report = %v, supplied = %v", smt, v.Policy.Smt)
		result.setFalse(&msg)
	}
	if migration != v.Policy.Migration {
		msg := fmt.Sprintf("SNP report Migration Agent mismatch: Report = %v, supplied = %v", migration, v.Policy.Migration)
		result.setFalse(&msg)
	}
	if debug != v.Policy.Debug {
		msg := fmt.Sprintf("SNP report Debug Support mismatch: Report = %v, supplied = %v", debug, v.Policy.Debug)
		result.setFalse(&msg)
	}
	if singleSocket != v.Policy.SingleSocket {
		msg := fmt.Sprintf("SNP report SingleSocket mismatch: Report = %v, supplied = %v", singleSocket, v.Policy.SingleSocket)
		result.setFalse(&msg)
	}

	return result, result.Success
}

func verifySnpSignature(reportRaw []byte, report snpreport, cert []byte) (SignatureResult, bool) {
	result := SignatureResult{}

	if len(reportRaw) < (header_offset + signature_offset) {
		msg := fmt.Sprintf("Internal Error: Report buffer too small")
		result.Signature.setFalse(&msg)
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

	// Load the VCEK certificate
	c, err := loadCert(cert)
	if err != nil {
		msg := fmt.Sprintf("Failed to load certificate: %v", err)
		result.Signature.setFalse(&msg)
		return result, false
	}
	result.Name = c.Subject.CommonName
	result.Organization = c.Subject.Organization
	result.SubjectKeyId = hex.EncodeToString(c.SubjectKeyId)
	result.AuthorityKeyId = hex.EncodeToString(c.AuthorityKeyId)

	// Examine SNP x509 extensions
	extensionResult, ok := verifySnpExtensions(c, &report)
	result.ExtensionsCheck = &extensionResult
	if !ok {
		return result, false
	}

	// Check that the algorithm is supported
	if report.SignatureAlgo != ecdsa384_with_sha384 {
		msg := fmt.Sprintf("Siganture Algorithm %v not supported", report.SignatureAlgo)
		result.Signature.setFalse(&msg)
		return result, false
	}

	// Extract the public key from the certificate
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		msg := fmt.Sprintf("Failed to extract ECDSA public key from certificate")
		result.Signature.setFalse(&msg)
		return result, false
	}

	// Verify ECDSA Signature represented by r and s
	ok = ecdsa.Verify(pub, digest[:], r, s)
	if !ok {
		msg := fmt.Sprintf("Failed to verify SNP report signature")
		result.Signature.setFalse(&msg)
		return result, false
	}
	log.Trace("Successfully verified SNP report signature")

	return result, true
}

func verifySnpExtensions(cert *x509.Certificate, report *snpreport) (ResultMulti, bool) {
	result := ResultMulti{}
	ok := true
	tcb := report.ReportedTcb

	if err := checkExtensionUint8(cert, "1.3.6.1.4.1.3704.1.3.1", uint8(tcb)); err != nil {
		msg := fmt.Sprintf("SEV BL Extension Check failed: %v", err)
		result.setFalseMulti(&msg)
		ok = false
	}

	if err := checkExtensionUint8(cert, "1.3.6.1.4.1.3704.1.3.2", uint8(tcb>>8)); err != nil {
		msg := fmt.Sprintf("SEV TEE Extension Check failed: %v", err)
		result.setFalseMulti(&msg)
		ok = false
	}

	if err := checkExtensionUint8(cert, "1.3.6.1.4.1.3704.1.3.3", uint8(tcb>>48)); err != nil {
		msg := fmt.Sprintf("SEV SNP Extension Check failed: %v", err)
		result.setFalseMulti(&msg)
		ok = false
	}

	if err := checkExtensionUint8(cert, "1.3.6.1.4.1.3704.1.3.8", uint8(tcb>>56)); err != nil {
		msg := fmt.Sprintf("SEV UCODE Extension Check failed: %v", err)
		result.setFalseMulti(&msg)
		ok = false
	}

	if err := checkExtensionBuf(cert, "1.3.6.1.4.1.3704.1.4", report.ChipId[:]); err != nil {
		msg := fmt.Sprintf("Chip ID Extension Check failed: %v", err)
		result.setFalseMulti(&msg)
		ok = false
	}

	result.Success = ok

	return result, ok
}
