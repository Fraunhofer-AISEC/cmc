// Copyright (c) 2021 - 2026 Fraunhofer AISEC
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
	"crypto/x509"
	"fmt"
	"slices"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// The attestation result version
const (
	resultVersion = "3.8.0"
)

func GetResultVersion() string {
	return resultVersion
}

// AttestationResult represents the results of all steps taken during
// the validation of an attestation report.
type AttestationResult struct {
	Version      string              `json:"version" cbor:"0,keyasint"`
	Type         string              `json:"type" cbor:"1,keyasint"`
	Summary      Result              `json:"summary" cbor:"2,keyasint"`
	Prover       Endpoint            `json:"prover" cbor:"3,keyasint"`
	Verifier     Endpoint            `json:"verifier,omitzero" cbor:"4,keyasint,omitzero"`
	Name         string              `json:"name,omitempty" cbor:"10,keyasint,omitempty"`
	Created      string              `json:"created,omitempty" cbor:"5,keyasint,omitempty"`
	Freshness    Result              `json:"freshness" cbor:"6,keyasint"`
	AttestLevel  AttestLevel         `json:"attestLevel" cbor:"7,keyasint"`
	Measurements []MeasurementResult `json:"measurements" cbor:"8,keyasint"`
	Metadata     MetadataSummary     `json:"metadata" cbor:"9,keyasint"`
	PeerAuth     Result              `json:"peerAuth,omitzero" cbor:"11,keyasint,omitzero"`
	Claims       map[string][]byte   `json:"claims,omitempty" cbor:"12,keyasint,omitempty"`
}

// AttestLevel states which kind of evidence an attestation was based on
type AttestLevel int

const (
	// LevelNone means no evidence was verified
	LevelNone AttestLevel = 0
	// LevelSoftware means only software-signed evidence was verified
	LevelSoftware AttestLevel = 1
	// LevelHardware means evidence of at least one hardware trust anchor was verified
	LevelHardware AttestLevel = 2
)

var attestLevelNames = []string{"none", "software", "hardware"}

// AttestLevelNames returns the names of all attestation levels in ascending order
func AttestLevelNames() []string {
	return slices.Clone(attestLevelNames)
}

func (l AttestLevel) String() string {
	if l < 0 || int(l) >= len(attestLevelNames) {
		return fmt.Sprintf("invalid(%d)", int(l))
	}
	return attestLevelNames[l]
}

// ParseAttestLevel parses the name of an attestation level
func ParseAttestLevel(s string) (AttestLevel, error) {
	i := slices.Index(attestLevelNames, s)
	if i < 0 {
		return LevelNone, fmt.Errorf("unknown attestation level %q, expected one of %v", s,
			strings.Join(attestLevelNames, ", "))
	}
	return AttestLevel(i), nil
}

type Endpoint struct {
	Hostname string `json:"hostname,omitempty" cbor:"0,keyasint,omitempty"`
	Ip       string `json:"ip,omitempty" cbor:"1,keyasint,omitempty"`
	PeerId   string `json:"peerId,omitempty" cbor:"2,keyasint,omitempty"`
}

type Status string

const (
	StatusSuccess Status = "success"
	StatusFail    Status = "fail"
	StatusWarn    Status = "warn"
)

// statusRank orders statuses by severity. An unset status is neutral, as many optional checks
// legitimately stay unset
var statusRank = map[Status]int{
	"":            0,
	StatusSuccess: 1,
	StatusWarn:    2,
	StatusFail:    3,
}

// Worse returns the more severe of both statuses (fail > warn > success > unset)
func (s Status) Worse(o Status) Status {
	if statusRank[o] > statusRank[s] {
		return o
	}
	return s
}

// Result is a generic struct do display if a verification of a measured/provided data structure
// against a reference data structure was successful
type Result struct {
	Status          Status      `json:"status"`
	Got             string      `json:"got,omitempty" cbor:"0,keyasint,omitempty"`
	Expected        string      `json:"expected,omitempty" cbor:"1,keyasint,omitempty"`
	ExpectedOneOf   []string    `json:"expectedOneOf,omitempty" cbor:"2,keyasint,omitempty"`
	ExpectedBetween []string    `json:"expectedBetween,omitempty" cbor:"3,keyasint,omitempty"`
	ErrorCodes      []ErrorCode `json:"errorCodes,omitempty" cbor:"4,keyasint,omitempty"`
	Details         string      `json:"details,omitempty" cbor:"5,keyasint,omitempty"`
}

//
// Metadata-related definitions
//

type MetadataSummary struct {
	Summary                  Result              `json:"summary" cbor:"6,keyasint"`
	ImageDescriptionResult   MetadataResult      `json:"imageDescriptionResult" cbor:"0,keyasint"`
	ManifestResults          []MetadataResult    `json:"manifestResults" cbor:"1,keyasint"`
	CompanyDescriptionResult *MetadataResult     `json:"companyDescriptionResult,omitempty" cbor:"2,keyasint,omitempty"`
	UnknownResults           []MetadataResult    `json:"unknownResults,omitempty" cbor:"3,keyasint,omitempty"`
	CompatibilityResult      CompatibilityResult `json:"compatibilityResult" cbor:"4,keyasint"`
	OmspResults              []MetadataResult    `json:"omspSignatureResults,omitempty" cbor:"5,keyasint,omitempty"`
}

// MetadataResult holds the verification result of a single metadata item together with the
// metadata fields required for display. The metadata content itself is provided via MetadataSet
type MetadataResult struct {
	MetaInfo
	BaseLayers       []string               `json:"baseLayers,omitempty" cbor:"12,keyasint,omitempty"`
	Details          map[string]interface{} `json:"details,omitempty" cbor:"18,keyasint,omitempty"`
	Location         string                 `json:"location,omitempty" cbor:"20,keyasint,omitempty"`
	Summary          Result                 `json:"summary" cbor:"40,keyasint"`
	ValidityCheck    Result                 `json:"validityCheck,omitzero" cbor:"41,keyasint,omitzero"`
	SignatureCheck   []SignatureResult      `json:"signatureValidation,omitempty" cbor:"42,keyasint,omitempty"`
	Digest           string                 `json:"digest,omitempty" cbor:"50,keyasint,omitempty"`
	OmspValidity     *Result                `json:"omspValidity,omitempty" cbor:"51,keyasint,omitempty"`
	OmspStatus       *Result                `json:"omspStatus,omitempty" cbor:"52,keyasint,omitempty"`
	RevocationTime   string                 `json:"revocationTime,omitempty" cbor:"53,keyasint,omitempty"`
	RevocationReason string                 `json:"revocationReason,omitempty" cbor:"54,keyasint,omitempty"`
}

type CompatibilityResult struct {
	Summary               Result   `json:"result" cbor:"0,keyasint"`
	DescriptionMatch      []Result `json:"descriptionMatch,omitempty" cbor:"1,keyasint,omitempty"`
	ManifestMatch         []Result `json:"manifestMatch,omitempty" cbor:"2,keyasint,omitempty"`
	ManifestCompatibility []Result `json:"manifestCompatibility,omitempty" cbor:"3,keyasint,omitempty"`
}

//
// Generic measurement definitions
//

type MeasurementResult struct {
	Type         string          `json:"type" cbor:"0,keyasint"`
	Summary      Result          `json:"summary" cbor:"1,keyasint"`
	Freshness    Result          `json:"freshness" cbor:"2,keyasint"`
	Signature    SignatureResult `json:"signature" cbor:"3,keyasint"`
	Artifacts    []DigestResult  `json:"artifacts,omitempty" cbor:"4,keyasint,omitempty"`
	TpmResult    *TpmResult      `json:"tpmResult,omitempty" cbor:"5,keyasint,omitempty"`
	SnpResult    *SnpResult      `json:"snpResult,omitempty" cbor:"6,keyasint,omitempty"`
	SgxResult    *SgxResult      `json:"sgxResult,omitempty" cbor:"7,keyasint,omitempty"`
	TdxResult    *TdxResult      `json:"tdxResult,omitempty" cbor:"8,keyasint,omitempty"`
	NvidiaResult *NvidiaResult   `json:"nvidiaResult,omitempty" cbor:"9,keyasint,omitempty"`
}

const (
	TYPE_DIGEST_VERIFIED        = "Verified"        // measurement with matching reference value
	TYPE_DIGEST_MEASUREMENT     = "Measurement"     // measurement without matching reference value
	TYPE_DIGEST_REFERENCE_VALUE = "Reference Value" // reference value with no matching measurement
	TYPE_DIGEST_ALTERNATIVE     = "Alternative"     // accepted alternative which was not launched
)

// DigestResult represents a generic result for a digest that was processed
// during attestation. The Index is the unique identifier for the result: This is the number of the
// PCR in case of TPM reference values, the MR index according to UEFI Spec 2.10 Section 38.4.1 in
// case of TDX reference values, and simply a monotonic counter for other reference values.
type DigestResult struct {
	Success     bool       `json:"success" cbor:"0,keyasint"`
	Launched    bool       `json:"launched" cbor:"1,keyasint"`
	Type        string     `json:"type,omitempty" cbor:"2,keyasint,omitempty"`
	Name        string     `json:"name,omitempty" cbor:"3,keyasint,omitempty"`
	Index       int        `json:"index" cbor:"4,keyasint"`
	Digest      HexByte    `json:"digest,omitempty" cbor:"5,keyasint,omitempty"`
	HashAlg     string     `json:"hashAlg,omitempty" cbor:"6,keyasint,omitempty"`
	Measured    string     `json:"measured,omitempty" cbor:"7,keyasint,omitempty"`
	Description string     `json:"description,omitempty" cbor:"8,keyasint,omitempty"`
	EventData   *EventData `json:"eventData,omitempty" cbor:"9,keyasint,omitempty"`
	CtrDetails  *CtrData   `json:"ctrDetails,omitempty" cbor:"10,keyasint,omitempty"`
	Version     string     `json:"version,omitempty" cbor:"11,keyasint,omitempty"`
	PackageUrl  string     `json:"purl,omitempty" cbor:"12,keyasint,omitempty"`
}

type BooleanMatch struct {
	Success  bool `json:"success" cbor:"0,keyasint"`
	Claimed  bool `json:"claimed" cbor:"1,keyasint"`
	Measured bool `json:"measured" cbor:"2,keyasint"`
}

//
// TPM-related definitions
//

type TpmResult struct {
	PcrMatch          []DigestResult `json:"pcrMatch" cbor:"0,keyasint"`
	AggPcrQuoteMatch  Result         `json:"aggPcrQuoteMatch" cbor:"1,keyasint"`
	PcrSelectionMatch Result         `json:"pcrSelectionMatch" cbor:"2,keyasint"`
}

//
// SNP-related definitions
//

type SnpResult struct {
	VersionMatch    Result       `json:"reportVersionMatch" cbor:"0,keyasint"`
	FwCheck         VersionCheck `json:"fwCheck" cbor:"1,keyasint"`
	TcbCheck        TcbCheck     `json:"tcbCheck" cbor:"2,keyasint"`
	PolicyCheck     PolicyCheck  `json:"policyCheck" cbor:"3,keyasint"`
	ExtensionsCheck []Result     `json:"extensionsCheck" cbor:"4,keyasint"`
	HostDataCheck   Result       `json:"hostDataCheck" cbor:"5,keyasint"`
}

type VersionCheck struct {
	Success  bool  `json:"success" cbor:"0,keyasint"`
	Claimed  []int `json:"claimed" cbor:"1,keyasint"`
	Measured []int `json:"measured" cbor:"2,keyasint"`
}

type TcbCheck struct {
	Summary Result       `json:"result" cbor:"0,keyasint"`
	Fmc     VersionCheck `json:"fmc" cbor:"5,keyasint"`
	Bl      VersionCheck `json:"bl" cbor:"1,keyasint"`
	Tee     VersionCheck `json:"tee" cbor:"2,keyasint"`
	Snp     VersionCheck `json:"snp" cbor:"3,keyasint"`
	Ucode   VersionCheck `json:"ucode" cbor:"4,keyasint"`
}

type PolicyCheck struct {
	Summary      Result       `json:"result" cbor:"0,keyasint"`
	Abi          VersionCheck `json:"abi" cbor:"1,keyasint"`
	Smt          BooleanMatch `json:"smt" cbor:"2,keyasint"`
	Migration    BooleanMatch `json:"migration" cbor:"3,keyasint"`
	Debug        BooleanMatch `json:"debug" cbor:"4,keyasint"`
	SingleSocket BooleanMatch `json:"singleSocket" cbor:"5,keyasint"`
}

//
// TDX / SGX-related definitions
//

type SgxResult struct {
	VersionMatch       Result             `json:"quoteVersionMatch" cbor:"0,keyasint"`
	TcbInfoCheck       TcbInfoResult      `json:"tcbInfoCheck" cbor:"1,keyasint"`
	QeReportCheck      QeReportResult     `json:"qeReportCheck" cbor:"2,keyasint"`
	SgxAttributesCheck SgxAttributesCheck `json:"sgxAttributesCheck" cbor:"3,keyasint"`
}

type TdxResult struct {
	VersionMatch        Result            `json:"quoteVersionMatch" cbor:"0,keyasint"`
	TcbInfoCheck        TcbInfoResult     `json:"tcbInfoCheck" cbor:"1,keyasint"`
	QeReportCheck       QeReportResult    `json:"qeReportCheck" cbor:"2,keyasint"`
	TdAttributesCheck   TdAttributesCheck `json:"tdAttributesCheck" cbor:"3,keyasint"`
	SeamAttributesCheck Result            `json:"seamAttributesCheck" cbor:"4,keyasint"`
	XfamCheck           Result            `json:"xfamCheck" cbor:"5,keyasint"`
	MrMatch             []DigestResult    `json:"mrMatch" cbor:"6,keyasint"`
}

type QeReportResult struct {
	Summary        Result `json:"summary" cbor:"0,keyasint"`
	MrSigner       Result `json:"mrsigner" cbor:"1,keyasint"`
	IsvProdId      Result `json:"isvProdId" cbor:"2,keyasint"`
	CpuSvn         Result `json:"cpuSvn" cbor:"3,keyasint"`
	IsvSvn         Result `json:"isvSvn" cbor:"4,keyasint"`
	MiscSelect     Result `json:"miscSelect" cbor:"5,keyasint"`
	Attributes     Result `json:"attributes" cbor:"6,keyasint"`
	TcbLevelStatus string `json:"status" cbor:"7,keyasint"`
	TcbLevelDate   string `json:"date" cbor:"8,keyasint"`
}

type TcbInfoResult struct {
	Summary  Result         `json:"summary" cbor:"0,keyasint"`
	Id       Result         `json:"id" cbor:"1,keyasint"`
	Version  Result         `json:"version" cbor:"2,keyasint"`
	TcbLevel TcbLevelResult `json:"tcbLevelResult" cbor:"3,keyasint"`
}

type TcbLevelResult struct {
	Status        string   `json:"status" cbor:"5,keyasint"`
	Date          string   `json:"date" cbor:"6,keyasint"`
	PceSvn        Result   `json:"pceSvn" cbor:"7,keyasint"`
	SgxComponents []Result `json:"sgxComponents" cbor:"8,keyasint"`
	TdxComponents []Result `json:"tdxComponents" cbor:"9,keyasint"`
}

type SgxAttributesCheck struct {
	Initted      BooleanMatch `json:"initted" cbor:"0,keyasint"`
	Debug        BooleanMatch `json:"debug" cbor:"1,keyasint"`
	Mode64Bit    BooleanMatch `json:"mode64Bit" cbor:"2,keyasint"`
	ProvisionKey BooleanMatch `json:"provisionKey" cbor:"3,keyasint"`
	EInitToken   BooleanMatch `json:"eInitToken" cbor:"4,keyasint"`
	Kss          BooleanMatch `json:"kss" cbor:"5,keyasint"`
	Legacy       BooleanMatch `json:"legacy" cbor:"6,keyasint"`
	Avx          BooleanMatch `json:"avx" cbor:"7,keyasint"`
}

type TdAttributesCheck struct {
	Debug         BooleanMatch `json:"debug" cbor:"0,keyasint"`
	SeptVEDisable BooleanMatch `json:"septVEDisable" cbor:"1,keyasint"`
	Pks           BooleanMatch `json:"pks" cbor:"2,keyasint"`
	Kl            BooleanMatch `json:"kl" cbor:"3,keyasint"`
}

//
// X509-related definitions
//

// SignatureResult shows the result of the signature check, the certificate chain check
// and includes all certificates present in the metadata item. If the certificate chain
// check was successful, Certs is always a valid chain. If not, certs contains the
// collected certificates present in the metadata item
type SignatureResult struct {
	SignCheck      Result                `json:"signatureVerification" cbor:"0,keyasint"`
	CertChainCheck Result                `json:"certChainValidation" cbor:"1,keyasint"`
	Certs          [][]X509CertExtracted `json:"certs,omitempty" cbor:"2,keyasint,omitempty"`
}

// X509CertExtracted represents a x509 certificate with attributes
// in a human-readable way and prepared for (un)marshaling JSON objects.
// It is based on the type Certificate from the crypto/x509 package.
type X509CertExtracted struct {
	Version            int      `json:"version" cbor:"0,keyasint"`
	SerialNumber       string   `json:"serialNumber" cbor:"1,keyasint"`
	Issuer             X509Name `json:"issuer" cbor:"2,keyasint"`
	Subject            X509Name `json:"subject" cbor:"3,keyasint"`
	Validity           Validity `json:"validity" cbor:"4,keyasint"`
	KeyUsage           []string `json:"keyUsage" cbor:"5,keyasint"`
	SignatureAlgorithm string   `json:"signatureAlgorithm" cbor:"6,keyasint"`
	PublicKeyAlgorithm string   `json:"publicKeyAlgorithm" cbor:"7,keyasint"`
	PublicKey          string   `json:"publicKey" cbor:"8,keyasint"`

	// Extensions contains raw X.509 extensions extracted during parsing.
	Extensions []PkixExtension `json:"pkixExtensions" cbor:"9,keyasint"`

	ExtKeyUsage        []string `json:"extKeyUsage,omitempty" cbor:"10,keyasint,omitempty"`
	UnknownExtKeyUsage []string `json:"unknownExtKeyUsage,omitempty" cbor:"11,keyasint,omitempty"`

	BasicConstraintsValid bool `json:"basicConstraintsValid" cbor:"12,keyasint"`
	IsCA                  bool `json:"isCA,omitempty" cbor:"13,keyasint,omitempty"`

	// MaxPathLen and MaxPathLenZero indicate the presence and
	// value of the BasicConstraints' "pathLenConstraint".
	//
	// A positive non-zero MaxPathLen means that the field was specified,
	// -1 means it was unset, and MaxPathLenZero being true means that the field was
	// explicitly set to zero. The case of MaxPathLen==0 with MaxPathLenZero==false
	// should be treated equivalent to -1 (unset).
	MaxPathLen int `json:"maxPathLen,omitempty" cbor:"14,keyasint,omitempty"`
	// MaxPathLenZero indicates that BasicConstraintsValid==true
	// and MaxPathLen==0 should be interpreted as an actual
	// maximum path length of zero. Otherwise, that combination is
	// interpreted as MaxPathLen not being set.
	MaxPathLenZero bool `json:"maxPathLenZero,omitempty" cbor:"15,keyasint,omitempty"`

	SubjectKeyId   HexByte `json:"subjectKeyId"`
	AuthorityKeyId HexByte `json:"authorityKeyId,omitempty" cbor:"16,keyasint,omitempty"`

	// Subject Alternate Name values.
	DNSNames       []string `json:"dnsNames,omitempty" cbor:"17,keyasint,omitempty"`
	EmailAddresses []string `json:"emailAddresses,omitempty" cbor:"18,keyasint,omitempty"`
	IPAddresses    []string `json:"ipAddresses,omitempty" cbor:"19,keyasint,omitempty"`
	URIs           []string `json:"uris,omitempty" cbor:"20,keyasint,omitempty"`
}

// X509Name represents an X.509 distinguished name. This only includes the common
// elements of a DN. Note that the structure is not a complete representation of
// the X.509 structure.
type X509Name struct {
	Country            []string `json:"country,omitempty" cbor:"0,keyasint,omitempty"`
	Organization       []string `json:"organization,omitempty" cbor:"1,keyasint,omitempty"`
	OrganizationalUnit []string `json:"organizationalUnit,omitempty" cbor:"2,keyasint,omitempty"`
	Locality           []string `json:"locality,omitempty" cbor:"3,keyasint,omitempty"`
	Province           []string `json:"province,omitempty" cbor:"4,keyasint,omitempty"`
	StreetAddress      []string `json:"streetAddress,omitempty" cbor:"5,keyasint,omitempty"`
	PostalCode         []string `json:"postalCode,omitempty" cbor:"6,keyasint,omitempty"`
	SerialNumber       string   `json:"serialNumber,omitempty" cbor:"7,keyasint,omitempty"`
	CommonName         string   `json:"commonName,omitempty" cbor:"8,keyasint,omitempty"`
}

// PkixExtension represents extensions of a x509 certificate.
type PkixExtension struct {
	Id       string `json:"id" cbor:"0,keyasint"`
	Critical bool   `json:"critical" cbor:"1,keyasint"`
	Value    []byte `json:"value" cbor:"2,keyasint"`
}

//
// End validation report definitions
//

// keyUsageName is used for translating the internal representation of allowed
// key usage in an x509 certificate to a string array.
var keyUsageName = [...]string{
	x509.KeyUsageDigitalSignature:  "Digital Signature",
	x509.KeyUsageContentCommitment: "Content Commitment",
	x509.KeyUsageKeyEncipherment:   "Key Encipherment",
	x509.KeyUsageDataEncipherment:  "Data Encipherment",
	x509.KeyUsageKeyAgreement:      "Key Agreement",
	x509.KeyUsageCertSign:          "Cert Sign",
	x509.KeyUsageCRLSign:           "CRL Sign",
	x509.KeyUsageEncipherOnly:      "Encipher Only",
	x509.KeyUsageDecipherOnly:      "Decipher Only",
}

// KeyUsageToString translates the internal representation of allowed key usage
// in an x509 certificate to a string array.
func KeyUsageToString(usage x509.KeyUsage) []string {
	res := []string{}
	for i := 0; i < len(keyUsageName); i++ {
		if ((1 << i) & usage) != 0 {
			res = append(res, keyUsageName[1<<i])
		}
	}
	return res
}

// extkeyUsageName is used for translating the internal representation of allowed
// extended key usage in an x509 certificate to a string array.
var extkeyUsageName = [...]string{
	x509.ExtKeyUsageAny:                            "Any",
	x509.ExtKeyUsageServerAuth:                     "Server Auth",
	x509.ExtKeyUsageClientAuth:                     "Client Auth",
	x509.ExtKeyUsageCodeSigning:                    "Code Signing",
	x509.ExtKeyUsageEmailProtection:                "Email Protection",
	x509.ExtKeyUsageIPSECEndSystem:                 "IPsec Endsystem",
	x509.ExtKeyUsageIPSECTunnel:                    "IPsec Tunnel",
	x509.ExtKeyUsageIPSECUser:                      "IPsec User",
	x509.ExtKeyUsageTimeStamping:                   "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSP Signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "Microsoft Server Gated Crypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "Netscape Server Gated Crypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft Commercial Code Signing",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "Microsoft Kernel Code Signing",
}

// ExtKeyUsageToString translates the internal representation of allowed extended
// key usage in an x509 certificate to a string array.
func ExtKeyUsageToString(usage []x509.ExtKeyUsage) []string {
	res := []string{}
	for i := 0; i < len(usage); i++ {
		res = append(res, extkeyUsageName[usage[i]])
	}
	return res
}

// ExtractX509Infos extracts relevant attributes from cert and transform some attribute
// into a more human-readable form by translating enums to a string representations.
// Returns an empty X509CertExtracted if cert is nil.
func ExtractX509Infos(cert *x509.Certificate) X509CertExtracted {
	certExtracted := X509CertExtracted{}

	if cert == nil {
		log.Warnf("Cannot extract infos from nil certificate")
		return certExtracted
	}

	certExtracted.Version = cert.Version
	certExtracted.SerialNumber = cert.SerialNumber.Text(16)

	certExtracted.Issuer = X509Name{
		Country:            cert.Issuer.Country,
		Organization:       cert.Issuer.Organization,
		OrganizationalUnit: cert.Issuer.OrganizationalUnit,
		Locality:           cert.Issuer.Locality,
		Province:           cert.Issuer.Province,
		StreetAddress:      cert.Issuer.StreetAddress,
		PostalCode:         cert.Issuer.PostalCode,
		SerialNumber:       cert.Issuer.SerialNumber,
		CommonName:         cert.Issuer.CommonName,
	}

	certExtracted.Subject = X509Name{
		Country:            cert.Subject.Country,
		Organization:       cert.Subject.Organization,
		OrganizationalUnit: cert.Subject.OrganizationalUnit,
		Locality:           cert.Subject.Locality,
		Province:           cert.Subject.Province,
		StreetAddress:      cert.Subject.StreetAddress,
		PostalCode:         cert.Subject.PostalCode,
		SerialNumber:       cert.Subject.SerialNumber,
		CommonName:         cert.Subject.CommonName,
	}

	certExtracted.Validity = Validity{
		NotBefore: cert.NotBefore.String(),
		NotAfter:  cert.NotAfter.String(),
	}

	certExtracted.KeyUsage = KeyUsageToString(cert.KeyUsage)
	certExtracted.SignatureAlgorithm = cert.SignatureAlgorithm.String()
	certExtracted.PublicKeyAlgorithm = cert.PublicKeyAlgorithm.String()

	pk, err := internal.WritePublicKeyPem(cert.PublicKey)
	if err != nil {
		log.Warnf("failed to marshal PKIX public key")
	} else {
		certExtracted.PublicKey = string(pk)
	}

	for _, ext := range cert.Extensions {
		ext_extracted := PkixExtension{
			Id:       ext.Id.String(),
			Critical: ext.Critical,
			Value:    ext.Value,
		}
		certExtracted.Extensions = append(certExtracted.Extensions, ext_extracted)
	}
	certExtracted.ExtKeyUsage = ExtKeyUsageToString(cert.ExtKeyUsage)

	for _, keyusage := range cert.UnknownExtKeyUsage {
		certExtracted.UnknownExtKeyUsage = append(certExtracted.UnknownExtKeyUsage, keyusage.String())
	}

	certExtracted.BasicConstraintsValid = cert.BasicConstraintsValid
	certExtracted.IsCA = cert.IsCA
	certExtracted.MaxPathLen = cert.MaxPathLen
	certExtracted.MaxPathLenZero = cert.MaxPathLenZero

	certExtracted.SubjectKeyId = cert.SubjectKeyId
	certExtracted.AuthorityKeyId = cert.AuthorityKeyId

	certExtracted.DNSNames = cert.DNSNames
	certExtracted.EmailAddresses = cert.EmailAddresses
	for _, uri := range cert.URIs {
		certExtracted.URIs = append(certExtracted.URIs, uri.String())
	}
	for _, ip := range cert.IPAddresses {
		certExtracted.IPAddresses = append(certExtracted.IPAddresses, ip.String())
	}

	return certExtracted
}

type ErrorCode int

const (
	// Values are part of the wire format. Only append new codes.
	NotSpecified                ErrorCode = 0
	CaFingerprint               ErrorCode = 1
	CRLCheckRoot                ErrorCode = 2
	CRLCheckPCK                 ErrorCode = 3
	CRLCheckSigningCert         ErrorCode = 4
	DecodeCertChain             ErrorCode = 5
	UnknownSerialization        ErrorCode = 6
	DownloadRootCRL             ErrorCode = 7
	DownloadPCKCRL              ErrorCode = 8
	EvidenceLength              ErrorCode = 9
	EvidenceMissing             ErrorCode = 10
	EvidenceType                ErrorCode = 11
	Expired                     ErrorCode = 12
	ExtractPubKey               ErrorCode = 13
	Internal                    ErrorCode = 14
	JWSNoSignatures             ErrorCode = 15
	JWSSignatureOrder           ErrorCode = 16
	JWSPayload                  ErrorCode = 17
	JWSNoKeyOrCert              ErrorCode = 18
	JWSUnknownVerifierType      ErrorCode = 19
	COSENoSignatures            ErrorCode = 20
	COSEUnknownVerifierType     ErrorCode = 21
	MeasurementNoMatch          ErrorCode = 22
	MeasurementTypeNotSupported ErrorCode = 23
	NotPresent                  ErrorCode = 24
	NotYetValid                 ErrorCode = 25
	OidLength                   ErrorCode = 26
	OidNotPresent               ErrorCode = 27
	OidTag                      ErrorCode = 28
	Parse                       ErrorCode = 29
	ParseAR                     ErrorCode = 30
	ParseX5C                    ErrorCode = 31
	ParseCA                     ErrorCode = 32
	ParseCAFingerprint          ErrorCode = 33
	ParseCert                   ErrorCode = 34
	ParseTcbInfo                ErrorCode = 35
	ParseJSON                   ErrorCode = 36
	ParseCBOR                   ErrorCode = 37
	ParseMetadata               ErrorCode = 38
	ParseEvidence               ErrorCode = 39
	ParseExtensions             ErrorCode = 40
	ParseQEIdentity             ErrorCode = 41
	ParseTime                   ErrorCode = 42
	PolicyEngineNotImplemented  ErrorCode = 43
	RefValTypeNotSupported      ErrorCode = 44
	SetupSystemCA               ErrorCode = 45
	SgxFmpcMismatch             ErrorCode = 46
	SgxPceidMismatch            ErrorCode = 47
	SignatureLength             ErrorCode = 48
	PolicyNotPresent            ErrorCode = 49
	RefValMultiple              ErrorCode = 50
	RefValAltUnsupported        ErrorCode = 51
	RefValAltGroup              ErrorCode = 52
	RefValNotPresent            ErrorCode = 53
	RefValType                  ErrorCode = 54
	RefValNoMatch               ErrorCode = 55
	TcbInfoExpired              ErrorCode = 56
	TcbLevelUnsupported         ErrorCode = 57
	TcbLevelRevoked             ErrorCode = 58
	UnsupportedAlgorithm        ErrorCode = 59
	VerifyAR                    ErrorCode = 60
	VerifyCertChain             ErrorCode = 61
	VerifyPCKChain              ErrorCode = 62
	VerifyMetadata              ErrorCode = 63
	VerifyPolicies              ErrorCode = 64
	VerifyQEIdentityErr         ErrorCode = 65
	VerifySignature             ErrorCode = 66
	VerifyTCBChain              ErrorCode = 67
	VerifyTcbInfo               ErrorCode = 68
	VerifyMeasurement           ErrorCode = 69
	ExtensionsCheck             ErrorCode = 70
	PcrNotSpecified             ErrorCode = 71
	ImageDescriptionNotPresent  ErrorCode = 72
	UnknownMetadata             ErrorCode = 73
	InvalidVersion              ErrorCode = 74
	NoRootManifest              ErrorCode = 75
	MultipleRootManifests       ErrorCode = 76
	VerifyEvidence              ErrorCode = 77
	VerifyAggregatedSwHash      ErrorCode = 78
	CollateralNotPresent        ErrorCode = 79
	ParseCollateral             ErrorCode = 80
	IllegalTdxMrIndex           ErrorCode = 81
	ParseKey                    ErrorCode = 82
	ExtractPayload              ErrorCode = 83
	TdxVerification             ErrorCode = 84
	Freshness                   ErrorCode = 85
	UnsupportedContextHashAlg   ErrorCode = 86
	CalculateContextHash        ErrorCode = 87
	ManifestRevoked             ErrorCode = 88
	ManifestRevocationUnknown   ErrorCode = 89
	ManifestOutdated            ErrorCode = 90
	PeerNotAuthorized           ErrorCode = 91
	LocalRoleUnknown            ErrorCode = 92
	PcrSelectionNoMatch         ErrorCode = 93
	AkExtKeyUsageMissing        ErrorCode = 94
	MultipleImageDescriptions   ErrorCode = 95
	MultipleCompanyDescriptions ErrorCode = 96
	MultipleOmspResponses       ErrorCode = 97
)

func (e ErrorCode) String() string {
	switch e {
	case NotSpecified:
		return fmt.Sprintf("%v (Error code not set)", int(e))
	case CaFingerprint:
		return fmt.Sprintf("%v (CA fingerprint error)", int(e))
	case CRLCheckRoot:
		return fmt.Sprintf("%v (CRL check root error)", int(e))
	case CRLCheckPCK:
		return fmt.Sprintf("%v (CRL check PCK error)", int(e))
	case CRLCheckSigningCert:
		return fmt.Sprintf("%v (CRL check signing certificate error)", int(e))
	case DecodeCertChain:
		return fmt.Sprintf("%v (Decode certificate chain error)", int(e))
	case UnknownSerialization:
		return fmt.Sprintf("%v (Unknown serialization error)", int(e))
	case DownloadRootCRL:
		return fmt.Sprintf("%v (Download root CRL error)", int(e))
	case DownloadPCKCRL:
		return fmt.Sprintf("%v (Download PCK CRL error)", int(e))
	case EvidenceLength:
		return fmt.Sprintf("%v (Evidence length error)", int(e))
	case EvidenceMissing:
		return fmt.Sprintf("%v (Evidence missing error)", int(e))
	case EvidenceType:
		return fmt.Sprintf("%v (Evidence type error)", int(e))
	case Expired:
		return fmt.Sprintf("%v (Validity expired error)", int(e))
	case ExtractPubKey:
		return fmt.Sprintf("%v (Extract public key error)", int(e))
	case Internal:
		return fmt.Sprintf("%v (Internal error)", int(e))
	case JWSNoSignatures:
		return fmt.Sprintf("%v (JWS no signatures error)", int(e))
	case JWSSignatureOrder:
		return fmt.Sprintf("%v (JWS signature order error)", int(e))
	case JWSPayload:
		return fmt.Sprintf("%v (JWS payload error)", int(e))
	case JWSNoKeyOrCert:
		return fmt.Sprintf("%v (JWS No key or cert provided)", int(e))
	case JWSUnknownVerifierType:
		return fmt.Sprintf("%v (JWS Unknown verifier type)", int(e))
	case COSENoSignatures:
		return fmt.Sprintf("%v (COSE no signatures error)", int(e))
	case COSEUnknownVerifierType:
		return fmt.Sprintf("%v (COSE Unknown verifier type)", int(e))
	case MeasurementNoMatch:
		return fmt.Sprintf("%v (Measurement no match error)", int(e))
	case MeasurementTypeNotSupported:
		return fmt.Sprintf("%v (Measurement type not supported error)", int(e))
	case NotPresent:
		return fmt.Sprintf("%v (Not present error)", int(e))
	case NotYetValid:
		return fmt.Sprintf("%v (Not yet valid error)", int(e))
	case OidLength:
		return fmt.Sprintf("%v (OID length error)", int(e))
	case OidNotPresent:
		return fmt.Sprintf("%v (OID not present error)", int(e))
	case OidTag:
		return fmt.Sprintf("%v (OID tag error)", int(e))
	case Parse:
		return fmt.Sprintf("%v (Parse error)", int(e))
	case ParseAR:
		return fmt.Sprintf("%v (Parse AR error)", int(e))
	case ParseX5C:
		return fmt.Sprintf("%v (Parse X5C error)", int(e))
	case ParseCA:
		return fmt.Sprintf("%v (Parse CA error)", int(e))
	case ParseCAFingerprint:
		return fmt.Sprintf("%v (Parse CA fingerprint error)", int(e))
	case ParseCert:
		return fmt.Sprintf("%v (Parse certificate error)", int(e))
	case ParseTcbInfo:
		return fmt.Sprintf("%v (Parse TCB info error)", int(e))
	case ParseJSON:
		return fmt.Sprintf("%v (Parse JSON error)", int(e))
	case ParseCBOR:
		return fmt.Sprintf("%v (Parse CBOR error)", int(e))
	case ParseEvidence:
		return fmt.Sprintf("%v (Parse evidence error)", int(e))
	case ParseExtensions:
		return fmt.Sprintf("%v (Parse extensions error)", int(e))
	case ParseQEIdentity:
		return fmt.Sprintf("%v (Parse QE identity error)", int(e))
	case ParseMetadata:
		return fmt.Sprintf("%v (Parse metadata error)", int(e))
	case ParseTime:
		return fmt.Sprintf("%v (Parse time error)", int(e))
	case PolicyEngineNotImplemented:
		return fmt.Sprintf("%v (Policy engine not implemented error)", int(e))
	case RefValTypeNotSupported:
		return fmt.Sprintf("%v (Reference value type not supported error)", int(e))
	case SetupSystemCA:
		return fmt.Sprintf("%v (Setup system CA error)", int(e))
	case SgxFmpcMismatch:
		return fmt.Sprintf("%v (SGX FMPC mismatch error)", int(e))
	case SgxPceidMismatch:
		return fmt.Sprintf("%v (SGX PCEID mismatch error)", int(e))
	case SignatureLength:
		return fmt.Sprintf("%v (Signature length error)", int(e))
	case PolicyNotPresent:
		return fmt.Sprintf("%v (Policy not present error)", int(e))
	case RefValMultiple:
		return fmt.Sprintf("%v (Reference value multiple error)", int(e))
	case RefValAltUnsupported:
		return fmt.Sprintf("%v (Reference value alternatives unsupported error)", int(e))
	case RefValAltGroup:
		return fmt.Sprintf("%v (Reference value alternative group error)", int(e))
	case RefValNotPresent:
		return fmt.Sprintf("%v (Reference value not present error)", int(e))
	case RefValType:
		return fmt.Sprintf("%v (Reference value type error)", int(e))
	case RefValNoMatch:
		return fmt.Sprintf("%v (Reference value no match error)", int(e))
	case TcbInfoExpired:
		return fmt.Sprintf("%v (TCB info expired error)", int(e))
	case TcbLevelUnsupported:
		return fmt.Sprintf("%v (TCB level unsupported error)", int(e))
	case TcbLevelRevoked:
		return fmt.Sprintf("%v (TCB level revoked error)", int(e))
	case UnsupportedAlgorithm:
		return fmt.Sprintf("%v (Unsupported algorithm error)", int(e))
	case VerifyAR:
		return fmt.Sprintf("%v (Verify AR error)", int(e))
	case VerifyCertChain:
		return fmt.Sprintf("%v (Verify certificate chain error)", int(e))
	case VerifyPCKChain:
		return fmt.Sprintf("%v (Verify PCK chain error)", int(e))
	case VerifyMetadata:
		return fmt.Sprintf("%v (Verify metadata error)", int(e))
	case VerifyPolicies:
		return fmt.Sprintf("%v (Verify policies error)", int(e))
	case VerifyQEIdentityErr:
		return fmt.Sprintf("%v (Verify QE identity error)", int(e))
	case VerifySignature:
		return fmt.Sprintf("%v (Verify signature error)", int(e))
	case VerifyTCBChain:
		return fmt.Sprintf("%v (Verify TCB chain error)", int(e))
	case VerifyTcbInfo:
		return fmt.Sprintf("%v (Verify TCB info error)", int(e))
	case VerifyMeasurement:
		return fmt.Sprintf("%v (Verify measurement)", int(e))
	case ExtensionsCheck:
		return fmt.Sprintf("%v (Extensions check error)", int(e))
	case PcrNotSpecified:
		return fmt.Sprintf("%v (PCR not specified error)", int(e))
	case ImageDescriptionNotPresent:
		return fmt.Sprintf("%v (Image description not present error)", int(e))
	case UnknownMetadata:
		return fmt.Sprintf("%v (Unknown metadata error)", int(e))
	case InvalidVersion:
		return fmt.Sprintf("%v (Invalid attestation report version)", int(e))
	case NoRootManifest:
		return fmt.Sprintf("%v (No root manifest)", int(e))
	case MultipleRootManifests:
		return fmt.Sprintf("%v (Multiple root manifests)", int(e))
	case VerifyEvidence:
		return fmt.Sprintf("%v (Verify Evidence)", int(e))
	case VerifyAggregatedSwHash:
		return fmt.Sprintf("%v (Verify aggregated SW hash)", int(e))
	case CollateralNotPresent:
		return fmt.Sprintf("%v (Collateral not present)", int(e))
	case ParseCollateral:
		return fmt.Sprintf("%v (Parse Collateral)", int(e))
	case IllegalTdxMrIndex:
		return fmt.Sprintf("%v (Illegal Intel TDX measurement register index)", int(e))
	case ParseKey:
		return fmt.Sprintf("%v (Parse key)", int(e))
	case ExtractPayload:
		return fmt.Sprintf("%v (Extract Payload)", int(e))
	case TdxVerification:
		return fmt.Sprintf("%v (TDX Verification)", int(e))
	case Freshness:
		return fmt.Sprintf("%v (Freshness)", int(e))
	case UnsupportedContextHashAlg:
		return fmt.Sprintf("%v (Unsupported context hash algorithm)", int(e))
	case CalculateContextHash:
		return fmt.Sprintf("%v (Calculate context hash)", int(e))
	case ManifestRevoked:
		return fmt.Sprintf("%v (Manifest revoked)", int(e))
	case ManifestRevocationUnknown:
		return fmt.Sprintf("%v (No revocation information for manifest available)", int(e))
	case ManifestOutdated:
		return fmt.Sprintf("%v (Manifest outdated)", int(e))
	case PeerNotAuthorized:
		return fmt.Sprintf("%v (Peer not authorized by local role)", int(e))
	case LocalRoleUnknown:
		return fmt.Sprintf("%v (Local role unknown, peer authorization skipped)", int(e))
	case PcrSelectionNoMatch:
		return fmt.Sprintf("%v (Measured PCRs do not match quoted PCR selection)", int(e))
	case AkExtKeyUsageMissing:
		return fmt.Sprintf("%v (AK certificate lacks extended key usage tcg-kp-AIKCertificate)", int(e))
	case MultipleImageDescriptions:
		return fmt.Sprintf("%v (Multiple image descriptions)", int(e))
	case MultipleCompanyDescriptions:
		return fmt.Sprintf("%v (Multiple company descriptions)", int(e))
	case MultipleOmspResponses:
		return fmt.Sprintf("%v (Multiple OMSP responses for the same server)", int(e))
	default:
		return fmt.Sprintf("Unknown error code: %v", int(e))
	}
}

func (r *Result) Fail(code ErrorCode, errs ...error) {
	r.Status = StatusFail
	r.record("Verification failed", code, errs)
}

func (r *Result) Warn(code ErrorCode, errs ...error) {
	r.Status = r.Status.Worse(StatusWarn)
	r.record("Verification passed with warning", code, errs)
}

// record appends the error code and all error messages to the result and logs them
func (r *Result) record(prefix string, code ErrorCode, errs []error) {
	if code != NotSpecified {
		r.ErrorCodes = append(r.ErrorCodes, code)
		prefix = fmt.Sprintf("%v with error code %v", prefix, code.String())
	}
	var msgs []string
	for _, err := range errs {
		if err != nil {
			msgs = append(msgs, err.Error())
		}
	}
	if len(msgs) == 0 {
		log.Warn(prefix)
		return
	}
	msg := strings.Join(msgs, "; ")
	r.appendDetails(msg)
	log.Warnf("%v: %v", prefix, msg)
}

func (r *Result) appendDetails(msg string) {
	if r.Details == "" {
		r.Details = msg
	} else {
		r.Details += "; " + msg
	}
}

func StatusFromBool(ok bool) Status {
	if ok {
		return StatusSuccess
	} else {
		return StatusFail
	}
}

func DigestTypeFromBool(matched bool, unmatched string) string {
	if matched {
		return TYPE_DIGEST_VERIFIED
	}
	return unmatched
}

func (r *AttestationResult) Fail(code ErrorCode, errs ...error) {
	r.Summary.Fail(code, errs...)
}

func (r *AttestationResult) Warn(code ErrorCode, errs ...error) {
	r.Summary.Warn(code, errs...)
}

func (r *Result) PrintErr(format string, args ...interface{}) {
	if r == nil {
		log.Warnf("%v is nil", fmt.Sprintf(format, args...))
		return
	}
	if r.Status == StatusSuccess {
		return
	}
	if len(r.ErrorCodes) == 0 || len(r.ErrorCodes) == 1 && r.ErrorCodes[0] == NotSpecified {
		log.Warnf("%v failed", fmt.Sprintf(format, args...))
	} else {
		log.Warnf("%v failed with error codes:", fmt.Sprintf(format, args...))
		for _, code := range r.ErrorCodes {
			log.Warnf("    %v", code.String())
		}
	}
	if r.Details != "" {
		log.Warnf("    Details: %v", r.Details)
	}

	if r.Expected != "" {
		log.Warnf("\tExpected: %v", r.Expected)
		log.Warnf("\tGot     : %v", r.Got)
	}
	if len(r.ExpectedBetween) == 2 {
		log.Warnf("\tExpected: %v - %v", r.ExpectedBetween[0], r.ExpectedBetween[1])
		log.Warnf("\tGot     : %v", r.Got)
	}
	if len(r.ExpectedOneOf) > 0 {
		log.Warnf("\tExpected: %v", strings.Join(r.ExpectedOneOf, ","))
		log.Warnf("\tGot     : %v", r.Got)
	}
}

func (r *SignatureResult) PrintErr(format string, args ...interface{}) {
	r.SignCheck.PrintErr("%v signature check", fmt.Sprintf(format, args...))
	r.CertChainCheck.PrintErr("%v cert chain check", fmt.Sprintf(format, args...))
}

func (v *VersionCheck) PrintErr(format string, args ...interface{}) {
	if v.Success {
		return
	}
	log.Warnf("%v failed: claimed %v, measured %v",
		fmt.Sprintf(format, args...), v.Claimed, v.Measured)
}

func (b *BooleanMatch) PrintErr(format string, args ...interface{}) {
	if b.Success {
		return
	}
	log.Warnf("%v failed: claimed %v, measured %v",
		fmt.Sprintf(format, args...), b.Claimed, b.Measured)
}

func (r *TcbCheck) PrintErr(format string, args ...interface{}) {
	if r.Summary.Status == StatusSuccess {
		return
	}
	r.Summary.PrintErr(format, args...)
	prefix := fmt.Sprintf(format, args...)
	r.Fmc.PrintErr("%v FMC SPL", prefix)
	r.Bl.PrintErr("%v BL SPL", prefix)
	r.Tee.PrintErr("%v TEE SPL", prefix)
	r.Snp.PrintErr("%v SNP SPL", prefix)
	r.Ucode.PrintErr("%v uCode SPL", prefix)
}

func (r *PolicyCheck) PrintErr(format string, args ...interface{}) {
	if r.Summary.Status == StatusSuccess {
		return
	}
	r.Summary.PrintErr(format, args...)
	prefix := fmt.Sprintf(format, args...)
	r.Abi.PrintErr("%v ABI", prefix)
	r.Smt.PrintErr("%v SMT", prefix)
	r.Migration.PrintErr("%v migration", prefix)
	r.Debug.PrintErr("%v debug", prefix)
	r.SingleSocket.PrintErr("%v single socket", prefix)
}

func (r *TcbLevelResult) PrintErr(format string, args ...interface{}) {
	prefix := fmt.Sprintf(format, args...)
	r.PceSvn.PrintErr("%v PCE SVN", prefix)
	for i := range r.SgxComponents {
		r.SgxComponents[i].PrintErr("%v SGX component %v", prefix, i)
	}
	for i := range r.TdxComponents {
		r.TdxComponents[i].PrintErr("%v TDX component %v", prefix, i)
	}
}

func (r *TcbInfoResult) PrintErr(format string, args ...interface{}) {
	if r.Summary.Status == StatusSuccess {
		return
	}
	r.Summary.PrintErr(format, args...)
	prefix := fmt.Sprintf(format, args...)
	r.Id.PrintErr("%v ID", prefix)
	r.Version.PrintErr("%v version", prefix)
	r.TcbLevel.PrintErr("%v TCB level", prefix)
}

func (r *QeReportResult) PrintErr(format string, args ...interface{}) {
	if r.Summary.Status == StatusSuccess {
		return
	}
	r.Summary.PrintErr(format, args...)
	prefix := fmt.Sprintf(format, args...)
	r.MrSigner.PrintErr("%v MRSIGNER", prefix)
	r.IsvProdId.PrintErr("%v ISV ProdID", prefix)
	r.CpuSvn.PrintErr("%v CPU SVN", prefix)
	r.IsvSvn.PrintErr("%v ISV SVN", prefix)
	r.MiscSelect.PrintErr("%v MiscSelect", prefix)
	r.Attributes.PrintErr("%v attributes", prefix)
	if r.TcbLevelStatus != "" {
		log.Warnf("%v TCB level status: %v (%v)", prefix, r.TcbLevelStatus, r.TcbLevelDate)
	}
}

func (r *SgxAttributesCheck) PrintErr(format string, args ...interface{}) {
	prefix := fmt.Sprintf(format, args...)
	r.Initted.PrintErr("%v initted", prefix)
	r.Debug.PrintErr("%v debug", prefix)
	r.Mode64Bit.PrintErr("%v mode64bit", prefix)
	r.ProvisionKey.PrintErr("%v provision key", prefix)
	r.EInitToken.PrintErr("%v einit token", prefix)
	r.Kss.PrintErr("%v KSS", prefix)
	r.Legacy.PrintErr("%v legacy", prefix)
	r.Avx.PrintErr("%v AVX", prefix)
}

func (r *TdAttributesCheck) PrintErr(format string, args ...interface{}) {
	prefix := fmt.Sprintf(format, args...)
	r.Debug.PrintErr("%v debug", prefix)
	r.SeptVEDisable.PrintErr("%v SEPT VE disable", prefix)
	r.Pks.PrintErr("%v PKS", prefix)
	r.Kl.PrintErr("%v KL", prefix)
}

// NvidiaResult represents the results of the verification of an NVIDIA GPU
// attestation report. A check which was never reached, because an earlier one
// failed, carries the zero status rather than a failure of its own
type NvidiaResult struct {
	MeasurementSignatureCheck Result `json:"signatureCheck" cbor:"0,keyasint"`
	MeasurementRIMCheck       Result `json:"measurementCheck" cbor:"1,keyasint"`
	RIMSignatureCheck         Result `json:"rimSignatureCheck" cbor:"2,keyasint"`
	RIMRecencyCheck           Result `json:"rimRecencyCheck" cbor:"3,keyasint"`
	DeviceRecencyCheck        Result `json:"deviceRecencyCheck" cbor:"4,keyasint"`
	PolicyCheck               Result `json:"policyCheck" cbor:"5,keyasint"`
}

func (r *NvidiaResult) PrintErr() {
	r.MeasurementSignatureCheck.PrintErr("NVIDIA attestation report signature check")
	r.MeasurementRIMCheck.PrintErr("NVIDIA measurement check against RIM reference values")
	r.RIMSignatureCheck.PrintErr("NVIDIA RIM signature check")
	r.RIMRecencyCheck.PrintErr("NVIDIA RIM recency (OCSP) check")
	r.DeviceRecencyCheck.PrintErr("NVIDIA device certificate recency (OCSP) check")
	r.PolicyCheck.PrintErr("NVIDIA policy check")
}

func (r *SnpResult) PrintErr() {
	r.VersionMatch.PrintErr("SNP report version match")
	r.FwCheck.PrintErr("SNP firmware version")
	r.TcbCheck.PrintErr("SNP TCB check")
	r.PolicyCheck.PrintErr("SNP guest policy check")
	for i := range r.ExtensionsCheck {
		r.ExtensionsCheck[i].PrintErr("SNP VCEK extension %v", i)
	}
	r.HostDataCheck.PrintErr("SNP host data check")
}

func (r *SgxResult) PrintErr() {
	r.VersionMatch.PrintErr("SGX quote version match")
	r.TcbInfoCheck.PrintErr("SGX TCB info check")
	r.QeReportCheck.PrintErr("SGX QE report check")
	r.SgxAttributesCheck.PrintErr("SGX attribute")
}

func (r *TdxResult) PrintErr() {
	r.VersionMatch.PrintErr("TDX quote version match")
	r.TcbInfoCheck.PrintErr("TDX TCB info check")
	r.QeReportCheck.PrintErr("TDX QE report check")
	r.TdAttributesCheck.PrintErr("TDX TD attribute")
	r.SeamAttributesCheck.PrintErr("TDX SEAM attributes check")
	r.XfamCheck.PrintErr("TDX XFAM check")
	for _, m := range r.MrMatch {
		if !m.Success {
			log.Warnf("%v %q failed: calculated %x, measured %v",
				internal.IndexToMr(m.Index), m.Name, m.Digest, m.Measured)
		}
	}
}

func (r *AttestationResult) PrintErr() {

	if r.Summary.Status == StatusSuccess {
		return
	}

	if len(r.Summary.ErrorCodes) == 0 {
		log.Warn("Verification failed")
	} else {
		log.Warnf("Verification failed with error codes: %v", r.Summary.ErrorCodes)
	}

	for _, m := range r.Measurements {
		m.Summary.PrintErr("%v", m.Type)
		m.Freshness.PrintErr("Measurement freshness check")
		m.Signature.PrintErr("Measurement")
		for _, a := range m.Artifacts {
			if !a.Success {
				var header string
				switch m.Type {
				case TYPE_RESULT_TPM:
					header = fmt.Sprintf("PCR%v %v", a.Index, a.Type)
				case TYPE_RESULT_TDX:
					header = fmt.Sprintf("%v %v", internal.IndexToMr(a.Index), a.Type)
				case TYPE_RESULT_SNP:
					header = fmt.Sprintf("%v", a.Type)
				default:
					header = fmt.Sprintf("%v Measurement", m.Type)
				}
				log.Warnf("%v %q: %x verification failed", header, a.Name, a.Digest)
			}
		}
		if m.TpmResult != nil {
			m.TpmResult.PcrSelectionMatch.PrintErr("PCR selection verification")
			m.TpmResult.AggPcrQuoteMatch.PrintErr("Aggregated PCR verification")
			for _, p := range m.TpmResult.PcrMatch {
				if !p.Success {
					log.Warnf("PCR%v calculated: %x, measured: %v", p.Index, p.Digest,
						p.Measured)
				}
			}
		}
		if m.SnpResult != nil {
			m.SnpResult.PrintErr()
		}
		if m.NvidiaResult != nil {
			m.NvidiaResult.PrintErr()
		}
		if m.SgxResult != nil {
			m.SgxResult.PrintErr()
		}
		if m.TdxResult != nil {
			m.TdxResult.PrintErr()
		}
	}

	if r.Metadata.CompanyDescriptionResult != nil {
		r.Metadata.CompanyDescriptionResult.Summary.PrintErr("Company description check")
		for _, s := range r.Metadata.CompanyDescriptionResult.SignatureCheck {
			s.PrintErr(TYPE_COMPANY_DESCRIPTION)
		}
		r.Metadata.CompanyDescriptionResult.ValidityCheck.PrintErr("Company description validity check")
	}

	for _, mr := range r.Metadata.ManifestResults {
		mr.Summary.PrintErr("%v %v check", mr.Type, mr.Name)
		for _, s := range mr.SignatureCheck {
			s.PrintErr("%v", mr.Name)
		}
		mr.ValidityCheck.PrintErr("%v validity check", mr.Name)
	}

	r.Metadata.ImageDescriptionResult.Summary.PrintErr("Image Description check")
	for _, s := range r.Metadata.ImageDescriptionResult.SignatureCheck {
		s.PrintErr(TYPE_IMAGE_DESCRIPTION)
	}

	r.PeerAuth.PrintErr("Peer authorization check")

	r.Metadata.CompatibilityResult.Summary.PrintErr("Metadata compatibility check")
	for _, mr := range r.Metadata.CompatibilityResult.ManifestCompatibility {
		mr.PrintErr("Manifest compatibility check")
	}
	for _, dr := range r.Metadata.CompatibilityResult.DescriptionMatch {
		dr.PrintErr("Description -> Manifest match")
	}
	for _, dr := range r.Metadata.CompatibilityResult.ManifestMatch {
		dr.PrintErr("Manifest -> Description match")
	}

}
