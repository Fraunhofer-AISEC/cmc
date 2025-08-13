// Copyright (c) 2021 - 2025 Fraunhofer AISEC
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
	"errors"
	"fmt"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// VerificationResult represents the results of all steps taken during
// the validation of an attestation report.
type VerificationResult struct {
	Version         string              `json:"version" cbor:"0,keyasint"`
	Type            string              `json:"type" cbor:"1,keyasint"`
	Summary         Result              `json:"summary" cbor:"2,keyasint"`
	Prover          string              `json:"prover,omitempty" cbor:"4,keyasint,omitempty"`
	Created         string              `json:"created,omitempty" cbor:"5,keyasint,omitempty"`
	CertLevel       int                 `json:"certLevel" cbor:"6,keyasint"`
	Measurements    []MeasurementResult `json:"measurements" cbor:"7,keyasint"`
	Metadata        MetadataSummary     `json:"metadata" cbor:"8,keyasint"`
	ReportSignature []SignatureResult   `json:"reportSignatureCheck" cbor:"10,keyasint"`
}

type Status string

const (
	StatusSuccess Status = "success"
	StatusFail    Status = "fail"
	StatusWarn    Status = "warn"
)

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
	DevDescResult       MetadataResult      `json:"devDescResult" cbor:"0,keyasint"`
	ManifestResults     []MetadataResult    `json:"manifestResults" cbor:"1,keyasint"`
	CompDescResult      *MetadataResult     `json:"compDescResult,omitempty" cbor:"2,keyasint,omitempty"`
	UnknownResults      []MetadataResult    `json:"unknownResults" cbor:"3,keyasint"`
	CompatibilityResult CompatibilityResult `json:"compatibilityResult" cbor:"4,keyasint"`
}

type MetadataResult struct {
	Metadata
	Summary        Result            `json:"summary" cbor:"40,keyasint"`
	ValidityCheck  Result            `json:"validityCheck,omitempty" cbor:"41,keyasint,omitempty"`
	SignatureCheck []SignatureResult `json:"signatureValidation" cbor:"42,keyasint,omitempty"`
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
	Type      string          `json:"type" cbor:"0,keyasint"`
	Summary   Result          `json:"summary" cbor:"1,keyasint"`
	Freshness Result          `json:"freshness" cbor:"2,keyasint"`
	Signature SignatureResult `json:"signature" cbor:"3,keyasint"`
	Artifacts []DigestResult  `json:"artifacts" cbor:"4,keyasint"`
	TpmResult *TpmResult      `json:"tpmResult,omitempty" cbor:"5,keyasint,omitempty"`
	SnpResult *SnpResult      `json:"snpResult,omitempty" cbor:"6,keyasint,omitempty"`
	SgxResult *SgxResult      `json:"sgxResult,omitempty" cbor:"7,keyasint,omitempty"`
	TdxResult *TdxResult      `json:"tdxResult,omitempty" cbor:"8,keyasint,omitempty"`
}

// DigestResult represents a generic result for a digest that was processed
// during attestation. The Index is the unique identifier for the result: This is the number of the
// PCR in case of TPM reference values, the MR index according to UEFI Spec 2.10 Section 38.4.1 in
// case of TDX reference values, and simply a monotonic counter for other reference values.
type DigestResult struct {
	Success     bool       `json:"success" cbor:"0,keyasint"`
	Launched    bool       `json:"launched" cbor:"1,keyasint"`
	Type        string     `json:"type,omitempty" cbor:"2,keyasint,omitempty"`
	SubType     string     `json:"subtype,omitempty" cbor:"3,keyasint,omitempty"`
	Index       int        `json:"index" cbor:"4,keyasint"`
	Digest      string     `json:"digest,omitempty" cbor:"5,keyasint,omitempty"`
	Measured    string     `json:"measured,omitempty" cbor:"6,keyasint,omitempty"`
	Description string     `json:"description,omitempty" cbor:"7,keyasint,omitempty"`
	EventData   *EventData `json:"eventData,omitempty" cbor:"8,keyasint,omitempty"`
	CtrDetails  *CtrData   `json:"ctrDetails,omitempty" cbor:"9,keyasint,omitempty"`
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
	PcrMatch         []DigestResult `json:"pcrMatch" cbor:"0,keyasint"`
	AggPcrQuoteMatch Result         `json:"aggPcrQuoteMatch" cbor:"1,keyasint"`
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
}

type VersionCheck struct {
	Success  bool  `json:"success" cbor:"0,keyasint"`
	Claimed  []int `json:"claimed" cbor:"1,keyasint"`
	Measured []int `json:"measured" cbor:"2,keyasint"`
}

type TcbCheck struct {
	Summary Result       `json:"result" cbor:"0,keyasint"`
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
	MiscSelect     Result `json:"miscSelect" cbor:"3,keyasint"`
	Attributes     Result `json:"attributes" cbor:"4,keyasint"`
	TcbLevelStatus string `json:"status" cbor:"5,keyasint"`
	TcbLevelDate   string `json:"date" cbor:"6,keyasint"`
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
	Certs          [][]X509CertExtracted `json:"certs,omitempty" cbor:"2,keyasint"`
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
	IsCA                  bool `json:"isCA,omitempty" cbor:"13,keyasint"`

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
func ExtractX509Infos(cert *x509.Certificate) X509CertExtracted {
	certExtracted := X509CertExtracted{}

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
	NotSpecified ErrorCode = iota
	CaFingerprint
	CRLCheckRoot
	CRLCheckPCK
	CRLCheckSigningCert
	DecodeCertChain
	UnknownSerialization
	DownloadRootCRL
	DownloadPCKCRL
	EvidenceLength
	EvidenceType
	Expired
	ExtractPubKey
	Internal
	InvalidCertLevel
	JWSNoSignatures
	JWSSignatureOrder
	JWSPayload
	JWSNoKeyOrCert
	JWSUnknownVerifierType
	COSENoSignatures
	COSEUnknownVerifierType
	MeasurementNoMatch
	MeasurementTypeNotSupported
	NotPresent
	NotYetValid
	OidLength
	OidNotPresent
	OidTag
	Parse
	ParseAR
	ParseX5C
	ParseCA
	ParseCAFingerprint
	ParseCert
	ParseTcbInfo
	ParseJSON
	ParseCBOR
	ParseMetadata
	ParseEvidence
	ParseExtensions
	ParseQEIdentity
	ParseTime
	PolicyEngineNotImplemented
	RefValTypeNotSupported
	SetupSystemCA
	SgxFmpcMismatch
	SgxPceidMismatch
	SignatureLength
	PolicyNotPresent
	RefValMultiple
	RefValNotPresent
	RefValType
	RefValNoMatch
	TcbInfoExpired
	TcbLevelUnsupported
	TcbLevelRevoked
	UnsupportedAlgorithm
	VerifyAR
	VerifyCertChain
	VerifyPCKChain
	VerifyMetadata
	VerifyPolicies
	VerifyQEIdentityErr
	VerifySignature
	VerifyTCBChain
	VerifyTcbInfo
	VerifyMeasurement
	ExtensionsCheck
	PcrNotSpecified
	DeviceDescriptionNotPresent
	UnknownMetadata
	InvalidVersion
	NoRootManifest
	MultipleRootManifests
	VerifyEvidence
	VerifyAggregatedSwHash
	CollateralNotPresent
	ParseCollateral
	IllegalTdxMrIndex
	ParseKey
	ExtractPayload
	TdxVerification
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
	case EvidenceType:
		return fmt.Sprintf("%v (Evidence type error)", int(e))
	case Expired:
		return fmt.Sprintf("%v (Validity expired error)", int(e))
	case ExtractPubKey:
		return fmt.Sprintf("%v (Extract public key error)", int(e))
	case Internal:
		return fmt.Sprintf("%v (Internal error)", int(e))
	case InvalidCertLevel:
		return fmt.Sprintf("%v (Invalid certification level error)", int(e))
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
	case DeviceDescriptionNotPresent:
		return fmt.Sprintf("%v (Device description not present error)", int(e))
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
	default:
		return fmt.Sprintf("Unknown error code: %v", int(e))
	}
}

func (r *Result) Fail(code ErrorCode, errs ...error) {
	r.Status = StatusFail
	if code != NotSpecified {
		r.ErrorCodes = append(r.ErrorCodes, code)
	}
	if len(errs) > 0 {
		r.Details = fmt.Sprintf("%v", errors.Join(errs...))
		log.Debugf("Verification failed with error code %v: %v", code.String(), r.Details)
	} else if code != NotSpecified {
		log.Debugf("Verification failed with error code %v", code.String())
	} else {
		log.Debugf("Verification failed")
	}
}

func (r *Result) Warn(code ErrorCode, errs ...error) {
	// Make sure, an already failed result is not set to warn
	if r.Status != StatusFail {
		r.Status = StatusWarn
	}
	if code != NotSpecified {
		r.ErrorCodes = append(r.ErrorCodes, code)
	}
	if len(errs) > 0 {
		r.Details = fmt.Sprintf("%v", errors.Join(errs...))
		log.Debugf("Verification passed with warning %v: %v", code.String(), r.Details)
	} else if code != NotSpecified {
		log.Debugf("Verification passed with warning %v", code.String())
	} else {
		log.Debugf("Verification passed with warning")
	}
}

func StatusFromBool(ok bool) Status {
	if ok {
		return StatusSuccess
	} else {
		return StatusFail
	}
}

func (r *VerificationResult) Fail(code ErrorCode, errs ...error) {
	if len(errs) > 0 {
		for _, err := range errs {
			r.Summary.Fail(code, err)
		}
	} else {
		r.Summary.Fail(code)
	}
}

func (r *VerificationResult) Warn(code ErrorCode, errs ...error) {
	if len(errs) > 0 {
		for _, err := range errs {
			r.Summary.Warn(code, err)
		}
	} else {
		r.Summary.Warn(code)
	}
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

func (r *VerificationResult) PrintErr() {

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
				header := ""
				if m.Type == "TPM Measurement" {
					header = fmt.Sprintf("PCR%v ", a.Index)
				} else if m.Type == "TDX Measurement" {
					header = fmt.Sprintf("%v ", internal.IndexToMr(a.Index))
				}
				log.Warnf("%vMeasurement Type %v, Subtype: %v: %v verification failed",
					header, a.Type, a.SubType, a.Digest)
			}
		}
		if m.TpmResult != nil {
			m.TpmResult.AggPcrQuoteMatch.PrintErr("Aggregated PCR verification")
			for _, p := range m.TpmResult.PcrMatch {
				if !p.Success {
					log.Warnf("PCR%v calculated: %v, measured: %v", p.Index, p.Digest,
						p.Measured)
				}
			}
		}
		if m.SnpResult != nil {
			m.SnpResult.VersionMatch.PrintErr("Version match")
			// TODO
			log.Warnf("Detailed SNP evaluation not yet implemented")
		}
		if m.SgxResult != nil {
			m.SgxResult.VersionMatch.PrintErr("Version match")
			// TODO
			log.Warnf("Detailed SGX evaluation not yet implemented")
		}
		if m.TdxResult != nil {
			m.TdxResult.VersionMatch.PrintErr("Version match")
			// TODO
			log.Warnf("Detailed TDX evaluation not yet implemented")
		}
	}

	for _, s := range r.ReportSignature {
		s.PrintErr("Report")
	}

	if r.Metadata.CompDescResult != nil {
		r.Metadata.CompDescResult.Summary.PrintErr("Company description check")
		for _, s := range r.Metadata.CompDescResult.SignatureCheck {
			s.PrintErr("Company Description")
		}
		r.Metadata.CompDescResult.ValidityCheck.PrintErr("Company description validity check")
	}

	for _, mr := range r.Metadata.ManifestResults {
		mr.Summary.PrintErr("%v %v check", mr.Type, mr.Name)
		for _, s := range mr.SignatureCheck {
			s.PrintErr("%v", mr.Name)
		}
		mr.ValidityCheck.PrintErr("%v validity check", mr.Name)
	}

	r.Metadata.DevDescResult.Summary.PrintErr("Device Description check")
	for _, s := range r.Metadata.DevDescResult.SignatureCheck {
		s.PrintErr("Device Description")
	}

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

func GetCtrDetailsFromRefVal(r *ReferenceValue, s Serializer) *CtrData {

	if r == nil {
		log.Warnf("internal error: reference value is nil")
		return nil
	}

	// Get OCI runtime config from manifest if present
	m, err := r.GetManifest()
	if err != nil {
		return nil
	}

	return &CtrData{
		OciSpec: m.OciSpec,
	}
}
