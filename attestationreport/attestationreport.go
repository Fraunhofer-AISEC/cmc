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
	"crypto"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	oci "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

// The attestation report version
const (
	reportVersion = "3.0.0"
)

func GetReportVersion() string {
	return reportVersion
}

var log = logrus.WithField("service", "ar")

// Attestation Report type fields
const (
	// Attestation Report type field
	TYPE_ATTESTATION_REPORT = "Attestation Report"
	TYPE_ATTESTATION_RESULT = "Attestation Result"

	// Encoding type fields
	TYPE_ENCODING_B64  = "b64"
	TYPE_ENCODING_JCS  = "jcs"
	TYPE_ENCODING_CBOR = "cbor"

	// Evidence type fields
	TYPE_EVIDENCE_SNP       = "SNP Evidence"
	TYPE_EVIDENCE_SW        = "SW Evidence"
	TYPE_EVIDENCE_SGX       = "SGX Evidence"
	TYPE_EVIDENCE_TDX       = "TDX Evidence"
	TYPE_EVIDENCE_TPM       = "TPM Evidence"
	TYPE_EVIDENCE_IAS       = "IAS Evidence"
	TYPE_EVIDENCE_AZURE_SNP = "azure SNP Evidence"
	TYPE_EVIDENCE_AZURE_TDX = "azure TDX Evidence"
	TYPE_EVIDENCE_AZURE_TPM = "azure vTPM Evidence"

	// Artifact type fields
	TYPE_PCR_SUMMARY    = "PCR Summary"
	TYPE_PCR_EVENTLOG   = "PCR Eventlog"
	TYPE_TDX_COLLATERAL = "TDX Collateral"
	TYPE_SGX_COLLATERAL = "SGX Collateral"
	TYPE_SW_EVENTLOG    = "SW Eventlog"
	TYPE_CC_EVENTLOG    = "CC Eventlog"

	// Reference metadata type fields
	TYPE_CONTEXT              = "Context"
	TYPE_MANIFEST             = "Manifest"
	TYPE_IMAGE_DESCRIPTION    = "Image Description"
	TYPE_MANIFEST_DESCRIPTION = "Manifest Description"
	TYPE_COMPANY_DESCRIPTION  = "Company Description"

	// Reference value type fields
	TYPE_REFVAL     = "Reference Value"
	TYPE_REFVAL_SNP = "SNP Reference Value"
	TYPE_REFVAL_SW  = "SW Reference Value"
	TYPE_REFVAL_SGX = "SGX Reference Value"
	TYPE_REFVAL_TDX = "TDX Reference Value"
	TYPE_REFVAL_TPM = "TPM Reference Value"
	TYPE_REFVAL_IAS = "IAS Reference Value"
)

// AttestationReport represents the self-contained attestation report comprising evidences,
// collateral, and signed reference metadata
type AttestationReport struct {
	Version   string     `json:"version" cbor:"0,keyasint"`
	Type      string     `json:"type" cbor:"1,keyasint"`
	Name      string     `json:"name,omitempty" cbor:"2,keyasint,omitempty"`
	Encoding  string     `json:"encoding" cbor:"3,keyasint"`
	Evidences []Evidence `json:"evidences" cbor:"4,keyasint"`
	Context   Context    `json:"-" cbor:"5,keyasint"`

	// Required for integrity
	encodedContext []byte
}

// Evidence contains the hardware trust anchor binary evidence, e.g., the TDX quote or AMD SEV-SNP
// attestation report. Matched to Collateral via the Type property
type Evidence struct {
	Type      string `json:"type" cbor:"0,keyasint"`
	Data      []byte `json:"evidence" cbor:"1,keyasint"`
	AddData   []byte `json:"addData,omitempty" cbor:"2,keyasint,omitempty"`
	Signature []byte `json:"signature,omitempty" cbor:"3,keyasint,omitempty"`
}

// Context contains all data required to interpret the evidence. This comprises evidence
// collateral, e.g., TPM event logs, metadata, e.g. manifests with reference hashes, as well as
// CA certificates
type Context struct {
	Type       string            `json:"type" cbor:"0,keyasint"`
	Alg        string            `json:"alg" cbor:"1,keyasint"`                          // Hash algorithm for metadata digests and integrity
	Nonce      []byte            `json:"nonce" cbor:"2,keyasint"`                        // User supplied nonce
	Collateral []Collateral      `json:"collateral" cbor:"3,keyasint"`                   // Metadata required for interpreting evidences, must match Evidence.Type
	Digests    []string          `json:"digests" cbor:"4,keyasint"`                      // Manifest Digests with hash alg "hash"
	Metadata   map[string][]byte `json:"metadata,omitempty" cbor:"5,keyasint,omitempty"` // Metadata (not cached)
	Certs      map[string][]byte `json:"certs,omitempty" cbor:"6,keyasint,omitempty"`    // DER encoded certs for verifying metadata (JWS: x5t/kid)
}

// Collateral contains the event logs and hardware trust anchor CA certificates required
// to interpret the evidence. Matched to Evidence via the Type property
type Collateral struct {
	Type      string     `json:"type" cbor:"0,keyasint"`
	Certs     [][]byte   `json:"certs,omitempty" cbor:"1,keyasint,omitempty"`
	Key       []byte     `json:"key,omitempty" cbor:"2,keyasint,omitempty"`
	Artifacts []Artifact `json:"artifacts,omitempty" cbor:"3,keyasint,omitempty"`
}

// Metadata represents attestation report reference descriptions and manifests containing
// the reference hashes. This structure already holds the unpacked and validated item.
type Metadata struct {
	MetaInfo
	Manifest
	ImageDescription
}

// MetaInfo is a helper struct for generic info
// present in every metadata object
type MetaInfo struct {
	Type        string   `json:"type" cbor:"0,keyasint"`
	Name        string   `json:"name" cbor:"1,keyasint"`
	Version     string   `json:"version" cbor:"2,keyasint"`
	Validity    Validity `json:"validity" cbor:"3,keyasint"`
	Description string   `json:"description,omitempty" cbor:"4,keyasint,omitempty"`
}

// Manifest represents a part of the reference software stack (e.g., OS layer, app layer)
// and includes a list of reference hash values comprising the layer
type Manifest struct {
	ReferenceValues []ReferenceValue       `json:"referenceValues,omitempty" cbor:"10,keyasint,omitempty"`
	DevCommonName   string                 `json:"developerCommonName,omitempty"  cbor:"11,keyasint,omitempty"`
	BaseLayers      []string               `json:"baseLayers,omitempty" cbor:"12,keyasint,omitempty"`
	CertLevel       int                    `json:"certLevel,omitempty" cbor:"13,keyasint,omitempty"`
	CaFingerprints  []string               `json:"caFingerprints,omitempty" cbor:"14,keyasint,omitempty"`
	SnpPolicy       *SnpPolicy             `json:"snpPolicy,omitempty" cbor:"15,keyasint,omitempty"`
	TdxPolicy       *TdxPolicy             `json:"tdxPolicy,omitempty" cbor:"16,keyasint,omitempty"`
	SgxPolicy       *SgxPolicy             `json:"sgxPolicy,omitempty" cbor:"17,keyasint,omitempty"`
	Details         map[string]interface{} `json:"details,omitempty" cbor:"18,keyasint,omitempty"`
}

// ImageDescription ties together all manifests
type ImageDescription struct {
	Location     string                `json:"location,omitempty" cbor:"20,keyasint,omitempty"`
	Descriptions []ManifestDescription `json:"descriptions,omitempty" cbor:"21,keyasint,omitempty"`
}

// ManifestDescription links the manifests into the ImageDescription
type ManifestDescription struct {
	Type        string `json:"type" cbor:"0,keyasint"`
	Name        string `json:"name" cbor:"1,keyasint"`
	Description string `json:"description,omitempty" cbor:"2,keyasint,omitempty"`
	Manifest    string `json:"manifest,omitempty" cbor:"3,keyasint,omitempty"`
}

// ReferenceValue represents the attestation report element of types as defined in TYPE_REFVAL.
// The Index is the unique identifier for the reference value: This is the number of the PCR in
// case of TPM reference values, the CC measurement register (MR) index according to
// UEFI Spec 2.10 Section 38.4.1 in case of TDX reference values:
// TPM PCR Index | CC MR Index | TDX register
// 0             | 0           |   MRTD
// 1, 7          | 1           |   RTMR0
// 2~6           | 2           |   RTMR1
// 8~15          | 3           |   RTMR2
// -             | 4           |   RTMR3
// -             | 5           |   MRSEAM (not in UEFI spec)
type ReferenceValue struct {
	Type        string     `json:"type" cbor:"0,keyasint"`
	SubType     string     `json:"subtype" cbor:"1,keyasint,omitempty"`
	Index       int        `json:"index" cbor:"2,keyasint"`
	Sha1        HexByte    `json:"sha1,omitempty" cbor:"3,keyasint,omitempty"`
	Sha256      HexByte    `json:"sha256,omitempty" cbor:"4,keyasint,omitempty"`
	Sha384      HexByte    `json:"sha384,omitempty" cbor:"5,keyasint,omitempty"`
	Sha512      HexByte    `json:"sha512,omitempty" cbor:"6,keyasint,omitempty"`
	Optional    bool       `json:"optional,omitempty" cbor:"7,keyasint,omitempty"`
	Description string     `json:"description,omitempty" cbor:"8,keyasint,omitempty"`
	EventData   *EventData `json:"eventdata,omitempty" cbor:"9,keyasint,omitempty"`
	OciSpec     *oci.Spec  `json:"ociSpec,omitempty" cbor:"ociSpec,omitempty"`
}

// Validity is a helper struct for 'Validity'
type Validity struct {
	NotBefore string `json:"notBefore" cbor:"0,keyasint"`
	NotAfter  string `json:"notAfter" cbor:"1,keyasint"`
}

// SwEvidence represents the CMC's own format for software-based container measurement
// evidences
type SwEvidence struct {
	Nonce  []byte `json:"nonce" cbor:"0,keyasint"`
	Sha256 []byte `json:"sha256,omitempty" cbor:"1,keyasint,omitempty"`
}

// Artifact represents the digests of a measurement.
// If the type is 'PCR Summary', 'Events' contains the final PCR value of PCR 'Pcr' and 'Index'
// contains the number of the PCR.
// If the type is 'PCR Eventlog', 'Events' contains a list of the extends that lead to the final
// PCR value and 'Index' contains the number of the PCR. The list is retrieved by the prover, e.g.,
// from the TPM binary bios measurements list or the IMA runtime measurements list.
// If the type is 'SW Eventlog', 'Events' contains a list of digests that have been recorded as
// SW measurements
// If the type is 'TDX Collateral', 'Events' contains the TDX collateral, which includes the
// TDX TCB info, the quoting enclave identity and the certicate revocation lists.
// It the type is CC Eventlog, 'Events' contains a list of the extends that lead to the final
// TDX RTMR value and 'Index' contains the number of the RTMR.
type Artifact struct {
	Type   string         `json:"type" cbor:"0,keyasint"`
	Index  int            `json:"index" cbor:"1,keyasint"`
	Events []MeasureEvent `json:"events,omitempty" cbor:"2,keyasint,omitempty"`
}

// MeasureEvent represents a measured event
type MeasureEvent struct {
	Sha1            HexByte          `json:"sha1,omitempty" cbor:"0,keyasint,omitempty"`
	Sha256          HexByte          `json:"sha256,omitempty" cbor:"1,keyasint,omitempty"`
	Sha384          HexByte          `json:"sha384,omitempty" cbor:"2,keyasint,omitempty"`
	Sha512          HexByte          `json:"sha512,omitempty" cbor:"3,keyasint,omitempty"`
	Index           int              `json:"index,omitempty" cbor:"4,keyasint,omitempty"`
	EventName       string           `json:"eventname,omitempty" cbor:"5,keyasint,omitempty"`
	EventData       *EventData       `json:"eventdata,omitempty" cbor:"6,keyasint,omitempty"`
	Description     string           `json:"description,omitempty" cbor:"7,keyasint,omitempty"`
	CtrData         *CtrData         `json:"ctrData,omitempty" cbor:"8,keyasint,omitempty"`
	IntelCollateral *IntelCollateral `json:"intelCollateral,omitempty" cbor:"9,keyasint,omitempty"`
}

type IntelQuoteType uint32

const (
	SGX_QUOTE_TYPE IntelQuoteType = 0x0
	TDX_QUOTE_TYPE IntelQuoteType = 0x81
)

// IntelCollateral is a helper struct for Intel SGX/TDX collateral
type IntelCollateral struct {
	TcbInfo                    []byte
	QeIdentity                 []byte
	RootCaCrl                  []byte
	PckCrl                     []byte
	PckCrlIntermediateCert     []byte
	PckCrlRootCert             []byte
	TcbInfoIntermediateCert    []byte
	TcbInfoRootCert            []byte
	QeIdentityIntermediateCert []byte
	QeIdentityRootCert         []byte
}

// CrtData represents the measurement of an OCI container, comprising the OCI
// runtime config hash, the rootfs hash, and the OCI spec itself for policy enforcement
type CtrData struct {
	ConfigSha256 HexByte   `json:"configSha256" cbor:"0,keyasint"`
	RootfsSha256 HexByte   `json:"rootfsSha256" cbor:"1,keyasint"`
	OciSpec      *oci.Spec `json:"ociSpec,omitempty" cbor:"ociSpec,omitempty"`
}

type SnpGuestPolicy struct {
	Type         string `json:"type" cbor:"0,keyasint"`
	SingleSocket bool   `json:"singleSocket" cbor:"1,keyasint"`
	Debug        bool   `json:"debug" cbor:"2,keyasint"`
	Migration    bool   `json:"migration" cbor:"3,keyasint"`
	Smt          bool   `json:"smt" cbor:"4,keyasint"`
	AbiMajor     uint8  `json:"abiMajor" cbor:"5,keyasint"`
	AbiMinor     uint8  `json:"abiMinor" cbor:"6,keyasint"`
}

type SnpFw struct {
	Build uint8 `json:"build" cbor:"0,keyasint"`
	Major uint8 `json:"major" cbor:"1,keyasint"`
	Minor uint8 `json:"minor" cbor:"2,keyasint"`
}

type SnpTcb struct {
	Fmc   uint8 `json:"fmc" cbor:"0,keyasint"`
	Bl    uint8 `json:"bl" cbor:"1,keyasint"`
	Tee   uint8 `json:"tee" cbor:"2,keyasint"`
	Snp   uint8 `json:"snp" cbor:"3,keyasint"`
	Ucode uint8 `json:"ucode" cbor:"4,keyasint"`
}

type SnpVersion struct {
	Name string `json:"name" cbor:"0,keyasint"`
	Fw   SnpFw  `json:"fw" cbor:"1,keyasint"`
	Tcb  SnpTcb `json:"tcb" cbor:"2,keyasint"`
}

type SnpPolicy struct {
	ReportMinVersion uint32         `json:"reportMinVersion" cbor:"0,keyasint"`
	ReportMaxVersion uint32         `json:"reportMaxVersion" cbor:"1,keyasint"`
	GuestPolicy      SnpGuestPolicy `json:"policy" cbor:"2,keyasint"`
	VersionPolicy    []SnpVersion   `json:"versions" cbor:"3,keyasint"`
}

// RtMrHashChainElem represents the attestation report
// element of type 'HashChain' embedded in 'TDXDetails'
type RtMrHashChainElem struct {
	Type    string    `json:"type" cbor:"0,keyasint"`
	Name    string    `json:"name" cbor:"1,keyasint"`
	Hashes  []HexByte `json:"Hashes" cbor:"2,keyasint"`
	Summary bool      `json:"summary" cbor:"3,keyasint"` // Indicates if element represents final RMTR value or single artifact
}

type TdxPolicy struct {
	QuoteVersion        uint16       `json:"quoteVersion" cbor:"0,keyasint"`
	TdId                TDId         `json:"tdId" cbor:"1,keyasint"`
	Xfam                HexByte      `json:"xfam" cbor:"2,keyasint"`
	TdAttributes        TDAttributes `json:"tdAttributes" cbor:"3,keyasint"`
	AcceptedTcbStatuses []string     `json:"acceptedTcbStatuses,omitempty" cbor:"4,keyasint"`
}

type SgxPolicy struct {
	QuoteVersion        uint16        `json:"quoteVersion" cbor:"0,keyasint"`
	IsvProdId           uint16        `json:"isvProdId" cbor:"1,keyasint"`
	MrSigner            string        `json:"mrSigner" cbor:"2,keyasint"`
	IsvSvn              uint16        `json:"isvSvn" cbor:"3,keyasint"`
	Attributes          SGXAttributes `json:"attributes" cbor:"4,keyasint"`
	AcceptedTcbStatuses []string      `json:"acceptedTcbStatuses,omitempty" cbor:"5,keyasint"`
}

// SGX attributes according to
// https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_Developer_Reference_Linux_2.22_Open_Source.pdf (page 414)
type SGXAttributes struct {
	Initted      bool `json:"initted" cbor:"0,keyasint"`
	Debug        bool `json:"debug" cbor:"1,keyasint"`
	Mode64Bit    bool `json:"mode64Bit" cbor:"2,keyasint"`
	ProvisionKey bool `json:"provisionKey" cbor:"3,keyasint"`
	EInitToken   bool `json:"eInitToken" cbor:"4,keyasint"`
	Kss          bool `json:"kss" cbor:"5,keyasint"`
	Legacy       bool `json:"legacy" cbor:"6,keyasint"`
	Avx          bool `json:"avx" cbor:"7,keyasint"`
}

// Structure of the security relevant attributes for a TD
// (Bits 0 - 31 of attributes array in quote)
// according to https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf (page 40)
type TDAttributes struct {
	Debug         bool `json:"debug" cbor:"0,keyasint"`
	SeptVEDisable bool `json:"septVEDisable" cbor:"1,keyasint"`
	Pks           bool `json:"pks" cbor:"2,keyasint"`
	Kl            bool `json:"kl" cbor:"3,keyasint"`
}

type TDId struct {
	MrOwner       HexByte `json:"mrOwner" cbor:"0,keyasint"`
	MrOwnerConfig HexByte `json:"mrOwnerConfig" cbor:"1,keyasint"`
	MrConfigId    HexByte `json:"mrConfigId" cbor:"2,keyasint"`
}

func (r *AttestationReport) PrepareContext(s Serializer, alg crypto.Hash) ([]byte, error) {
	raw, err := s.Marshal(r.Context)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal report context: %w", err)
	}

	switch r.Encoding {
	case TYPE_ENCODING_B64:
		r.encodedContext = make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
		base64.RawURLEncoding.Encode(r.encodedContext, raw)
	case TYPE_ENCODING_CBOR:
		r.encodedContext = raw
	default:
		return nil, fmt.Errorf("unknown encoding %q", r.Encoding)
	}

	h, err := internal.Hash(alg, r.encodedContext)
	if err != nil {
		return nil, fmt.Errorf("failed to construct metadata hash: %w", err)
	}
	log.Tracef("Calculated %v context hash %x for encoded context with user nonce %x and length %v",
		alg.String(), h, r.Context.Nonce, len(r.encodedContext))

	return h, nil
}

func (r *AttestationReport) CheckVersion() error {
	if r == nil {
		return fmt.Errorf("internal error: AttestationReport is nil")
	}
	if !strings.EqualFold(reportVersion, r.Version) {
		return fmt.Errorf("API version mismatch. Expected AttestationReport version %v, got %v",
			reportVersion, r.Version)
	}
	return nil
}

func (ar *AttestationReport) GetEncodedContext() []byte {
	return ar.encodedContext
}

func GetSnpTcb(codeName string, tcb uint64) SnpTcb {
	if strings.EqualFold(codeName, "Milan") || strings.EqualFold(codeName, "Genoa") {
		return SnpTcb{
			Fmc:   0,
			Bl:    uint8(tcb & 0xFF),
			Tee:   uint8((tcb >> 8) & 0xFF),
			Snp:   uint8((tcb >> 48) & 0xFF),
			Ucode: uint8((tcb >> 56) & 0xFF),
		}

	} else { // Turin
		return SnpTcb{
			Fmc:   uint8(tcb & 0xFF),
			Bl:    uint8((tcb >> 8) & 0xFF),
			Tee:   uint8((tcb >> 16) & 0xFF),
			Snp:   uint8((tcb >> 24) & 0xFF),
			Ucode: uint8((tcb >> 56) & 0xFF),
		}
	}
}

func (r *ReferenceValue) GetHash(h crypto.Hash) []byte {
	switch h {
	case crypto.SHA1:
		return r.Sha1
	case crypto.SHA256:
		return r.Sha256
	case crypto.SHA384:
		return r.Sha384
	case crypto.SHA512:
		return r.Sha512
	default:
		return nil
	}
}

func (e *MeasureEvent) GetHash(h crypto.Hash) []byte {
	switch h {
	case crypto.SHA1:
		return e.Sha1
	case crypto.SHA256:
		return e.Sha256
	case crypto.SHA384:
		return e.Sha384
	case crypto.SHA512:
		return e.Sha512
	default:
		return nil
	}
}
