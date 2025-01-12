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
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"

	oci "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

// The attestation report and verification result version
const (
	arVersion = "1.0.0"
)

func GetVersion() string {
	return arVersion
}

var log = logrus.WithField("service", "ar")

// AttestationReport represents the attestation report in JWS/COSE format with its
// contents already in signed JWS/COSE format
type AttestationReport struct {
	Version      string           `json:"version" cbor:"0,keyasint"`
	Type         string           `json:"type" cbor:"1,keyasint"`
	Measurements []Measurement    `json:"measurements,omitempty" cbor:"2,keyasint,omitempty"`
	Metadata     []MetadataDigest `json:"metadata,omitempty" cbor:"3,keyasint,omitempty"`
}

// MetadataDigest represents attestation report metadata elements
type MetadataDigest struct {
	Type   string  `json:"type" cbor:"0,keyasint"`
	Digest HexByte `json:"digest" cbor:"1,keyasint"`
}

// Measurement represents the attestation report
// elements of type 'TPM Measurement', 'SNP Measurement', 'TDX Measurement',
// 'SGX Measurement', 'IAS Measurement' or 'SW Measurement'
type Measurement struct {
	Type      string     `json:"type" cbor:"0,keyasint"`
	Evidence  []byte     `json:"evidence,omitempty" cbor:"1,keyasint"`
	Certs     [][]byte   `json:"certs,omitempty" cbor:"3,keyasint"`
	Signature []byte     `json:"signature,omitempty" cbor:"2,keyasint,omitempty"`
	Artifacts []Artifact `json:"artifacts,omitempty" cbor:"4,keyasint,omitempty"`
}

// Metadata represents attestation report elements of type 'Manifest'
// 'Device Description', 'Manifest Description' and 'Company Description'
type Metadata struct {
	MetaInfo
	Manifest
	DeviceDescription
	*DeviceConfig
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

type Manifest struct {
	ReferenceValues []ReferenceValue       `json:"referenceValues,omitempty" cbor:"10,keyasint,omitempty"`
	DevCommonName   string                 `json:"developerCommonName,omitempty"  cbor:"11,keyasint,omitempty"`
	BaseLayers      []string               `json:"baseLayers,omitempty" cbor:"12,keyasint,omitempty"`
	CertLevel       int                    `json:"certLevel,omitempty" cbor:"13,keyasint,omitempty"`
	Details         map[string]interface{} `json:"details,omitempty" cbor:"14,keyasint,omitempty"`
	OciSpec         *oci.Spec              `json:"ociSpec,omitempty" cbor:"ociSpec,omitempty"` // TODO move to app description
}

type DeviceDescription struct {
	Location     string                `json:"location,omitempty" cbor:"20,keyasint,omitempty"`
	Descriptions []ManifestDescription `json:"descriptions,omitempty" cbor:"21,keyasint,omitempty"`
}

// DeviceConfig contains the local device configuration parameters
type DeviceConfig struct {
	Tpm       CertConfig `json:"tpm,omitempty" cbor:"30,keyasint,omitempty"`
	Snp       CertConfig `json:"snp,omitempty" cbor:"31,keyasint,omitempty"`
	Sgx       CertConfig `json:"sgx,omitempty" cbor:"32,keyasint,omitempty"`
	Sw        CertConfig `json:"sw,omitempty" cbor:"33,keyasint,omitempty"`
	SgxValues struct {
		EncryptedPPID HexByte `json:"encryptedPPID,omitempty" cbor:"34,keyasint,omitempty"`
		Pceid         HexByte `json:"pceid,omitempty" cbor:"35,keyasint,omitempty"`
		Cpusvn        HexByte `json:"cpusvn,omitempty" cbor:"36,keyasint,omitempty"`
		Pcesvn        HexByte `json:"pcesvn,omitempty" cbor:"37,keyasint,omitempty"`
	}
}

// ManifestDescription represents the attestation report
// element of type 'Manifest Description'
type ManifestDescription struct {
	Type        string              `json:"type" cbor:"0,keyasint"`
	Name        string              `json:"name" cbor:"1,keyasint"`
	Description string              `json:"description,omitempty" cbor:"2,keyasint,omitempty"`
	Manifest    string              `json:"manifest,omitempty" cbor:"3,keyasint,omitempty"`
	External    []ExternalInterface `json:"externalConnections,omitempty" cbor:"4,keyasint,omitempty"`
	Environment []Environment       `json:"environment,omitempty" cbor:"5,keyasint,omitempty"`
}

// CertConfig contains the subject parameters for CSRs/Certs
type CertConfig struct {
	AkCsr CsrParams `json:"akCsr,omitempty" cbor:"3,keyasint,omitempty"`
	IkCsr CsrParams `json:"ikCsr,omitempty" cbor:"4,keyasint,omitempty"`
}

// ReferenceValue represents the attestation report
// element of types 'SNP Reference Value', 'TPM Reference Value', 'TDX Reference Value', 'SGX Reference Value'
// and 'SW Reference Value'
type ReferenceValue struct {
	Type        string      `json:"type" cbor:"0,keyasint"`
	Sha256      HexByte     `json:"sha256,omitempty" cbor:"1,keyasint,omitempty"`
	Sha384      HexByte     `json:"sha384,omitempty" cbor:"2,keyasint,omitempty"`
	Name        string      `json:"name,omitempty" cbor:"3,keyasint,omitempty"`
	Optional    bool        `json:"optional,omitempty" cbor:"4,keyasint,omitempty"`
	Pcr         *int        `json:"pcr,omitempty" cbor:"5,keyasint,omitempty"`
	Snp         *SnpDetails `json:"snp,omitempty" cbor:"6,keyasint,omitempty"`
	Tdx         *TDXDetails `json:"tdx,omitempty" cbor:"7,keyasint,omitempty"`
	Sgx         *SGXDetails `json:"sgx,omitempty" cbor:"8,keyasint,omitempty"`
	Description string      `json:"description,omitempty" cbor:"9,keyasint,omitempty"`
	EventData   *EventData  `json:"eventdata,omitempty" cbor:"10,keyasint,omitempty"`

	manifest *Metadata
}

// Validity is a helper struct for 'Validity'
type Validity struct {
	NotBefore string `json:"notBefore" cbor:"0,keyasint"`
	NotAfter  string `json:"notAfter" cbor:"1,keyasint"`
}

// Artifact represents the digests of a measurement, e.g., of a single PCR.
// If the type is 'PCR Summary', Summary is the final PCR value.
// If the type is 'PCR Eventlog', Events contains a list of the extends that lead to the final
// PCR value. The list is retrieved by the prover, e.g., from the TPM binary bios measurements
// list or the IMA runtime measurements list.
// If the type is 'SW Eventlog', Events contains a list of digests that have been recorded as
// SW measurements
type Artifact struct {
	Type    string         `json:"type" cbor:"0,keyasint"` // PCR Summary, PCR Eventlog, SW Eventlog
	Pcr     *int           `json:"pcr,omitempty" cbor:"1,keyasint"`
	Summary HexByte        `json:"summary,omitempty" cbor:"2,keyasint,omitempty"` // Either summary
	Events  []MeasureEvent `json:"events,omitempty" cbor:"3,keyasint,omitempty"`  // Or Events
}

type MeasureEvent struct {
	Sha256    HexByte    `json:"sha256" cbor:"0,keyasint"`
	EventName string     `json:"eventname,omitempty" cbor:"1,keyasint,omitempty"`
	EventData *EventData `json:"eventdata,omitempty" cbor:"2,keyasint,omitempty"`
	CtrData   *CtrData   `json:"ctrData,omitempty" cbor:"3,keyasint,omitempty"`
}

type CtrData struct {
	ConfigSha256 HexByte   `json:"configSha256" cbor:"0,keyasint"`
	RootfsSha256 HexByte   `json:"rootfsSha256" cbor:"1,keyasint"`
	OciSpec      *oci.Spec `json:"ociSpec,omitempty" cbor:"ociSpec,omitempty"`
}

type SnpPolicy struct {
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
	Bl    uint8 `json:"bl" cbor:"0,keyasint"`
	Tee   uint8 `json:"tee" cbor:"1,keyasint"`
	Snp   uint8 `json:"snp" cbor:"2,keyasint"`
	Ucode uint8 `json:"ucode" cbor:"3,keyasint"`
}

type SnpDetails struct {
	Version       uint32    `json:"version" cbor:"0,keyasint"`
	CaFingerprint string    `json:"caFingerprint" cbor:"1,keyasint"`
	Policy        SnpPolicy `json:"policy" cbor:"2,keyasint"`
	Fw            SnpFw     `json:"fw" cbor:"3,keyasint"`
	Tcb           SnpTcb    `json:"tcb" cbor:"4,keyasint"`
}

type IntelCollateral struct {
	TeeType        uint32          `json:"teeType" cbor:"0,keyasint"`
	TcbInfo        json.RawMessage `json:"tcbInfo" cbor:"1,keyasint"`
	TcbInfoSize    uint32          `json:"tcbInfoSize" cbor:"2,keyasint"`
	QeIdentity     json.RawMessage `json:"qeIdentity" cbor:"3,keyasint"`
	QeIdentitySize uint32          `json:"qeIdentitySize" cbor:"4,keyasint"`
}

// RtMrHashChainElem represents the attestation report
// element of type 'HashChain' embedded in 'TDXDetails'
type RtMrHashChainElem struct {
	Type    string    `json:"type" cbor:"0,keyasint"`
	Name    string    `json:"name" cbor:"1,keyasint"`
	Hashes  []HexByte `json:"Hashes" cbor:"2,keyasint"`
	Summary bool      `json:"summary" cbor:"3,keyasint"` // Indicates if element represents final RMTR value or single artifact
}

type TDXDetails struct {
	Version       uint16          `json:"version" cbor:"0,keyasint"`
	Collateral    IntelCollateral `json:"collateral" cbor:"1,keyasint"`
	CaFingerprint string          `json:"caFingerprint" cbor:"2,keyasint"` // Intel Root CA Certificate Fingerprint
	TdId          TDId            `json:"tdId" cbor:"3,keyasint"`
	TdMeas        TDMeasurements  `json:"tdMeasurements" cbor:"4,keyasint"`
	Xfam          [8]byte         `json:"xfam" cbor:"5,keyasint"`
	TdAttributes  TDAttributes    `json:"tdAttributes" cbor:"6,keyasint"`
}

type SGXDetails struct {
	Version       uint16          `json:"version" cbor:"0,keyasint"`
	Collateral    IntelCollateral `json:"collateral" cbor:"1,keyasint"`
	CaFingerprint string          `json:"caFingerprint" cbor:"2,keyasint"` // Intel Root CA Certificate Fingerprint
	IsvProdId     uint16          `json:"isvProdId" cbor:"3,keyasint"`
	MrSigner      string          `json:"mrSigner" cbor:"4,keyasint"`
	IsvSvn        uint16          `json:"isvSvn" cbor:"5,keyasint"`
	Attributes    SGXAttributes   `json:"attributes" cbor:"6,keyasint"`
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

type TDMeasurements struct {
	RtMr0  RtMrHashChainElem `json:"rtMr0" cbor:"0,keyasint"`  // Firmware measurement
	RtMr1  RtMrHashChainElem `json:"rtMr1" cbor:"1,keyasint"`  // BIOS measurement
	RtMr2  RtMrHashChainElem `json:"rtMr2" cbor:"2,keyasint"`  // OS measurement
	RtMr3  RtMrHashChainElem `json:"rtMr3" cbor:"3,keyasint"`  // Runtime measurement
	MrSeam HexByte           `json:"mrSeam" cbor:"4,keyasint"` // TDX Module measurement
}

type TDId struct {
	MrOwner       [48]byte `json:"mrOwner" cbor:"0,keyasint"`
	MrOwnerConfig [48]byte `json:"mrOwnerConfig" cbor:"1,keyasint"`
	MrConfigId    [48]byte `json:"mrConfigId" cbor:"2,keyasint"`
}

// ExternalInterface represents the attestation report
// element of type 'External Interface'
type ExternalInterface struct {
	Type        string `json:"type" cbor:"0,keyasint"`
	AppEndpoint string `json:"appEndpoint" cbor:"1,keyasint"`
	Interface   string `json:"interface" cbor:"2,keyasint"`
	Port        int    `json:"port" cbor:"3,keyasint"`
}

// Environment represents environment variables
// for apps
type Environment struct {
	Key   string `json:"key" cbor:"0,keyasint"`
	Value string `json:"value" cbor:"1,keyasint"`
}

// CsrParams contains certificate signing request parameters
type CsrParams struct {
	Subject Name     `json:"subject,omitempty" cbor:"0,keyasint,omitempty"`
	SANs    []string `json:"sans,omitempty" cbor:"1,keyasint,omitempty"`
}

// Name is the PKIX Name for CsrParams
type Name struct {
	CommonName         string        `json:"commonName,omitempty" cbor:"0,keyasint,omitempty"`
	Country            string        `json:"country,omitempty" cbor:"1,keyasint,omitempty"`
	Organization       string        `json:"organization,omitempty" cbor:"2,keyasint,omitempty"`
	OrganizationalUnit string        `json:"organizationalUnit,omitempty" cbor:"3,keyasint,omitempty"`
	Locality           string        `json:"locality,omitempty" cbor:"4,keyasint,omitempty"`
	Province           string        `json:"province,omitempty" cbor:"5,keyasint,omitempty"`
	StreetAddress      string        `json:"streetAddress,omitempty" cbor:"6,keyasint,omitempty"`
	PostalCode         string        `json:"postalCode,omitempty" cbor:"7,keyasint,omitempty"`
	Names              []interface{} `json:"names,omitempty" cbor:"8,keyasint,omitempty"`
}

// Driver is an interface representing a driver for a hardware trust anchor,
// capable of providing attestation evidence and signing data. This can be
// e.g. a Trusted Platform Module (TPM), AMD SEV-SNP, or the ARM PSA
// Initial Attestation Service (IAS). The driver must be capable of
// performing measurements, i.e. retrieving attestation evidence, such as
// a TPM Quote or an SNP attestation report, as well as signing data.
// For measurements, the driver must provide handles for attestation keys.
// For signing, the driver provides handles for identity keys.
type Driver interface {
	Init(c *DriverConfig) error
	Measure(nonce []byte) (Measurement, error)
	Lock() error
	Unlock() error
	GetKeyHandles(keyType KeySelection) (crypto.PrivateKey, crypto.PublicKey, error)
	GetCertChain(keyType KeySelection) ([]*x509.Certificate, error)
	Name() string
}

// DriverConfig contains all configuration values required for the different drivers
type DriverConfig struct {
	StoragePath    string
	ServerAddr     string
	KeyConfig      string
	Ima            bool
	ImaPcr         int
	Serializer     Serializer
	MeasurementLog bool
	Ctr            bool
	CtrPcr         int
	CtrLog         string
	ExtCtrLog      bool
	CtrDriver      string
	DeviceConfig   DeviceConfig
}

type KeySelection int

const (
	UNKNOWN = iota
	AK
	IK
)

func (r *ReferenceValue) GetManifest() (*Metadata, error) {
	if r.manifest == nil {
		return nil, fmt.Errorf("internal error: failed to retrieve manifest")
	}
	return r.manifest, nil
}

func (r *ReferenceValue) SetManifest(m *Metadata) {
	r.manifest = m
}

func (report *AttestationReport) CheckVersion() error {
	if report == nil {
		return fmt.Errorf("internal error: AttestationReport is nil")
	}
	if !strings.EqualFold(arVersion, report.Version) {
		return fmt.Errorf("API version mismatch. Expected AttestationReport version %v, got %v", arVersion, report.Version)
	}
	return nil
}
