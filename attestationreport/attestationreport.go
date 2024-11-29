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
	"crypto"
	"crypto/x509"
	"encoding/json"

	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "ar")

// AttestationReport represents the attestation report in JWS/COSE format with its
// contents already in signed JWS/COSE format
type AttestationReport struct {
	Type                     string           `json:"type" cbor:"0,keyasint"`
	Measurements             []Measurement    `json:"measurements,omitempty" cbor:"1,keyasint,omitempty"`
	RtmManifest              []byte           `json:"rtmManifest,omitempty" cbor:"2,keyasint"`
	RtmManifestDigest        MetadataDigest   `json:"rtmManifestDigest,omitempty" cbor:"3,keyasint,omitempty"`
	OsManifest               []byte           `json:"osManifest,omitempty" cbor:"4,keyasint,omitempty"`
	OsManifestDigest         MetadataDigest   `json:"osManifestDigest,omitempty" cbor:"5,keyasint,omitempty"`
	AppManifests             [][]byte         `json:"appManifests,omitempty" cbor:"6,keyasint,omitempty"`
	AppManifestDigests       []MetadataDigest `json:"appManifestDigests,omitempty" cbor:"7,keyasint,omitempty"`
	CompanyDescription       []byte           `json:"companyDescription,omitempty" cbor:"8,keyasint,omitempty"`
	CompanyDescriptionDigest MetadataDigest   `json:"companyDescriptionDigest,omitempty" cbor:"9,keyasint,omitempty"`
	DeviceDescription        []byte           `json:"deviceDescription,omitempty" cbor:"9,keyasint,omitempty"`
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

// MetadataDigest represents attestation report
// elements of type 'RTM Manifest Digest', 'OS Manifest Digest' and 'App Manifest Digest'
type MetadataDigest struct {
	Type   string  `json:"type" cbor:"0,keyasint"`
	Digest HexByte `json:"digest" cbor:"1,keyasint"`
}

// Manifest represents attestation report
// elements of type 'RTM Manifest', 'OS Manifest' and 'App Manifest'
type Manifest struct {
	MetaInfo
	DevCommonName      string           `json:"developerCommonName"  cbor:"3,keyasint"`
	BaseLayers         []string         `json:"baseLayers" cbor:"4,keyasint"` // Links to RtmManifest.Name or OsManifest.Name
	Description        string           `json:"description" cbor:"5,keyasint"`
	CertificationLevel int              `json:"certificationLevel" cbor:"6,keyasint"`
	Validity           Validity         `json:"validity" cbor:"7,keyasint"`
	ReferenceValues    []ReferenceValue `json:"referenceValues" cbor:"8,keyasint"`
	OciSpec            any              `json:"ociSpec,omitempty" cbor:"9,keyasint,omitempty"` // TODO move to app description
	Details            any              `json:"details,omitempty" cbor:"9,keyasint,omitempty"`
}

// DeviceDescription represents the attestation report
// element of type 'Device Description'
type DeviceDescription struct {
	MetaInfo
	Description     string               `json:"description" cbor:"3,keyasint"`
	Location        string               `json:"location" cbor:"4,keyasint"`
	RtmManifest     string               `json:"rtmManifest" cbor:"5,keyasint"`
	OsManifest      string               `json:"osManifest" cbor:"6,keyasint"`
	AppDescriptions []AppDescription     `json:"appDescriptions" cbor:"7,keyasint"`
	Internal        []InternalConnection `json:"internalConnections" cbor:"8,keyasint"`
	External        []ExternalInterface  `json:"externalEndpoints" cbor:"9,keyasint"`
}

// CompanyDescription represents the attestation report
// element of type 'Company Description'
type CompanyDescription struct {
	MetaInfo
	CertificationLevel int      `json:"certificationLevel" cbor:"3,keyasint"`
	Description        string   `json:"description" cbor:"4,keyasint"`
	Validity           Validity `json:"validity" cbor:"5,keyasint"`
}

// AppDescription represents the attestation report
// element of type 'App Description'
type AppDescription struct {
	MetaInfo
	AppManifest string              `json:"appManifest" cbor:"3,keyasint"` // Links to App Manifest.Name
	External    []ExternalInterface `json:"externalConnections,omitempty" cbor:"4,keyasint,omitempty"`
	Environment []Environment       `json:"environment,omitempty" cbor:"5,keyasint,omitempty"`
}

// DeviceConfig contains the local device configuration parameters
type DeviceConfig struct {
	MetaInfo
	AkCsr     CsrParams `json:"akCsr" cbor:"3,keyasint"`
	IkCsr     CsrParams `json:"ikCsr" cbor:"4,keyasint"`
	SgxValues struct {
		EncryptedPPID HexByte `json:"encryptedPPID" cbor:"5,keyasint"`
		Pceid         HexByte `json:"pceid" cbor:"6,keyasint"`
		Cpusvn        HexByte `json:"cpusvn" cbor:"7,keyasint"`
		Pcesvn        HexByte `json:"pcesvn" cbor:"8,keyasint"`
	}
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

	manifest *Manifest
}

// MetaInfo is a helper struct for generic info
// present in every metadata object
type MetaInfo struct {
	Type    string `json:"type" cbor:"0,keyasint"`
	Name    string `json:"name" cbor:"1,keyasint"`
	Version string `json:"version" cbor:"2,keyasint"`
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
	Sha256    HexByte    `json:"sha256" cbor:"2,keyasint"`
	EventName string     `json:"eventname,omitempty" cbor:"4,keyasint,omitempty"`
	EventData *EventData `json:"eventdata,omitempty" cbor:"5,keyasint,omitempty"`
	CtrData   *CtrData   `json:"ctrData,omitempty" cbor:"6,keyasint,omitempty"`
}

type CtrData struct {
	ConfigSha256 HexByte `json:"configSha256" cbor:"0,keyasint"`
	RootfsSha256 HexByte `json:"rootfsSha256" cbor:"1,keyasint"`
	OciSpec      []byte  `json:"ociSpec" cbor:"2,keyasint"`
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

// InternalConnection represents the attestation report
// element of type 'Internal Connection'
type InternalConnection struct {
	Type         string `json:"type" cbor:"0,keyasint"`
	NameAppA     string `json:"nameAppA" cbor:"1,keyasint"`     // Links to AppDescription.Name
	EndpointAppA string `json:"endpointAppA" cbor:"2,keyasint"` // Links to AppManifest.Endpoint
	NameAppB     string `json:"nameAppB" cbor:"3,keyasint"`     // Links to AppDescription.Name
	EndpointAppB string `json:"endpointAppB" cbor:"4,keyasint"` // Links to AppManifest.Endpoint
}

// ExternalInterface represents the attestation report
// element of type 'External Interface'
type ExternalInterface struct {
	Type        string `json:"type" cbor:"0,keyasint"`
	AppEndpoint string `json:"appEndpoint" cbor:"1,keyasint"` // Links to AppManifest.Endpoint
	Interface   string `json:"interface" cbor:"2,keyasint"`   // Links to AppDescription.Name
	Port        int    `json:"port" cbor:"3,keyasint"`        // Links to App Manifest.Endpoint
}

// Environment represents environment variables
// for apps
type Environment struct {
	Key   string `json:"key" cbor:"0,keyasint"`
	Value string `json:"value" cbor:"1,keyasint"`
}

// CsrParams contains certificate signing request parameters
type CsrParams struct {
	Subject Name     `json:"subject" cbor:"0,keyasint"`
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

// Metadata is an internal structure for manifests and descriptions
type Metadata struct {
	RtmManifest        Manifest
	OsManifest         Manifest
	AppManifests       []Manifest
	CompanyDescription *CompanyDescription
	DeviceDescription  DeviceDescription
}

// Driver is an interface representing a driver for a hardware trust anchor,
// capable of providing attestation evidence and signing data. This can be
// e.g. a Trusted Platform Module (TPM), AMD SEV-SNP, or the ARM PSA
// Initial Attestation Service (IAS). The driver must be capable of
// performing measurements, i.e. retrieving attestation evidence such as
// a TPM Quote or an SNP attestation report and providing handles to
// signing keys and their certificate chains
type Driver interface {
	Init(c *DriverConfig) error                                   // Initializes the driver
	Measure(nonce []byte) (Measurement, error)                    // Retrieves measurements
	Lock() error                                                  // For sync, if required
	Unlock() error                                                // For sync, if required
	GetSigningKeys() (crypto.PrivateKey, crypto.PublicKey, error) // Get Signing key handles
	GetCertChain() ([]*x509.Certificate, error)                   // Get cert chain for signing key
}

// DriverConfig contains all configuration values required for the different drivers
type DriverConfig struct {
	StoragePath    string
	ServerAddr     string
	KeyConfig      string
	Metadata       map[string][]byte
	UseIma         bool
	ImaPcr         int
	Serializer     Serializer
	MeasurementLog bool
	UseCtr         bool
	CtrPcr         int
	CtrLog         string
	ExtCtrLog      bool
	CtrDriver      string
}

// Serializer is a generic interface providing methods for data serialization and
// de-serialization. This enables to generate and verify attestation reports in
// different formats, such as JSON/JWS or CBOR/COSE
type Serializer interface {
	GetPayload(raw []byte) ([]byte, error)
	Marshal(v any) ([]byte, error)
	Unmarshal(data []byte, v any) error
	Sign(data []byte, signer Driver) ([]byte, error)
	VerifyToken(data []byte, roots []*x509.Certificate) (TokenResult, []byte, bool)
}

func (r *ReferenceValue) GetManifest() *Manifest {
	return r.manifest
}

func (r *ReferenceValue) SetManifest(m *Manifest) {
	r.manifest = m
}
