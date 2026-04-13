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

// Contains the API definitions for the CoAP and socket API.
// The gRPC API is in a separate file
package api

import (
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// The version of the API
const (
	apiVersion = "1.4.0"
)

func GetVersion() string {
	return apiVersion
}

const (
	EndpointAttest         = "/Attest"
	EndpointVerify         = "/Verify"
	EndpointTLSCreate      = "/TLSCreate"
	EndpointTLSSign        = "/TLSSign"
	EndpointTLSCert        = "/TLSCert"
	EndpointPeerCache      = "/PeerCache"
	EndpointMeasure        = "/Measure"
	EndpointUpdateCerts    = "/UpdateCerts"
	EndpointUpdateMetadata = "/UpdateMetadata"
)

const (
	TypeError          uint32 = 0
	TypeAttest         uint32 = 1
	TypeVerify         uint32 = 2
	TypeTLSCreate      uint32 = 3
	TypeTLSSign        uint32 = 4
	TypeTLSCert        uint32 = 5
	TypePeerCache      uint32 = 6
	TypeMeasure        uint32 = 7
	TypeUpdateCerts    uint32 = 8
	TypeUpdateMetadata uint32 = 9
)

type AttestationRequest struct {
	Version string   `json:"version" cbor:"0,keyasint"`
	Nonce   []byte   `json:"nonce" cbor:"1,keyasint"`
	Cached  []string `json:"cached,omitempty" cbor:"2,keyasint,omitempty"`
}

type AttestationResponse struct {
	Version string `json:"version" cbor:"0,keyasint"`
	Report  []byte `json:"report" cbor:"1,keyasint"`
}

type VerificationRequest struct {
	Version  string `json:"version" cbor:"0,keyasint"`
	Nonce    []byte `json:"nonce" cbor:"1,keyasint"`
	Report   []byte `json:"report" cbor:"2,keyasint"`
	Peer     string `json:"peer,omitempty" cbor:"6,keyasint,omitempty"`
	Policies []byte `json:"policies,omitempty" cbor:"8,keyasint,omitempty"`
}

type VerificationResponse struct {
	Version string                `json:"version" cbor:"0,keyasint"`
	Result  *ar.AttestationResult `json:"result" cbor:"1,keyasint"`
}

type TLSCreateRequest struct {
	Version   string       `json:"version" cbor:"0,keyasint"`
	KeyConfig TLSKeyConfig `json:"keyConfig" cbor:"1,keyasint"`
}

type TLSKeyConfig struct {
	Type        string   `json:"type" cbor:"1,keyasint" jsonschema:"enum=tpm,enum=sw,enum=snp"`
	Alg         string   `json:"alg" cbor:"2,keyasint" jsonschema:"enum=EC256,enum=EC384,enum=EC521,enum=RSA2048,enum=RSA4096"`
	Cn          string   `json:"cn" cbor:"3,keyasint"`
	DNSNames    []string `json:"dnsNames,omitempty" cbor:"4,keyasint,omitempty"`
	IPAddresses []string `json:"ipAddresses,omitempty" cbor:"5,keyasint,omitempty"`
}

type TLSCreateResponse struct {
	Version string `json:"version" cbor:"0,keyasint"`
	KeyId   string `json:"keyId" cbor:"1,keyasint"`
}

type TLSSignRequest struct {
	Version string `json:"version" cbor:"0,keyasint"`
	KeyId   string `json:"keyId" cbor:"1,keyasint"`
	Content []byte `json:"content" cbor:"2,keyasint"`
	HashAlg string `json:"hashAlg" cbor:"3,keyasint" jsonschema:"enum=SHA-256,enum=SHA-384,enum=SHA-512"`
}

type TLSSignResponse struct {
	Version       string `json:"version" cbor:"0,keyasint"`
	SignedContent []byte `json:"signedContent" cbor:"1,keyasint"`
}

type TLSCertRequest struct {
	Version string `json:"version" cbor:"0,keyasint"`
	KeyId   string `json:"keyId" cbor:"1,keyasint"`
}

type TLSCertResponse struct {
	Version     string   `json:"version" cbor:"0,keyasint"`
	Certificate [][]byte `json:"certificate" cbor:"1,keyasint"`
}

type PeerCacheRequest struct {
	Version string `json:"version" cbor:"0,keyasint"`
	Peer    string `json:"peer" cbor:"1,keyasint"`
}

type PeerCacheResponse struct {
	Version string   `json:"version" cbor:"0,keyasint"`
	Cache   []string `json:"cache" cbor:"1,keyasint"`
}

type MeasureRequest struct {
	Version string       `json:"version" cbor:"0,keyasint"`
	Event   ar.Component `json:"event" cbor:"1,keyasint"`
}

type MeasureResponse struct {
	Version string `json:"version" cbor:"0,keyasint"`
	Success bool   `json:"success" cbor:"1,keyasint"`
}

type UpdateCertsRequest struct {
	Version string `json:"version" cbor:"0,keyasint"`
}

type UpdateCertsResponse struct {
	Version string `json:"version" cbor:"0,keyasint"`
	Success bool   `json:"success" cbor:"1,keyasint"`
}

type UpdateMetadataRequest struct {
	Version string `json:"version" cbor:"0,keyasint"`
}

type UpdateMetadataResponse struct {
	Version string `json:"version" cbor:"0,keyasint"`
	Success bool   `json:"success" cbor:"1,keyasint"`
}

type SocketError struct {
	Version string `json:"version" cbor:"0,keyasint"`
	Msg     string `json:"msg" cbor:"1,keyasint"`
}

const (
	// Set maximum message length for unix domain sockets to 10 MB
	MaxUnixMsgLen = 1024 * 1024 * 10
)

type PSSOptions struct {
	SaltLength int32
}

func TypeToString(t uint32) string {
	switch t {
	case TypeError:
		return "Error"
	case TypeAttest:
		return "Attest"
	case TypeVerify:
		return "Verify"
	case TypeTLSCreate:
		return "TLSCreate"
	case TypeTLSSign:
		return "TLSSign"
	case TypeTLSCert:
		return "TLSCert"
	case TypePeerCache:
		return "PeerCache"
	case TypeMeasure:
		return "Measure"
	case TypeUpdateCerts:
		return "UpdateCerts"
	case TypeUpdateMetadata:
		return "UpdateMetadata"
	default:
		return "Unknown"
	}
}

func checkVersion(version string) error {
	return nil
}

func (req *AttestationRequest) CheckVersion() error {
	return checkVersion(req.Version)
}

func (resp *AttestationResponse) CheckVersion() error {
	return checkVersion(resp.Version)
}

func (req *VerificationRequest) CheckVersion() error {
	return checkVersion(req.Version)
}

func (resp *VerificationResponse) CheckVersion() error {
	return checkVersion(resp.Version)
}

func (req *TLSCreateRequest) CheckVersion() error {
	return checkVersion(req.Version)
}

func (resp *TLSCreateResponse) CheckVersion() error {
	return checkVersion(resp.Version)
}

func (req *TLSSignRequest) CheckVersion() error {
	return checkVersion(req.Version)
}

func (resp *TLSSignResponse) CheckVersion() error {
	return checkVersion(resp.Version)
}

func (req *TLSCertRequest) CheckVersion() error {
	return checkVersion(req.Version)
}

func (resp *TLSCertResponse) CheckVersion() error {
	return checkVersion(resp.Version)
}

func (req *PeerCacheRequest) CheckVersion() error {
	return checkVersion(req.Version)
}

func (resp *PeerCacheResponse) CheckVersion() error {
	return checkVersion(resp.Version)
}

func (req *MeasureRequest) CheckVersion() error {
	return checkVersion(req.Version)
}

func (resp *MeasureResponse) CheckVersion() error {
	return checkVersion(resp.Version)
}

func (req *UpdateCertsRequest) CheckVersion() error {
	return checkVersion(req.Version)
}

func (resp *UpdateCertsResponse) CheckVersion() error {
	return checkVersion(resp.Version)
}

func (req *UpdateMetadataRequest) CheckVersion() error {
	return checkVersion(req.Version)
}

func (resp *UpdateMetadataResponse) CheckVersion() error {
	return checkVersion(resp.Version)
}

func (err *SocketError) CheckVersion() error {
	return checkVersion(err.Version)
}
