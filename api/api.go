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
	"crypto"
	"crypto/rsa"
	"fmt"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// The version of the API
const (
	apiVersion = "1.3.0"
)

func GetVersion() string {
	return apiVersion
}

const (
	EndpointAttest         = "/Attest"
	EndpointVerify         = "/Verify"
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
	TypeTLSSign        uint32 = 3
	TypeTLSCert        uint32 = 4
	TypePeerCache      uint32 = 5
	TypeMeasure        uint32 = 6
	TypeUpdateCerts    uint32 = 7
	TypeUpdateMetadata uint32 = 8
)

type AttestationRequest struct {
	Version string   `json:"version" cbor:"0,keyasint"`
	Nonce   []byte   `json:"nonce" cbor:"1,keyasint"`
	Cached  []string `json:"cached,omitempty" cbor:"2,keyasint,omitempty"`
}

type AttestationResponse struct {
	Version     string            `json:"version" cbor:"0,keyasint"`
	Report      []byte            `json:"report" cbor:"1,keyasint"`
	Metadata    map[string][]byte `json:"metadata,omitempty" cbor:"2,keyasint,omitempty"`
	CacheMisses []string          `json:"cacheMisses,omitempty" cbor:"3,keyasint,omitempty"`
}

type VerificationRequest struct {
	Version     string            `json:"version" cbor:"0,keyasint"`
	Nonce       []byte            `json:"nonce" cbor:"1,keyasint"`
	Report      []byte            `json:"report" cbor:"2,keyasint"`
	Metadata    map[string][]byte `json:"metadata,omitempty" cbor:"3,keyasint,omitempty"`
	Peer        string            `json:"peer,omitempty" cbor:"6,keyasint,omitempty"`
	CacheMisses []string          `json:"cacheMisses,omitempty" cbor:"7,keyasint,omitempty"`
	Policies    []byte            `json:"policies,omitempty" cbor:"8,keyasint,omitempty"`
}

type VerificationResponse struct {
	Version string                `json:"version" cbor:"0,keyasint"`
	Result  ar.VerificationResult `json:"result" cbor:"1,keyasint"`
}

type TLSSignRequest struct {
	Version string      `json:"version" cbor:"0,keyasint"`
	Content []byte      `json:"content" cbor:"1,keyasint"`
	HashAlg string      `json:"hashAlg" cbor:"2,keyasint" jsonschema:"enum=SHA-256,enum=SHA-384,enum=SHA-512"`
	PssOpts *PSSOptions `json:"pssOpts,omitempty" cbor:"3,keyasint,omitempty"`
}

type TLSSignResponse struct {
	Version       string `json:"version" cbor:"0,keyasint"`
	SignedContent []byte `json:"signedContent" cbor:"1,keyasint"`
}

type TLSCertRequest struct {
	Version string `json:"version" cbor:"0,keyasint"`
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
	Version string          `json:"version" cbor:"0,keyasint"`
	Event   ar.MeasureEvent `json:"event" cbor:"1,keyasint"`
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
	case TypeMeasure:
		return "Measure"
	case TypeTLSSign:
		return "TLSSign"
	case TypeTLSCert:
		return "TLSCert"
	case TypePeerCache:
		return "PeerCache"
	case TypeUpdateCerts:
		return "UpdateCerts"
	case TypeUpdateMetadata:
		return "UpdateMetadata"
	default:
		return "Unknown"
	}
}

// StringToSignerOpts converts hash strings as defined in https://pkg.go.dev/crypto#Hash.String
// to SignerOpts
// Converts hash strings as defined in https://pkg.go.dev/crypto#Hash.String to SignerOpts
func StringToSignerOpts(s string, pssOpts *PSSOptions) (crypto.SignerOpts, error) {
	hash, err := internal.HashFromString(s)
	if err != nil {
		return nil, err
	}
	return HashToSignerOpts(hash, pssOpts)
}

// HashToSignerOpts converts hashes to crypto.SignerOpts
func HashToSignerOpts(hash crypto.Hash, pssOpts *PSSOptions) (crypto.SignerOpts, error) {
	if pssOpts != nil {
		saltlen := int(pssOpts.SaltLength)
		// go-attestation / go-tpm does not allow -1 as definition for length of hash
		if saltlen < 0 {
			saltlen = hash.Size()
		}
		return &rsa.PSSOptions{SaltLength: saltlen, Hash: hash}, nil
	}
	return hash, nil
}

func (req *AttestationRequest) CheckVersion() error {
	if req == nil {
		return fmt.Errorf("internal error: AttestationRequest is nil")
	}
	if !strings.EqualFold(apiVersion, req.Version) {
		return fmt.Errorf("API version mismatch. Expected AttestationRequest version %q, got %q", apiVersion, req.Version)
	}
	return nil
}

func (resp *AttestationResponse) CheckVersion() error {
	if resp == nil {
		return fmt.Errorf("internal error: AttestationResponse is nil")
	}
	if !strings.EqualFold(apiVersion, resp.Version) {
		return fmt.Errorf("API version mismatch. Expected AttestationResponse version %q, got %q", apiVersion, resp.Version)
	}
	return nil
}

func (req *VerificationRequest) CheckVersion() error {
	if req == nil {
		return fmt.Errorf("internal error: VerificationRequest is nil")
	}
	if !strings.EqualFold(apiVersion, req.Version) {
		return fmt.Errorf("API version mismatch. Expected VerificationRequest version %q, got %q", apiVersion, req.Version)
	}
	return nil
}

func (resp *VerificationResponse) CheckVersion() error {
	if resp == nil {
		return fmt.Errorf("internal error: VerificationResponse is nil")
	}
	if !strings.EqualFold(apiVersion, resp.Version) {
		return fmt.Errorf("API version mismatch. Expected VerificationResponse version %q, got %q", apiVersion, resp.Version)
	}
	return nil
}

func (req *TLSSignRequest) CheckVersion() error {
	if req == nil {
		return fmt.Errorf("internal error: TLSSignRequest is nil")
	}
	if !strings.EqualFold(apiVersion, req.Version) {
		return fmt.Errorf("API version mismatch. Expected TLSSignRequest version %q, got %q", apiVersion, req.Version)
	}
	return nil
}

func (resp *TLSSignResponse) CheckVersion() error {
	if resp == nil {
		return fmt.Errorf("internal error: TLSSignResponse is nil")
	}
	if !strings.EqualFold(apiVersion, resp.Version) {
		return fmt.Errorf("API version mismatch. Expected TLSSignResponse version %q, got %q", apiVersion, resp.Version)
	}
	return nil
}

func (req *TLSCertRequest) CheckVersion() error {
	if req == nil {
		return fmt.Errorf("internal error: TLSCertRequest is nil")
	}
	if !strings.EqualFold(apiVersion, req.Version) {
		return fmt.Errorf("API version mismatch. Expected TLSCertRequest version %q, got %q", apiVersion, req.Version)
	}
	return nil
}

func (resp *TLSCertResponse) CheckVersion() error {
	if resp == nil {
		return fmt.Errorf("internal error: TLSCertResponse is nil")
	}
	if !strings.EqualFold(apiVersion, resp.Version) {
		return fmt.Errorf("API version mismatch. Expected TLSCertResponse version %q, got %q", apiVersion, resp.Version)
	}
	return nil
}

func (req *PeerCacheRequest) CheckVersion() error {
	if req == nil {
		return fmt.Errorf("internal error: PeerCacheRequest is nil")
	}
	if !strings.EqualFold(apiVersion, req.Version) {
		return fmt.Errorf("API version mismatch. Expected PeerCacheRequest version %q, got %q", apiVersion, req.Version)
	}
	return nil
}

func (resp *PeerCacheResponse) CheckVersion() error {
	if resp == nil {
		return fmt.Errorf("internal error: PeerCacheResponse is nil")
	}
	if !strings.EqualFold(apiVersion, resp.Version) {
		return fmt.Errorf("API version mismatch. Expected PeerCacheResponse version %q, got %q", apiVersion, resp.Version)
	}
	return nil
}

func (req *MeasureRequest) CheckVersion() error {
	if req == nil {
		return fmt.Errorf("internal error: MeasureRequest is nil")
	}
	if !strings.EqualFold(apiVersion, req.Version) {
		return fmt.Errorf("API version mismatch. Expected MeasureRequest version %q, got %q", apiVersion, req.Version)
	}
	return nil
}

func (resp *MeasureResponse) CheckVersion() error {
	if resp == nil {
		return fmt.Errorf("internal error: MeasureResponse is nil")
	}
	if !strings.EqualFold(apiVersion, resp.Version) {
		return fmt.Errorf("API version mismatch. Expected MeasureResponse version %q, got %q", apiVersion, resp.Version)
	}
	return nil
}

func (req *UpdateCertsRequest) CheckVersion() error {
	if req == nil {
		return fmt.Errorf("internal error: UpdateCertsRequest is nil")
	}
	if !strings.EqualFold(apiVersion, req.Version) {
		return fmt.Errorf("API version mismatch. Expected UpdateCertsRequest version %q, got %q", apiVersion, req.Version)
	}
	return nil
}

func (resp *UpdateCertsResponse) CheckVersion() error {
	if resp == nil {
		return fmt.Errorf("internal error: UpdateCertsResponse is nil")
	}
	if !strings.EqualFold(apiVersion, resp.Version) {
		return fmt.Errorf("API version mismatch. Expected UpdateCertsResponse version %q, got %q", apiVersion, resp.Version)
	}
	return nil
}

func (req *UpdateMetadataRequest) CheckVersion() error {
	if req == nil {
		return fmt.Errorf("internal error: UpdateMetadataRequest is nil")
	}
	if !strings.EqualFold(apiVersion, req.Version) {
		return fmt.Errorf("API version mismatch. Expected UpdateMetadataRequest version %q, got %q", apiVersion, req.Version)
	}
	return nil
}

func (resp *UpdateMetadataResponse) CheckVersion() error {
	if resp == nil {
		return fmt.Errorf("internal error: UpdateMetadataResponse is nil")
	}
	if !strings.EqualFold(apiVersion, resp.Version) {
		return fmt.Errorf("API version mismatch. Expected UpdateMetadataResponse version %q, got %q", apiVersion, resp.Version)
	}
	return nil
}

func (err *SocketError) CheckVersion() error {
	if err == nil {
		return fmt.Errorf("internal error: SocketError is nil")
	}
	if !strings.EqualFold(apiVersion, err.Version) {
		return fmt.Errorf("API version mismatch. Expected SocketError version %q, got %q", apiVersion, err.Version)
	}
	return nil
}
