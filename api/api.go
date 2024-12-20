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

// Contains the API definitions for the CoAP and socket API.
// The gRPC API is in a separate file
package api

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// The version of the API
const (
	apiVersion = "1.0.0"
)

func GetVersion() string {
	return apiVersion
}

const (
	EndpointAttest    = "/Attest"
	EndpointVerify    = "/Verify"
	EndpointTLSSign   = "/TLSSign"
	EndpointTLSCert   = "/TLSCert"
	EndpointPeerCache = "/PeerCache"
	EndpointMeasure   = "/Measure"
)

const (
	TypeError     uint32 = 0
	TypeAttest    uint32 = 1
	TypeVerify    uint32 = 2
	TypeTLSSign   uint32 = 3
	TypeTLSCert   uint32 = 4
	TypePeerCache uint32 = 5
	TypeMeasure   uint32 = 6
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
	Ca          []byte            `json:"ca" cbor:"4,keyasint"`
	Peer        string            `json:"peer,omitempty" cbor:"5,keyasint,omitempty"`
	CacheMisses []string          `json:"cacheMisses,omitempty" cbor:"6,keyasint,omitempty"`
	Policies    []byte            `json:"policies,omitempty" cbor:"7,keyasint,omitempty"`
}

type VerificationResponse struct {
	Version string                `json:"version" cbor:"0,keyasint"`
	Result  ar.VerificationResult `json:"result" cbor:"1,keyasint"`
}

type TLSSignRequest struct {
	Version  string       `json:"version" cbor:"0,keyasint"`
	Content  []byte       `json:"content" cbor:"1,keyasint"`
	Hashtype HashFunction `json:"hashType" cbor:"2,keyasint"`
	PssOpts  *PSSOptions  `json:"pssOpts" cbor:"3,keyasint"`
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

type SocketError struct {
	Version string `json:"version" cbor:"0,keyasint"`
	Msg     string `json:"msg" cbor:"1,keyasint"`
}

const (
	// Set maximum message length to 10 MB
	MaxMsgLen = 1024 * 1024 * 10
)

type PSSOptions struct {
	SaltLength int32
}

type HashFunction int32

const (
	HashFunction_SHA1        HashFunction = 0
	HashFunction_SHA224      HashFunction = 1
	HashFunction_SHA256      HashFunction = 2
	HashFunction_SHA384      HashFunction = 3
	HashFunction_SHA512      HashFunction = 4
	HashFunction_MD4         HashFunction = 5
	HashFunction_MD5         HashFunction = 6
	HashFunction_MD5SHA1     HashFunction = 7
	HashFunction_RIPEMD160   HashFunction = 8
	HashFunction_SHA3_224    HashFunction = 9
	HashFunction_SHA3_256    HashFunction = 10
	HashFunction_SHA3_384    HashFunction = 11
	HashFunction_SHA3_512    HashFunction = 12
	HashFunction_SHA512_224  HashFunction = 13
	HashFunction_SHA512_256  HashFunction = 14
	HashFunction_BLAKE2s_256 HashFunction = 15
	HashFunction_BLAKE2b_256 HashFunction = 16
	HashFunction_BLAKE2b_384 HashFunction = 17
	HashFunction_BLAKE2b_512 HashFunction = 18
)

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
	default:
		return "Unknown"
	}
}

// Converts Protobuf hashtype to crypto.SignerOpts
func HashToSignerOpts(hashtype HashFunction, pssOpts *PSSOptions) (crypto.SignerOpts, error) {
	var hash crypto.Hash
	var len int
	switch hashtype {
	case HashFunction_SHA256:
		hash = crypto.SHA256
		len = 32
	case HashFunction_SHA384:
		hash = crypto.SHA384
		len = 48
	case HashFunction_SHA512:
		len = 64
		hash = crypto.SHA512
	default:
		return crypto.SHA512, fmt.Errorf("hash function not implemented: %v", hashtype)
	}
	if pssOpts != nil {
		saltlen := int(pssOpts.SaltLength)
		// go-attestation / go-tpm does not allow -1 as definition for length of hash
		if saltlen < 0 {
			saltlen = len
		}
		return &rsa.PSSOptions{SaltLength: saltlen, Hash: hash}, nil
	}
	return hash, nil
}

// Converts Hash Types from crypto.SignerOpts to the types specified in the CMC interface
func SignerOptsToHash(opts crypto.SignerOpts) (HashFunction, error) {
	switch opts.HashFunc() {
	case crypto.MD4:
		return HashFunction_MD4, nil
	case crypto.MD5:
		return HashFunction_MD5, nil
	case crypto.SHA1:
		return HashFunction_SHA1, nil
	case crypto.SHA224:
		return HashFunction_SHA224, nil
	case crypto.SHA256:
		return HashFunction_SHA256, nil
	case crypto.SHA384:
		return HashFunction_SHA384, nil
	case crypto.SHA512:
		return HashFunction_SHA512, nil
	case crypto.MD5SHA1:
		return HashFunction_MD5SHA1, nil
	case crypto.RIPEMD160:
		return HashFunction_RIPEMD160, nil
	case crypto.SHA3_224:
		return HashFunction_SHA3_224, nil
	case crypto.SHA3_256:
		return HashFunction_SHA3_256, nil
	case crypto.SHA3_384:
		return HashFunction_SHA3_384, nil
	case crypto.SHA3_512:
		return HashFunction_SHA3_512, nil
	case crypto.SHA512_224:
		return HashFunction_SHA512_224, nil
	case crypto.SHA512_256:
		return HashFunction_SHA512_256, nil
	case crypto.BLAKE2s_256:
		return HashFunction_BLAKE2s_256, nil
	case crypto.BLAKE2b_256:
		return HashFunction_BLAKE2b_256, nil
	case crypto.BLAKE2b_384:
		return HashFunction_BLAKE2b_384, nil
	case crypto.BLAKE2b_512:
		return HashFunction_BLAKE2b_512, nil
	default:
	}
	return HashFunction_SHA512, errors.New("could not determine correct Hash function")
}

func (req *AttestationRequest) CheckVersion() error {
	if req == nil {
		return fmt.Errorf("internal error: AttestationRequest is nil")
	}
	if !strings.EqualFold(apiVersion, req.Version) {
		return fmt.Errorf("API version mismatch. Expected AttestationRequest version %v, got %v", apiVersion, req.Version)
	}
	return nil
}

func (resp *AttestationResponse) CheckVersion() error {
	if resp == nil {
		return fmt.Errorf("internal error: AttestationResponse is nil")
	}
	if !strings.EqualFold(apiVersion, resp.Version) {
		return fmt.Errorf("API version mismatch. Expected AttestationResponse version %v, got %v", apiVersion, resp.Version)
	}
	return nil
}

func (req *VerificationRequest) CheckVersion() error {
	if req == nil {
		return fmt.Errorf("internal error: VerificationRequest is nil")
	}
	if !strings.EqualFold(apiVersion, req.Version) {
		return fmt.Errorf("API version mismatch. Expected VerificationRequest version %v, got %v", apiVersion, req.Version)
	}
	return nil
}

func (resp *VerificationResponse) CheckVersion() error {
	if resp == nil {
		return fmt.Errorf("internal error: VerificationResponse is nil")
	}
	if !strings.EqualFold(apiVersion, resp.Version) {
		return fmt.Errorf("API version mismatch. Expected VerificationResponse version %v, got %v", apiVersion, resp.Version)
	}
	return nil
}

func (req *TLSSignRequest) CheckVersion() error {
	if req == nil {
		return fmt.Errorf("internal error: TLSSignRequest is nil")
	}
	if !strings.EqualFold(apiVersion, req.Version) {
		return fmt.Errorf("API version mismatch. Expected TLSSignRequest version %v, got %v", apiVersion, req.Version)
	}
	return nil
}

func (resp *TLSSignResponse) CheckVersion() error {
	if resp == nil {
		return fmt.Errorf("internal error: TLSSignResponse is nil")
	}
	if !strings.EqualFold(apiVersion, resp.Version) {
		return fmt.Errorf("API version mismatch. Expected TLSSignResponse version %v, got %v", apiVersion, resp.Version)
	}
	return nil
}

func (req *TLSCertRequest) CheckVersion() error {
	if req == nil {
		return fmt.Errorf("internal error: TLSCertRequest is nil")
	}
	if !strings.EqualFold(apiVersion, req.Version) {
		return fmt.Errorf("API version mismatch. Expected TLSCertRequest version %v, got %v", apiVersion, req.Version)
	}
	return nil
}

func (resp *TLSCertResponse) CheckVersion() error {
	if resp == nil {
		return fmt.Errorf("internal error: TLSCertResponse is nil")
	}
	if !strings.EqualFold(apiVersion, resp.Version) {
		return fmt.Errorf("API version mismatch. Expected TLSCertResponse version %v, got %v", apiVersion, resp.Version)
	}
	return nil
}

func (req *PeerCacheRequest) CheckVersion() error {
	if req == nil {
		return fmt.Errorf("internal error: PeerCacheRequest is nil")
	}
	if !strings.EqualFold(apiVersion, req.Version) {
		return fmt.Errorf("API version mismatch. Expected PeerCacheRequest version %v, got %v", apiVersion, req.Version)
	}
	return nil
}

func (resp *PeerCacheResponse) CheckVersion() error {
	if resp == nil {
		return fmt.Errorf("internal error: PeerCacheResponse is nil")
	}
	if !strings.EqualFold(apiVersion, resp.Version) {
		return fmt.Errorf("API version mismatch. Expected PeerCacheResponse version %v, got %v", apiVersion, resp.Version)
	}
	return nil
}

func (req *MeasureRequest) CheckVersion() error {
	if req == nil {
		return fmt.Errorf("internal error: MeasureRequest is nil")
	}
	if !strings.EqualFold(apiVersion, req.Version) {
		return fmt.Errorf("API version mismatch. Expected MeasureRequest version %v, got %v", apiVersion, req.Version)
	}
	return nil
}

func (resp *MeasureResponse) CheckVersion() error {
	if resp == nil {
		return fmt.Errorf("internal error: MeasureResponse is nil")
	}
	if !strings.EqualFold(apiVersion, resp.Version) {
		return fmt.Errorf("API version mismatch. Expected MeasureResponse version %v, got %v", apiVersion, resp.Version)
	}
	return nil
}

func (err *SocketError) CheckVersion() error {
	if err == nil {
		return fmt.Errorf("internal error: SocketError is nil")
	}
	if !strings.EqualFold(apiVersion, err.Version) {
		return fmt.Errorf("API version mismatch. Expected SocketError version %v, got %v", apiVersion, err.Version)
	}
	return nil
}
