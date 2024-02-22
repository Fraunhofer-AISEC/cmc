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

// Contains the API definitions for the CoAP and unix domain socket API
// The gRPC API is in a separate file
package api

import (
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/fxamacker/cbor/v2"
	log "github.com/sirupsen/logrus"
)

type SocketError struct {
	Msg string `json:"msg" cbor:"0,keyasint"`
}

type AttestationRequest struct {
	Id    string `json:"id" cbor:"0,keyasint"`
	Nonce []byte `json:"nonce" nonce:"1,keyasint"`
}

type AttestationResponse struct {
	AttestationReport []byte `json:"attestationReport" cbor:"0,keyasint"`
}

type VerificationRequest struct {
	Nonce             []byte `json:"nonce" cbor:"0,keyasint"`
	AttestationReport []byte `json:"attestationReport" cbor:"1,keyasint"`
	Ca                []byte `json:"ca" cbor:"2,keyasint"`
	Policies          []byte `json:"policies" cbor:"3,keyasint"`
}

type VerificationResponse struct {
	VerificationResult []byte `json:"verificationResult" cbor:"0,keyasint"`
}

type TLSSignRequest struct {
	Id       string       `json:"id" cbor:"0,keyasint"`
	Content  []byte       `json:"content" cbor:"1,keyasint"`
	Hashtype HashFunction `json:"hashType" cbor:"2,keyasint"`
	PssOpts  *PSSOptions  `json:"pssOpts" cbor:"3,keyasint"`
}

type TLSSignResponse struct {
	SignedContent []byte `json:"signedContent" cbor:"0,keyasint"`
}

type TLSCertRequest struct {
	Id string `json:"id" cbor:"0,keyasint"`
}

type TLSCertResponse struct {
	Certificate [][]byte `json:"certificate" cbor:"0,keyasint"`
}

const (
	// Set maximum message length to 10 MB
	MaxMsgLen = 1024 * 1024 * 10
)

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

type PSSOptions struct {
	SaltLength int32
}

const (
	TypeError   uint32 = 0
	TypeAttest  uint32 = 1
	TypeVerify  uint32 = 2
	TypeTLSSign uint32 = 3
	TypeTLSCert uint32 = 4
)

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

// Receive receives data from a socket with the following format
//
//	Len uint32 -> Length of the payload to be sent
//	Type uint32 -> Type of the payload
//	payload []byte -> CBOR-encoded payload
func Receive(conn net.Conn) ([]byte, uint32, error) {

	err := conn.(*net.UnixConn).SetReadBuffer(MaxMsgLen)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to socket write buffer size %v", err)
	}

	// Read header
	buf := make([]byte, 8)

	log.Tracef("Reading header length %v", len(buf))

	n, err := conn.Read(buf)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read header: %w", err)
	}
	if n != 8 {
		return nil, 0, fmt.Errorf("read %v bytes (expected 8)", n)
	}

	// Decode header to get length and type
	payloadLen := binary.BigEndian.Uint32(buf[0:4])
	msgType := binary.BigEndian.Uint32(buf[4:8])

	if payloadLen > MaxMsgLen {
		return nil, 0, fmt.Errorf("cannot receive: payload size %v exceeds maximum size %v",
			payloadLen, MaxMsgLen)
	}

	log.Tracef("Decoded header. Expecting type %v, length %v", msgType, payloadLen)

	// Read payload
	payload := make([]byte, payloadLen)
	n, err = conn.Read(payload)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read payload: %w", err)
	}
	if uint32(n) != payloadLen {
		return nil, 0, fmt.Errorf("failed to read payload (received %v, expected %v bytes)",
			n, payloadLen)
	}

	if msgType == TypeError {
		resp := new(SocketError)
		err = cbor.Unmarshal(payload, resp)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to unmarshal error response")
		} else {
			return nil, 0, fmt.Errorf("server responded with error: %v", resp.Msg)
		}
	}

	return payload, msgType, nil
}

// Send sends data to a socket with the following format
//
//	Len uint32 -> Length of the payload to be sent
//	Type uint32 -> Type of the payload
//	payload []byte -> CBOR-encoded payload
func Send(conn net.Conn, payload []byte, t uint32) error {

	if len(payload) > MaxMsgLen {
		return fmt.Errorf("cannot send: payload size %v exceeds maximum size %v",
			len(payload), MaxMsgLen)
	}

	err := conn.(*net.UnixConn).SetWriteBuffer(MaxMsgLen)
	if err != nil {
		return fmt.Errorf("failed to socket write buffer size %v", err)
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(buf[4:8], t)

	log.Tracef("Sending header length %v", len(buf))

	n, err := conn.Write(buf)
	if err != nil {
		return fmt.Errorf("failed to send header: %w", err)
	}
	if n != len(buf) {
		return fmt.Errorf("could only send %v of %v bytes", n, len(buf))
	}

	log.Tracef("Sending payload type %v length %v", t, uint32(len(payload)))

	n, err = conn.Write(payload)
	if err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}
	if n != len(payload) {
		return fmt.Errorf("could only send %v of %v bytes", n, len(payload))
	}

	return nil
}

func SendError(conn net.Conn, format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	log.Warn(msg)
	resp := &SocketError{
		Msg: msg,
	}
	payload, err := cbor.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal error response: %v", err)
	}

	return Send(conn, payload, TypeError)
}
