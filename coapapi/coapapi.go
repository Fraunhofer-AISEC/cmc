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

package coapapi

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
)

type AttestationRequest struct {
	Id    string
	Nonce []byte
}

type AttestationResponse struct {
	AttestationReport []byte
}

type VerificationRequest struct {
	Nonce             []byte
	AttestationReport []byte
	Ca                []byte
	Policies          []byte
}

type VerificationResponse struct {
	VerificationResult []byte
}

type TLSSignRequest struct {
	Id       string
	Content  []byte
	Hashtype HashFunction
	PssOpts  *PSSOptions
}

type TLSSignResponse struct {
	SignedContent []byte
}

type TLSCertRequest struct {
	Id string
}

type TLSCertResponse struct {
	Certificate [][]byte
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

type PSSOptions struct {
	SaltLength int32
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
