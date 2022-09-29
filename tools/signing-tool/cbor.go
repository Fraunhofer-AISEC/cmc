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

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/veraison/go-cose"
)

type CborSerializer struct{}

func (s CborSerializer) Sign(data []byte, keys []crypto.PrivateKey, x5cs [][]*x509.Certificate) ([]byte, error) {

	if len(keys) != len(x5cs) {
		return nil, fmt.Errorf("length of keys (%v) not equal to length of certificate chains (%v)", keys, x5cs)
	}

	// TODO cryptographic agility
	alg := cose.AlgorithmES256

	// create message to be signed
	msg := cose.NewSignMessage()
	msg.Payload = data

	signers := make([]cose.Signer, 0)
	for i := range keys {
		// create signer TODO cryptographic agility
		signer, err := cose.NewSigner(alg, keys[i].(*ecdsa.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to create signer: %v", err)
		}
		signers = append(signers, signer)

		// Get certificate chain
		certchain := make([][]byte, 0)
		for _, cert := range x5cs[i] {
			certchain = append(certchain, cert.Raw)
		}

		// create a signature holder
		sigHolder := cose.NewSignature()
		sigHolder.Headers.Protected.SetAlgorithm(alg)
		// https://datatracker.ietf.org/doc/draft-ietf-cose-x509/08/ section 2
		// If multiple certificates are conveyed, a CBOR array of byte strings is used,
		// with each certificate being in its own byte string (DER Encoded)
		sigHolder.Headers.Unprotected[cose.HeaderLabelX5Chain] = certchain

		msg.Signatures = append(msg.Signatures, sigHolder)
	}

	err := msg.Sign(rand.Reader, nil, signers...)
	if err != nil {
		return nil, fmt.Errorf("failed to sign cbor object: %v", err)
	}

	coseRaw, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cbor object: %v", err)
	}

	return coseRaw, nil
}
