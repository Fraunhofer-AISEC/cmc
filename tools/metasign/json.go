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
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	log "github.com/sirupsen/logrus"
)

type JsonSerializer struct{}

func (s JsonSerializer) Sign(data []byte, keys []crypto.PrivateKey, x5cs [][]*x509.Certificate) ([]byte, error) {

	if len(keys) != len(x5cs) {
		return nil, fmt.Errorf("length of keys (%v) not equal to length of certificate chains (%v)", keys, x5cs)
	}

	var sig *jose.JSONWebSignature
	for i := range keys {

		var alg jose.SignatureAlgorithm
		switch keys[i].(type) {
		case *ecdsa.PrivateKey:
			log.Trace("Key type ECDSA")
			alg = jose.SignatureAlgorithm("ES256")
		case ed25519.PrivateKey:
			log.Trace("Key type EdDSA")
			alg = jose.SignatureAlgorithm("EdDSA")
		default:
			return nil, fmt.Errorf("key type %v not supported", keys[i])
		}
		log.Tracef("Using signature algorithm: %v", alg)

		var opts jose.SignerOptions
		key := jose.SigningKey{Algorithm: alg, Key: keys[i]}
		certchain := make([]string, 0)
		for _, cert := range x5cs[i] {
			certchain = append(certchain, base64.StdEncoding.EncodeToString(cert.Raw))
		}
		signer, err := jose.NewSigner(key, opts.WithHeader("x5c", certchain))
		if err != nil {
			return nil, fmt.Errorf("failed to create signer: %v", err)
		}
		if i == 0 {
			sig, err = signer.Sign(data)
			if err != nil {
				return nil, fmt.Errorf("failed to create signature: %v", err)
			}
		} else {
			s, err := signer.Sign(data)
			if err != nil {
				return nil, fmt.Errorf("failed to create signature: %v", err)
			}
			sig.Signatures = append(sig.Signatures, s.Signatures[0])
		}
	}

	output := sig.FullSerialize()
	return []byte(output), nil
}
