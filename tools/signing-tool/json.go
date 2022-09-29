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
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"gopkg.in/square/go-jose.v2"
)

type JsonSerializer struct{}

func (s JsonSerializer) Sign(data []byte, keys []crypto.PrivateKey, x5cs [][]*x509.Certificate) ([]byte, error) {

	if len(keys) != len(x5cs) {
		return nil, fmt.Errorf("length of keys (%v) not equal to length of certificate chains (%v)", keys, x5cs)
	}

	// TODO cryptographic agility
	alg := jose.SignatureAlgorithm("ES256")

	var sig *jose.JSONWebSignature
	for i := range keys {
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
