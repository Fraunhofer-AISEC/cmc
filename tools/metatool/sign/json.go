// Copyright (c) 2021 - 2026 Fraunhofer AISEC
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

package sign

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/go-jose/go-jose/v4"
)

type jsonSerializer struct{}

func (s jsonSerializer) sign(data []byte, signers []crypto.Signer, x5cs [][]*x509.Certificate) ([]byte, error) {
	return internal.SignJws(data, signers, x5cs)
}

// verify checks that signature i of the JWS verifies with key i over data, using the
// algorithms accepted by the attestation report verifier
func (s jsonSerializer) verify(signed, data []byte, keys []crypto.PublicKey) error {
	jws, err := jose.ParseSigned(string(signed), ar.JwsAlgorithms)
	if err != nil {
		return fmt.Errorf("failed to parse JWS: %w", err)
	}
	if len(jws.Signatures) != len(keys) {
		return fmt.Errorf("number of signatures (%v) does not match number of keys (%v)",
			len(jws.Signatures), len(keys))
	}
	for i, sig := range jws.Signatures {
		single := *jws
		single.Signatures = []jose.Signature{sig}
		payload, err := single.Verify(keys[i])
		if err != nil {
			return fmt.Errorf("failed to verify signature %v: %w", i, err)
		}
		if !bytes.Equal(payload, data) {
			return fmt.Errorf("payload of signature %v does not match input", i)
		}
	}
	return nil
}
