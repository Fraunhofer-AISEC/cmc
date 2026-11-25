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

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/veraison/go-cose"
)

type cborSerializer struct{}

func (s cborSerializer) sign(data []byte, signers []crypto.Signer, x5cs [][]*x509.Certificate) ([]byte, error) {
	return internal.SignCose(data, signers, x5cs)
}

// verify checks that signature i of the COSE_Sign message verifies with key i over data
func (s cborSerializer) verify(signed, data []byte, keys []crypto.PublicKey) error {
	var msg cose.SignMessage
	if err := msg.UnmarshalCBOR(signed); err != nil {
		return fmt.Errorf("failed to unmarshal COSE message: %w", err)
	}
	if len(msg.Signatures) != len(keys) {
		return fmt.Errorf("number of signatures (%v) does not match number of keys (%v)",
			len(msg.Signatures), len(keys))
	}
	if !bytes.Equal(msg.Payload, data) {
		return fmt.Errorf("payload does not match input")
	}
	verifiers := make([]cose.Verifier, 0, len(keys))
	for i, sig := range msg.Signatures {
		alg, err := sig.Headers.Protected.Algorithm()
		if err != nil {
			return fmt.Errorf("failed to get algorithm of signature %v: %w", i, err)
		}
		v, err := cose.NewVerifier(alg, keys[i])
		if err != nil {
			return fmt.Errorf("failed to create verifier for signature %v: %w", i, err)
		}
		verifiers = append(verifiers, v)
	}
	if err := msg.Verify(nil, verifiers...); err != nil {
		return fmt.Errorf("failed to verify signatures: %w", err)
	}
	return nil
}
