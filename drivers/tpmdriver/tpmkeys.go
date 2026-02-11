// Copyright (c) 2026 Fraunhofer AISEC
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

package tpmdriver

import (
	"crypto"
	"fmt"
	"io"
	"os"

	"github.com/Fraunhofer-AISEC/go-attestation/attest"
	// local modules
)

// Implements crypto.Signer
type TpmKey struct {
	marshalled []byte           // JSON struct with wrapped key
	public     crypto.PublicKey // Public key
	tpm        *Tpm             // Reference to the TPM
}

func NewKey(tpm *Tpm, alg string) (*TpmKey, error) {

	config, err := KeyAlgFromString(alg)
	if err != nil {
		return nil, err
	}

	tpm.mu.Lock()
	defer tpm.mu.Unlock()

	// Create the key
	key, err := tpm.tpm.NewKey(tpm.ak, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create new TPM key: %w", err)
	}
	// Some TPMs can only hold 3 keys, so we store them in marshalled form in memory and load them
	// when requested
	defer key.Close()

	data, err := key.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TPM key: %w", err)
	}

	tpmKey := &TpmKey{
		marshalled: data,
		public:     key.Public(),
		tpm:        tpm,
	}

	return tpmKey, nil
}

func ImportKey(tpm *Tpm, data []byte) (*TpmKey, error) {

	tpm.mu.Lock()
	defer tpm.mu.Unlock()

	key, err := tpm.tpm.LoadKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}
	// Some TPMs can only hold 3 keys, so we store them in marshalled form in memory and load them
	// when requested
	defer key.Close()

	tpmKey := &TpmKey{
		marshalled: data,
		public:     key.Public(),
		tpm:        tpm,
	}

	return tpmKey, nil

}

func (tpmKey *TpmKey) Public() crypto.PublicKey {
	return tpmKey.public
}

func (tpmKey *TpmKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	key, err := tpmKey.tpm.tpm.LoadKey(tpmKey.marshalled)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}
	defer key.Close()

	priv, err := key.Private(key.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	signature, err := priv.(crypto.Signer).Sign(rand, digest, opts)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (tpmKey *TpmKey) Export(path string) error {
	err := os.WriteFile(path, tpmKey.marshalled, 0644)
	if err != nil {
		return fmt.Errorf("failed to write marshalled key file: %w", err)
	}
	return nil
}

func (tpmKey *TpmKey) GetCertificationParameters() (attest.CertificationParameters, error) {
	key, err := tpmKey.tpm.tpm.LoadKey(tpmKey.marshalled)
	if err != nil {
		return attest.CertificationParameters{}, fmt.Errorf("failed to load key: %w", err)
	}
	defer key.Close()

	return key.CertificationParameters(), nil
}

func KeyAlgFromString(in string) (*attest.KeyConfig, error) {
	out := &attest.KeyConfig{}
	switch in {
	case "EC256":
		out.Algorithm = attest.ECDSA
		out.Size = 256
	case "EC384":
		out.Algorithm = attest.ECDSA
		out.Size = 384
	case "EC521":
		out.Algorithm = attest.ECDSA
		out.Size = 521
	case "RSA2048":
		out.Algorithm = attest.RSA
		out.Size = 2048
	case "RSA4096":
		out.Algorithm = attest.RSA
		out.Size = 4096
	default:
		return nil, fmt.Errorf("unsupported key algorithm %q", in)
	}

	return out, nil
}
