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
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/fxamacker/cbor/v2"
)

type serializer interface {
	sign(data []byte, signers []crypto.Signer, x5cs [][]*x509.Certificate) ([]byte, error)
	verify(signed, data []byte, keys []crypto.PublicKey) error
}

// Sign signs data with the PEM encoded private keys and certificate chains
func Sign(data []byte, keysPem [][]byte, chainsPem [][][]byte) ([]byte, error) {

	signers := make([]crypto.Signer, 0, len(keysPem))
	for i, keyPem := range keysPem {
		key, err := internal.ParsePrivateKey(keyPem)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key %v: %w", i, err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("private key %v of type %T cannot sign", i, key)
		}
		signers = append(signers, signer)
	}
	log.Tracef("Read %v private keys", len(signers))

	certChains := make([][]*x509.Certificate, 0, len(chainsPem))
	for i, chainPem := range chainsPem {
		certChain := make([]*x509.Certificate, 0, len(chainPem))
		for _, certPem := range chainPem {
			c, err := internal.ParseCert(certPem)
			if err != nil {
				return nil, fmt.Errorf("failed to load certificates: %w", err)
			}
			certChain = append(certChain, c)
		}
		if len(certChain) == 0 {
			return nil, fmt.Errorf("certificate chain %v is empty", i)
		}
		certChains = append(certChains, certChain)
	}
	log.Tracef("Read %v certificate chains", len(certChains))

	return signWith(data, signers, certChains)
}

// signWith signs data with arbitrary signers, e.g. keys held in a KMS or HSM. Each signer must
// match the leaf certificate of its chain. The signed output is verified before it is returned.
func signWith(data []byte, signers []crypto.Signer, certChains [][]*x509.Certificate) ([]byte, error) {

	if len(signers) == 0 {
		return nil, errors.New("no valid keys specified")
	}
	if len(certChains) != len(signers) {
		return nil, fmt.Errorf("number of certificate chains (%v) does not match number of keys (%v)",
			len(certChains), len(signers))
	}

	leafKeys := make([]crypto.PublicKey, 0, len(signers))
	for i, signer := range signers {
		if len(certChains[i]) == 0 {
			return nil, fmt.Errorf("certificate chain %v is empty", i)
		}
		leaf := certChains[i][0]
		pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
		if !ok || !pub.Equal(leaf.PublicKey) {
			return nil, fmt.Errorf("key %v does not match public key of leaf certificate %q",
				i, leaf.Subject.CommonName)
		}
		leafKeys = append(leafKeys, leaf.PublicKey)
	}

	// Detect serialization format. Currently, JSON and CBOR are supported
	var s serializer
	if json.Valid(data) {
		log.Trace("Detected JSON serialization")
		s = jsonSerializer{}
	} else if err := cbor.Wellformed(data); err == nil {
		log.Trace("Detected CBOR serialization")
		s = cborSerializer{}
	} else {
		return nil, errors.New("failed to detect serialization (only JSON and CBOR are supported)")
	}

	signedData, err := s.sign(data, signers, certChains)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	if err := s.verify(signedData, data, leafKeys); err != nil {
		return nil, fmt.Errorf("failed to verify signed data: %w", err)
	}

	log.Trace("Signed and verified metadata")

	return signedData, nil
}

func LoadKeys(keyFiles string) ([][]byte, error) {
	keysPem := make([][]byte, 0)
	for keyFile := range strings.SplitSeq(keyFiles, ",") {
		k, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %v: %w", keyFile, err)
		}
		keysPem = append(keysPem, k)
	}
	return keysPem, nil
}

func LoadCertChains(x5cFiles string) ([][][]byte, error) {
	certChainsPem := make([][][]byte, 0)
	for chain := range strings.SplitSeq(x5cFiles, ":") {
		certChainPem := make([][]byte, 0)
		for certFile := range strings.SplitSeq(chain, ",") {
			certPem, err := os.ReadFile(certFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read certificate file %v: %w", certFile, err)
			}
			certChainPem = append(certChainPem, certPem)
		}
		certChainsPem = append(certChainsPem, certChainPem)
	}
	return certChainsPem, nil
}
