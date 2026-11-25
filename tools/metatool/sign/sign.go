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
	"io"
	"os"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
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

	certChains, err := parseCertChains(chainsPem)
	if err != nil {
		return nil, err
	}

	return signWith(data, signers, certChains)
}

// Tbs holds what an external signer has to sign for one signature
type Tbs struct {
	// Data is the exact byte string to be signed (JWS signing input or COSE Sig_structure)
	Data []byte
	// Digest is the hash of Data under the signature algorithm, nil for Ed25519
	Digest []byte
}

// Prepare returns the to-be-signed data for each certificate chain, so that the signatures can be
// created outside of metatool and added with Attach. The signature algorithm is derived from the
// public key of the leaf certificate.
func Prepare(data []byte, chainsPem [][][]byte) ([]Tbs, error) {

	certChains, err := parseCertChains(chainsPem)
	if err != nil {
		return nil, err
	}

	recorders := make([]*internal.TbsRecorder, 0, len(certChains))
	signers := make([]crypto.Signer, 0, len(certChains))
	for _, chain := range certChains {
		r := &internal.TbsRecorder{Key: chain[0].PublicKey}
		recorders = append(recorders, r)
		signers = append(signers, r)
	}

	s, err := detectSerializer(data)
	if err != nil {
		return nil, err
	}
	if _, err := s.sign(data, signers, certChains); err != nil {
		return nil, fmt.Errorf("failed to prepare data: %w", err)
	}

	tbs := make([]Tbs, 0, len(recorders))
	for i, r := range recorders {
		h, err := hashFromPublicKey(r.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to get hash algorithm for signer %v: %w", i, err)
		}
		t := Tbs{Data: r.Tbs}
		if h != 0 {
			hasher := h.New()
			hasher.Write(r.Tbs)
			t.Digest = hasher.Sum(nil)
		}
		tbs = append(tbs, t)
	}

	return tbs, nil
}

// Attach creates the signed output from data, the certificate chains and the signatures created
// over the output of Prepare. ECDSA signatures must be ASN.1 DER encoded. The inputs must be
// identical to the ones passed to Prepare.
func Attach(data []byte, signatures [][]byte, chainsPem [][][]byte) ([]byte, error) {

	certChains, err := parseCertChains(chainsPem)
	if err != nil {
		return nil, err
	}
	if len(signatures) != len(certChains) {
		return nil, fmt.Errorf("number of signatures (%v) does not match number of certificate chains (%v)",
			len(signatures), len(certChains))
	}

	signers := make([]crypto.Signer, 0, len(signatures))
	for i, sig := range signatures {
		signers = append(signers, detachedSigner{pub: certChains[i][0].PublicKey, sig: sig})
	}

	return signWith(data, signers, certChains)
}

// detachedSigner returns a signature that was created outside of metatool. As crypto.Signer
// returns ASN.1 DER for ECDSA, the JWS and COSE libraries convert it to the raw format.
type detachedSigner struct {
	pub crypto.PublicKey
	sig []byte
}

func (s detachedSigner) Public() crypto.PublicKey {
	return s.pub
}

func (s detachedSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return s.sig, nil
}

// hashFromPublicKey returns the hash of the signature algorithm for the key, which is the same for
// JWS and COSE, or 0 for Ed25519
func hashFromPublicKey(pub crypto.PublicKey) (crypto.Hash, error) {
	alg, err := internal.CoseAlgFromPublicKey(pub)
	if err != nil {
		return 0, err
	}
	switch alg {
	case cose.AlgorithmES256, cose.AlgorithmPS256:
		return crypto.SHA256, nil
	case cose.AlgorithmES384, cose.AlgorithmPS384:
		return crypto.SHA384, nil
	case cose.AlgorithmES512, cose.AlgorithmPS512:
		return crypto.SHA512, nil
	case cose.AlgorithmEdDSA:
		return 0, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm %v", alg)
	}
}

func parseCertChains(chainsPem [][][]byte) ([][]*x509.Certificate, error) {
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
	return certChains, nil
}

// detectSerializer detects the serialization format. Currently, JSON and CBOR are supported
func detectSerializer(data []byte) (serializer, error) {
	if json.Valid(data) {
		log.Trace("Detected JSON serialization")
		return jsonSerializer{}, nil
	}
	if err := cbor.Wellformed(data); err == nil {
		log.Trace("Detected CBOR serialization")
		return cborSerializer{}, nil
	}
	return nil, errors.New("failed to detect serialization (only JSON and CBOR are supported)")
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

	s, err := detectSerializer(data)
	if err != nil {
		return nil, err
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

// LoadFiles reads the comma-separated list of files
func LoadFiles(files string) ([][]byte, error) {
	contents := make([][]byte, 0)
	for file := range strings.SplitSeq(files, ",") {
		c, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %v: %w", file, err)
		}
		contents = append(contents, c)
	}
	return contents, nil
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
