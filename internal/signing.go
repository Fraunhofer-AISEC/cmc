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

package internal

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/veraison/go-cose"
)

// Sign signs data with a single key and an optional certificate chain
func Sign(data []byte, priv crypto.PrivateKey, serializer string,
	certChain []*x509.Certificate,
) ([]byte, error) {
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("signing key of type %T is not a crypto.Signer", priv)
	}
	chains := [][]*x509.Certificate{certChain}
	switch serializer {
	case "JSON":
		return SignJws(data, []crypto.Signer{signer}, chains)
	case "CBOR":
		return SignCose(data, []crypto.Signer{signer}, chains)
	default:
		return nil, fmt.Errorf("unknown serializer %v", serializer)
	}
}

// TbsRecorder can be passed to SignJws and SignCose in place of a signer to obtain the bytes to be
// signed instead of a signature, e.g. to sign them with an external tool. It records the JWS
// signing input or the COSE Sig_structure in Tbs. The resulting signature is a placeholder, so the
// output of SignJws and SignCose is not valid.
type TbsRecorder struct {
	Key crypto.PublicKey
	Tbs []byte
}

func (r *TbsRecorder) Public() crypto.PublicKey {
	return r.Key
}

func (r *TbsRecorder) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("TbsRecorder can only be used with SignJws and SignCose")
}

var placeholderSignature = []byte{0}

// jwsRecorder implements jose.OpaqueSigner, which receives the JWS signing input
type jwsRecorder struct {
	r   *TbsRecorder
	alg jose.SignatureAlgorithm
}

func (j jwsRecorder) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{Key: j.r.Key}
}

func (j jwsRecorder) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{j.alg}
}

func (j jwsRecorder) SignPayload(payload []byte, _ jose.SignatureAlgorithm) ([]byte, error) {
	j.r.Tbs = bytes.Clone(payload)
	return placeholderSignature, nil
}

// coseRecorder implements cose.Signer, which receives the Sig_structure
type coseRecorder struct {
	r   *TbsRecorder
	alg cose.Algorithm
}

func (c coseRecorder) Algorithm() cose.Algorithm {
	return c.alg
}

func (c coseRecorder) Sign(_ io.Reader, content []byte) ([]byte, error) {
	c.r.Tbs = bytes.Clone(content)
	return placeholderSignature, nil
}

// SignJws creates a JSON Web Signature with one signature per signer. Each signature carries the
// corresponding certificate chain in its x5c header if the chain is not empty. The signature
// algorithm is derived from the public key of each signer. Signers may be TbsRecorders.
func SignJws(data []byte, signers []crypto.Signer, certChains [][]*x509.Certificate,
) ([]byte, error) {
	if len(signers) == 0 {
		return nil, errors.New("no signers specified")
	}
	if len(signers) != len(certChains) {
		return nil, fmt.Errorf("number of signers (%v) does not match number of certificate chains (%v)",
			len(signers), len(certChains))
	}

	log.Tracef("Signing JSON data length %v with %v signers...", len(data), len(signers))

	var jws *jose.JSONWebSignature
	for i, signer := range signers {
		alg, err := JwsAlgFromPublicKey(signer.Public())
		if err != nil {
			return nil, fmt.Errorf("failed to get JWS algorithm for signer %v: %w", i, err)
		}
		log.Tracef("Chosen JWS signature algorithm for signer %v: %v", i, alg)

		certsb64 := make([]string, 0, len(certChains[i]))
		for _, cert := range certChains[i] {
			certsb64 = append(certsb64, base64.StdEncoding.EncodeToString(cert.Raw))
		}
		opts := &jose.SignerOptions{}
		if len(certsb64) > 0 {
			opts.WithHeader("x5c", certsb64)
		}

		var key jose.OpaqueSigner = cryptosigner.Opaque(signer)
		if r, ok := signer.(*TbsRecorder); ok {
			key = jwsRecorder{r: r, alg: alg}
		}
		joseSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to create signer %v: %w", i, err)
		}

		obj, err := joseSigner.Sign(data)
		if err != nil {
			return nil, fmt.Errorf("failed to sign with signer %v: %w", i, err)
		}
		if jws == nil {
			jws = obj
		} else {
			jws.Signatures = append(jws.Signatures, obj.Signatures...)
		}
	}
	log.Trace("Signing finished")

	return []byte(jws.FullSerialize()), nil
}

// SignCose creates a COSE_Sign message with one signature per signer. Each signature carries the
// corresponding certificate chain in its x5chain header if the chain is not empty. The signature
// algorithm is derived from the public key of each signer. Signers may be TbsRecorders.
func SignCose(data []byte, signers []crypto.Signer, certChains [][]*x509.Certificate,
) ([]byte, error) {
	if len(signers) == 0 {
		return nil, errors.New("no signers specified")
	}
	if len(signers) != len(certChains) {
		return nil, fmt.Errorf("number of signers (%v) does not match number of certificate chains (%v)",
			len(signers), len(certChains))
	}

	log.Tracef("Signing CBOR data length %v with %v signers...", len(data), len(signers))

	msg := cose.NewSignMessage()
	msg.Payload = data

	coseSigners := make([]cose.Signer, 0, len(signers))
	for i, signer := range signers {
		alg, err := CoseAlgFromPublicKey(signer.Public())
		if err != nil {
			return nil, fmt.Errorf("failed to get COSE algorithm for signer %v: %w", i, err)
		}
		log.Tracef("Chosen COSE signature algorithm for signer %v: %v", i, alg)

		var coseSigner cose.Signer
		if r, ok := signer.(*TbsRecorder); ok {
			coseSigner = coseRecorder{r: r, alg: alg}
		} else {
			coseSigner, err = cose.NewSigner(alg, signer)
			if err != nil {
				return nil, fmt.Errorf("failed to create signer %v: %w", i, err)
			}
		}
		coseSigners = append(coseSigners, coseSigner)

		sigHolder := cose.NewSignature()
		sigHolder.Headers.Protected.SetAlgorithm(alg)
		if len(certChains[i]) > 0 {
			// https://datatracker.ietf.org/doc/draft-ietf-cose-x509/08/ section 2
			// If multiple certificates are conveyed, a CBOR array of byte strings is used,
			// with each certificate being in its own byte string (DER Encoded)
			certChainRaw := make([][]byte, 0, len(certChains[i]))
			for _, cert := range certChains[i] {
				certChainRaw = append(certChainRaw, cert.Raw)
			}
			sigHolder.Headers.Unprotected[cose.HeaderLabelX5Chain] = certChainRaw
		}
		msg.Signatures = append(msg.Signatures, sigHolder)
	}

	err := msg.Sign(rand.Reader, nil, coseSigners...)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w. len(data): %v", err, len(data))
	}

	coseRaw, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cbor object: %w", err)
	}

	log.Trace("Signing finished")

	return coseRaw, nil
}

// JwsAlgFromPublicKey deduces the JWS signature algorithm from the public key of the signer.
// RSA uses RSASSA-PSS with a hash matching the security level of the key size.
func JwsAlgFromPublicKey(pub crypto.PublicKey) (jose.SignatureAlgorithm, error) {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		switch key.Size() {
		case 256:
			return jose.PS256, nil
		case 384:
			return jose.PS384, nil
		case 512:
			return jose.PS512, nil
		default:
			return "", fmt.Errorf("unsupported RSA key size: %v bits", key.Size()*8)
		}
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		default:
			return "", fmt.Errorf("unsupported elliptic curve: %v", key.Curve.Params().Name)
		}
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	default:
		return "", fmt.Errorf("unsupported key type %T", pub)
	}
}

// CoseAlgFromPublicKey deduces the COSE signature algorithm from the public key of the signer.
// RSA uses RSASSA-PSS with a hash matching the security level of the key size.
func CoseAlgFromPublicKey(pub crypto.PublicKey) (cose.Algorithm, error) {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		switch key.Size() {
		case 256:
			return cose.AlgorithmPS256, nil
		case 384:
			return cose.AlgorithmPS384, nil
		case 512:
			return cose.AlgorithmPS512, nil
		default:
			return cose.AlgorithmReserved, fmt.Errorf("unsupported RSA key size: %v bits", key.Size()*8)
		}
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return cose.AlgorithmES256, nil
		case elliptic.P384():
			return cose.AlgorithmES384, nil
		case elliptic.P521():
			return cose.AlgorithmES512, nil
		default:
			return cose.AlgorithmReserved, fmt.Errorf("unsupported elliptic curve: %v", key.Curve.Params().Name)
		}
	case ed25519.PublicKey:
		return cose.AlgorithmEdDSA, nil
	default:
		return cose.AlgorithmReserved, fmt.Errorf("unsupported key type %T", pub)
	}
}
