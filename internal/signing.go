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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/veraison/go-cose"
)

func Sign(data []byte, priv crypto.PrivateKey, serializer string,
	certChain []*x509.Certificate,
) ([]byte, error) {
	switch serializer {
	case "JSON":
		return signJson(data, priv, certChain)
	case "CBOR":
		return signCbor(data, priv, certChain)
	default:
		return nil, fmt.Errorf("unknown serializer %v", serializer)
	}
}

func signJson(data []byte, priv crypto.PrivateKey, certChain []*x509.Certificate,
) ([]byte, error) {
	log.Tracef("Signing JSON data length %v...", len(data))

	// Certificate chain in base64 encoding if present
	certsb64 := make([]string, 0)
	for _, cert := range certChain {
		certsb64 = append(certsb64, base64.StdEncoding.EncodeToString(cert.Raw))
	}

	// Get signature algorithm
	alg, err := algFromKeyType(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to get alg from key type: %w", err)
	}
	log.Trace("Chosen signature algorithm: ", alg)

	// Create signer with certificate chain header if present
	opts := &jose.SignerOptions{}
	if len(certsb64) > 0 {
		opts.WithHeader("x5c", certsb64)
	}
	var joseSigner jose.Signer
	joseSigner, err = jose.NewSigner(
		jose.SigningKey{Algorithm: alg, Key: priv},
		opts,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to setup signer : %w", err)
	}

	// sign
	log.Tracef("Signing data length %v", len(data))
	obj, err := joseSigner.Sign(data)
	if err != nil {
		return nil, err
	}
	log.Trace("Signing finished")

	// return signature in bytes
	msg := obj.FullSerialize()

	return []byte(msg), nil
}

func signCbor(data []byte, priv crypto.PrivateKey, certChain []*x509.Certificate) ([]byte, error) {

	log.Tracef("Signing CBOR data length %v...", len(data))

	certChainRaw := make([][]byte, 0)
	for _, cert := range certChain {
		certChainRaw = append(certChainRaw, cert.Raw)
	}

	stmp, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("failed to convert signing key of type %T", priv)
	}

	alg, err := coseAlgFromKeyType(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to get COSE algorithm from key type: %w", err)
	}
	log.Trace("Chosen COSE signature algorithm: ", alg)

	coseSigner, err := cose.NewSigner(alg, stmp)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	// create a signature holder
	sigHolder := cose.NewSignature()
	sigHolder.Headers.Protected.SetAlgorithm(alg)

	// https://datatracker.ietf.org/doc/draft-ietf-cose-x509/08/ section 2
	// If multiple certificates are conveyed, a CBOR array of byte strings is used,
	// with each certificate being in its own byte string (DER Encoded)
	sigHolder.Headers.Unprotected[cose.HeaderLabelX5Chain] = certChainRaw

	msgToSign := cose.NewSignMessage()
	msgToSign.Payload = data
	msgToSign.Signatures = append(msgToSign.Signatures, sigHolder)

	err = msgToSign.Sign(rand.Reader, nil, coseSigner)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w. len(data): %v", err, len(data))
	}

	// sign and marshal message
	coseRaw, err := msgToSign.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cbor object: %w", err)
	}

	log.Trace("Signing finished")

	return coseRaw, nil
}

// Deduces jose signature algorithm from provided key type
func algFromKeyType(priv crypto.PrivateKey) (jose.SignatureAlgorithm, error) {
	switch key := priv.(type) {
	case rsa.PrivateKey:
		switch key.Size() {
		case 256:
			// FUTURE: use RSA PSS: PS256
			return jose.RS256, nil
		case 512:
			// FUTURE: use RSA PSS: PS512
			return jose.RS512, nil
		default:
			return jose.RS256, fmt.Errorf("failed to determine algorithm from key type: unknown RSA key size: %v", key.Size())
		}
	case *rsa.PrivateKey:
		switch key.Size() {
		case 256:
			// FUTURE: use RSA PSS: PS256
			return jose.RS256, nil
		case 512:
			// FUTURE: use RSA PSS: PS512
			return jose.RS512, nil
		default:
			return jose.RS256, fmt.Errorf("failed to determine algorithm from key type: unknown RSA key size: %v", key.Size())
		}
	case ecdsa.PrivateKey:
		switch key.Curve {
		case elliptic.P224(), elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		default:
			return jose.RS256, errors.New("failed to determine algorithm from key type: unknown elliptic curve")
		}
	case *ecdsa.PrivateKey:
		switch key.Curve {
		case elliptic.P224(), elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		default:
			return jose.RS256, errors.New("failed to determine algorithm from key type: unknown elliptic curve")
		}
	default:
		return jose.RS256, fmt.Errorf("failed to determine algorithm from key type: unknown key type %T", priv)
	}
}

// Deduces COSE signature algorithm from provided key type
func coseAlgFromKeyType(priv crypto.PrivateKey) (cose.Algorithm, error) {
	switch key := priv.(type) {
	case rsa.PrivateKey:
		switch key.Size() {
		case 256:
			return cose.AlgorithmRS256, nil
		case 512:
			return cose.AlgorithmRS512, nil
		default:
			return cose.AlgorithmReserved, fmt.Errorf("unsupported RSA key size: %v", key.Size())
		}
	case *rsa.PrivateKey:
		switch key.Size() {
		case 256:
			return cose.AlgorithmRS256, nil
		case 512:
			return cose.AlgorithmRS512, nil
		default:
			return cose.AlgorithmReserved, fmt.Errorf("unsupported RSA key size: %v", key.Size())
		}
	case ecdsa.PrivateKey:
		switch key.Curve {
		case elliptic.P224(), elliptic.P256():
			return cose.AlgorithmES256, nil
		case elliptic.P384():
			return cose.AlgorithmES384, nil
		case elliptic.P521():
			return cose.AlgorithmES512, nil
		default:
			return cose.AlgorithmReserved, errors.New("unsupported elliptic curve for COSE")
		}
	case *ecdsa.PrivateKey:
		switch key.Curve {
		case elliptic.P224(), elliptic.P256():
			return cose.AlgorithmES256, nil
		case elliptic.P384():
			return cose.AlgorithmES384, nil
		case elliptic.P521():
			return cose.AlgorithmES512, nil
		default:
			return cose.AlgorithmReserved, errors.New("unsupported elliptic curve for COSE")
		}
	default:
		return cose.AlgorithmReserved, fmt.Errorf("unsupported key type for COSE: %T", priv)
	}
}
