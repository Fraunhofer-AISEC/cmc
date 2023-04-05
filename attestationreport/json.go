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

package attestationreport

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"gopkg.in/square/go-jose.v2"
)

// Custom type for JSON unmarshaller as byte arrays are
// encoded as hex strings in JSON but used as byte arrays
// internally and by CBOR encoding
type HexByte []byte

// MarshalJSON marshalls a byte array into a hex string
func (h *HexByte) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(*h))
}

// UnmarshalJSON unmarshalls JSON hex strings into
// byte arrays
func (h *HexByte) UnmarshalJSON(data []byte) error {

	var v string
	err := json.Unmarshal(data, &v)
	if err != nil {
		return fmt.Errorf("failed to unmarshal: %v", err)
	}

	*h, err = hex.DecodeString(v)
	if err != nil {
		return fmt.Errorf("failed to decode string: %v", err)
	}

	return nil
}

type JsonSerializer struct{}

func (s JsonSerializer) GetPayload(raw []byte) ([]byte, error) {
	// Extract plain payload out of base64-encoded JSON Web Signature
	jws, err := jose.ParseSigned(string(raw))
	if err != nil {
		return nil, fmt.Errorf("failed to parse jws object: %v", err)
	}
	data := jws.UnsafePayloadWithoutVerification()

	return data, nil
}

func (s JsonSerializer) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (s JsonSerializer) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// Sign signs the attestation report with the specified signer 'signer'
func (s JsonSerializer) Sign(report []byte, signer Driver) ([]byte, error) {

	log.Trace("Signing attestation report")

	// create list of all certificates in the correct order
	certs, err := signer.GetCertChain()
	if err != nil {
		return nil, fmt.Errorf("failed to get cert chain: %w", err)
	}

	// certificate chain in base64 encoding
	certsb64 := make([]string, 0)
	for _, cert := range certs {
		certsb64 = append(certsb64, base64.StdEncoding.EncodeToString(cert.Raw))
	}

	priv, pub, err := signer.GetSigningKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing keys: %w", err)
	}

	// Get jose.SignatureAlgorithm
	// Saltlength and further algorithms are set to the recommended default by x509
	// we assume these defaults are correct
	var alg jose.SignatureAlgorithm
	alg, err = algFromKeyType(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to get alg from key type: %w", err)
	}
	log.Trace("Chosen signature algorithm: ", alg)

	// create jose.OpaqueSigner with hwSigner wrapper (tpm key)
	var hws *hwSigner
	var opaqueSigner jose.OpaqueSigner
	hws = &hwSigner{
		pk:     &jose.JSONWebKey{Key: pub},
		signer: priv,
		alg:    alg,
	}
	opaqueSigner = jose.OpaqueSigner(hws)

	// Create jose.Signer with OpaqueSigner
	// x5c: adds Certificate Chain in later result
	var opt jose.SignerOptions
	var joseSigner jose.Signer
	joseSigner, err = jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: opaqueSigner}, opt.WithHeader("x5c", certsb64))
	if err != nil {
		return nil, fmt.Errorf("failed to setup signer for the Attestation Report: %w", err)
	}

	// This allows the signer to ensure mutual access for signing, if required
	signer.Lock()
	defer signer.Unlock()

	// sign
	log.Trace("Performing Sign operation")
	obj, err := joseSigner.Sign(report)
	if err != nil {
		return nil, fmt.Errorf("failed to sign the Attestation Report: %w", err)
	}
	log.Trace("Signed attestation report")

	// return signature in bytes
	msg := obj.FullSerialize()

	return []byte(msg), nil
}

// VerifyToken verifies signatures and certificate chains for JWS tokens
func (s JsonSerializer) VerifyToken(data []byte, roots []*x509.Certificate) (TokenResult, []byte, bool) {

	var rootpool *x509.CertPool
	var err error
	result := TokenResult{}
	ok := true

	if len(roots) == 0 {
		log.Debug("Using system certificate pool in absence of provided root certifcates")
		rootpool, err = x509.SystemCertPool()
		if err != nil {
			msg := "Failed to setup trusted cert pool with system certificate pool"
			result.Summary.setFalseMulti(&msg)
			return result, nil, false
		}
	} else {
		rootpool = x509.NewCertPool()
		for _, cert := range roots {
			rootpool.AddCert(cert)
		}
	}

	opts := x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:     rootpool,
	}

	jwsData, err := jose.ParseSigned(string(data))
	if err != nil {
		msg := fmt.Sprintf("Data could not be parsed: %v", err)
		result.Summary.setFalseMulti(&msg)
		return result, nil, false
	}

	if len(jwsData.Signatures) == 0 {
		msg := "JWS does not contain signatures"
		result.Summary.setFalseMulti(&msg)
		return result, nil, false
	}

	index := make([]int, len(jwsData.Signatures))
	payloads := make([][]byte, len(jwsData.Signatures))
	for i, sig := range jwsData.Signatures {
		result.SignatureCheck = append(result.SignatureCheck, SignatureResult{})

		certs, err := sig.Protected.Certificates(opts)
		if err != nil {
			msg := fmt.Sprintf("Failed to verify certificate chain: %v", err)
			result.SignatureCheck[i].CertChainCheck.setFalse(&msg)
			ok = false
			continue
		}

		//Store details from (all) validated certificate chain(s) in the report
		for _, chain := range certs {
			chainExtracted := []X509CertExtracted{}
			for _, cert := range chain {
				chainExtracted = append(chainExtracted, ExtractX509Infos(cert))
			}
			result.SignatureCheck[i].ValidatedCerts = append(result.SignatureCheck[i].ValidatedCerts, chainExtracted)
		}

		result.SignatureCheck[i].CertChainCheck.Success = true

		index[i], _, payloads[i], err = jwsData.VerifyMulti(certs[0][0].PublicKey)
		if err == nil {
			result.SignatureCheck[i].SignCheck.Success = true
		} else {
			msg := fmt.Sprintf("Signature verification failed: %v", err)
			result.SignatureCheck[i].SignCheck.setFalse(&msg)
			ok = false
		}

		if index[i] != i {
			msg := "order of signatures incorrect"
			result.Summary.setFalseMulti(&msg)
		}

		if i > 0 {
			if !bytes.Equal(payloads[i], payloads[i-1]) {
				msg := "payloads differ for jws with multiple signatures"
				result.Summary.setFalseMulti(&msg)
			}
		}
	}

	payload := payloads[0]
	result.Summary.Success = ok

	return result, payload, ok
}

// Deduces jose signature algorithm from provided key type
func algFromKeyType(pub crypto.PublicKey) (jose.SignatureAlgorithm, error) {
	switch key := pub.(type) {
	case *rsa.PublicKey:
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
	case *ecdsa.PublicKey:
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
		return jose.RS256, errors.New("failed to determine algorithm from key type: unknown key type")
	}
}

// Used for the JOSE Opaque Signer Interface. This enables signing
// the attestation report with hardware-based keys (such as TPM-based keys)
type hwSigner struct {
	pk     *jose.JSONWebKey
	signer crypto.PrivateKey
	alg    jose.SignatureAlgorithm
}

// Implements the JOSE Opaque Signer Interface. This enables signing
// the attestation report with hardware-based keys (such as TPM-based keys)
func (hws *hwSigner) Public() *jose.JSONWebKey {
	return hws.pk
}

// Implements the JOSE Opaque Signer Interface. This enables signing
// the attestation report with hardware-based keys (such as TPM-based keys)
func (hws *hwSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{hws.alg}
}

// Implements the JOSE Opaque Signer Interface. This enables signing
// the attestation report with hardware-based keys (such as TPM-based keys)
func (hws *hwSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	// EC-specific: key size in byte for later padding
	var keySize int
	// Determine hash / SignerOpts from algorithm
	var opts crypto.SignerOpts
	switch alg {
	case jose.RS256, jose.ES256: // RSA, ECDSA with SHA256
		keySize = 32 // 256 bit
		opts = crypto.SHA256
	case jose.PS256: // RSA PSS with SHA256
		// we force default saltLengths, same as x509 and TPM2.0
		opts = &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}
	case jose.RS384, jose.ES384: // RSA, ECDSA with SHA384
		keySize = 48
		opts = crypto.SHA384
	case jose.PS384: // RSA PSS with SHA384
		opts = &rsa.PSSOptions{SaltLength: 48, Hash: crypto.SHA384}
	case jose.RS512, jose.ES512: // RSA, ECDSA with SHA512
		keySize = 66 // 521 bit + padding
		opts = crypto.SHA512
	case jose.PS512: // RSA PSS with SHA512
		opts = &rsa.PSSOptions{SaltLength: 64, Hash: crypto.SHA512}
	default:
		return nil, errors.New("could not determine appropriate hash type")
	}

	// Hash payload
	hasher := opts.HashFunc().New()
	// According to documentation, Write() on hash never fails
	_, _ = hasher.Write(payload)
	hashed := hasher.Sum(nil)

	// sign payload
	switch alg {
	case jose.ES256, jose.ES384, jose.ES512:
		// Obtain signature
		asn1Sig, err := hws.signer.(crypto.Signer).Sign(rand.Reader, hashed, opts)
		if err != nil {
			return nil, err
		}
		// Convert from asn1 format (as specified in crypto) to concatenated and padded format for go-jose
		type ecdsasig struct {
			R *big.Int
			S *big.Int
		}
		var esig ecdsasig
		ret := make([]byte, 2*keySize)
		_, err = asn1.Unmarshal(asn1Sig, &esig)
		if err != nil {
			return nil, errors.New("ECDSA signature was not in expected format")
		}
		// Fill return buffer with padded keys
		rBytes := esig.R.Bytes()
		sBytes := esig.S.Bytes()
		copy(ret[keySize-len(rBytes):keySize], rBytes)
		copy(ret[2*keySize-len(sBytes):2*keySize], sBytes)
		return ret, nil
	default:
		// The return format of all other signatures does not need to be adapted for go-jose
		return hws.signer.(crypto.Signer).Sign(rand.Reader, hashed, opts)
	}
}
