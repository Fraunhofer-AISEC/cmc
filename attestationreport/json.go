// Copyright (c) 2021 - 2024 Fraunhofer AISEC
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

	"github.com/go-jose/go-jose/v4"
)

// Custom type for JSON unmarshaller as byte arrays are
// encoded as hex strings in JSON but used as byte arrays
// internally and by CBOR encoding
type HexByte []byte

// MarshalJSON marshalls a byte array into a hex string
func (h HexByte) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h))
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

func (s JsonSerializer) String() string {
	return "JSON"
}

func (s JsonSerializer) GetPayload(raw []byte) ([]byte, error) {
	// Extract plain payload out of base64-encoded JSON Web Signature
	jws, err := jose.ParseSigned(string(raw), []jose.SignatureAlgorithm{
		jose.RS256,
		jose.RS512,
		jose.ES256,
		jose.ES384,
		jose.ES512,
	})
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

// Sign signs data with the specified driver (to enable hardware-based signatures)
func (s JsonSerializer) Sign(data []byte, driver Driver, sel KeySelection) ([]byte, error) {

	log.Tracef("Signing JSON data length %v...", len(data))

	// This allows the signer to ensure mutual access for signing, if required
	driver.Lock()
	defer driver.Unlock()

	// Create list of all certificates in the correct order
	certs, err := driver.GetCertChain(sel)
	if err != nil {
		return nil, fmt.Errorf("failed to get cert chain: %w", err)
	}

	// Certificate chain in base64 encoding
	certsb64 := make([]string, 0)
	for _, cert := range certs {
		certsb64 = append(certsb64, base64.StdEncoding.EncodeToString(cert.Raw))
	}

	// Fetch signing keys from driver
	priv, pub, err := driver.GetKeyHandles(sel)
	if err != nil {
		return nil, fmt.Errorf("failed to get signing keys: %w", err)
	}

	// Get jose.SignatureAlgorithm
	// Saltlength and further algorithms are set to the recommended default by x509
	var alg jose.SignatureAlgorithm
	alg, err = algFromKeyType(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to get alg from key type: %w", err)
	}
	log.Trace("Chosen signature algorithm: ", alg)

	// create jose signer with hwSigner wrapper for hardware-based keys
	var hws *hwSigner
	var opaqueSigner jose.OpaqueSigner
	hws = &hwSigner{
		pk: &jose.JSONWebKey{
			Key: pub,
		},
		signer: priv,
		alg:    alg,
	}
	opaqueSigner = jose.OpaqueSigner(hws)

	// Create signer with certificate chain header if present
	opts := &jose.SignerOptions{}
	if len(certsb64) > 0 {
		opts.WithHeader("x5c", certsb64)
	}
	var joseSigner jose.Signer
	joseSigner, err = jose.NewSigner(
		jose.SigningKey{Algorithm: alg, Key: opaqueSigner},
		opts,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to setup signer : %w", err)
	}

	// sign
	log.Tracef("Performing Sign operation using %v", driver.Name())
	obj, err := joseSigner.Sign(data)
	if err != nil {
		return nil, err
	}
	log.Trace("Signing finished")

	// return signature in bytes
	msg := obj.FullSerialize()

	return []byte(msg), nil
}

// Verify verifies signatures and certificate chains of JWS tokens. The verifier interface must
// either be a list of trusted CA certificates, or a trusted public key, or a VerifierOption,
// which can be using the system certificates or the embedded self-signed certificate.
func (s JsonSerializer) Verify(data []byte, verifier Verifier) (MetadataResult, []byte, bool) {

	var rootpool *x509.CertPool
	var verifyingKey crypto.PublicKey
	var err error
	result := MetadataResult{
		Summary: Result{
			Status: StatusSuccess,
		},
	}
	success := true
	verifyCertChain := true

	log.Tracef("Verifying JWS object...")

	// Parse the signed JWS object
	jwsData, err := jose.ParseSigned(string(data), []jose.SignatureAlgorithm{
		jose.RS256,
		jose.RS512,
		jose.ES256,
		jose.ES384,
		jose.ES512,
	})
	if err != nil {
		result.Summary.Fail(ParseJSON, err)
		return result, nil, false
	}
	if len(jwsData.Signatures) == 0 {
		result.Summary.Fail(JWSNoSignatures)
		return result, nil, false
	}
	index := make([]int, len(jwsData.Signatures))
	payloads := make([][]byte, len(jwsData.Signatures))

	// Determine verifier type
	switch verifier := verifier.(type) {
	case []*x509.Certificate:
		roots := verifier
		log.Tracef("Using %v provided root CAs for JWS verification", len(roots))
		rootpool = x509.NewCertPool()
		for _, cert := range roots {
			log.Tracef("Adding %q with SubjectKeyID %q to trusted root pool",
				cert.Subject.CommonName, hex.EncodeToString(cert.SubjectKeyId))
			rootpool.AddCert(cert)
		}
	case crypto.PublicKey:
		log.Trace("Using provided public key for JWS verification")
		verifyingKey = verifier
		rootpool = nil
		verifyCertChain = false
	case nil:
		log.Trace("Using system certificate pool for JWS verification")
		rootpool, err = x509.SystemCertPool()
		if err != nil {
			result.Summary.Fail(SetupSystemCA, err)
			return result, nil, false
		}
	default:
		result.Summary.Fail(JWSUnknownVerifierType)
		return result, nil, false
	}

	opts := x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:     rootpool,
	}

	for i, sig := range jwsData.Signatures {

		result.SignatureCheck = append(result.SignatureCheck, SignatureResult{})

		if verifyCertChain {
			// Verify the certificate chain present in the x5c header against the given roots
			certs, err := sig.Protected.Certificates(opts)
			if err != nil {
				result.Summary.Status = StatusFail
				result.SignatureCheck[i].CertChainCheck.Fail(VerifyCertChain, err)
				success = false
				continue
			}
			// Store details from validated certificate chain(s)
			for _, chain := range certs {
				chainExtracted := []X509CertExtracted{}
				for _, cert := range chain {
					chainExtracted = append(chainExtracted, ExtractX509Infos(cert))
				}
				result.SignatureCheck[i].Certs = append(result.SignatureCheck[i].Certs, chainExtracted)
			}
			result.SignatureCheck[i].CertChainCheck.Status = StatusSuccess
			verifyingKey = certs[0][0].PublicKey

			log.Tracef("Using public key from cert %v for signature verification", certs[0][0].Subject.CommonName)
		}

		// The JSONWebKey uses the certificates from the x5c header, already validated before
		index[i], _, payloads[i], err = jwsData.VerifyMulti(verifyingKey)
		if err == nil {
			result.SignatureCheck[i].SignCheck.Status = StatusSuccess
		} else {
			result.Summary.Status = StatusFail
			result.SignatureCheck[i].SignCheck.Fail(VerifySignature, err)
			success = false
		}

		if index[i] != i {
			result.Summary.Fail(JWSSignatureOrder,
				fmt.Errorf("order of signatures incorrect (index %v != iterator %v)", index[i], i))
			success = false
		}

		if i > 0 {
			if !bytes.Equal(payloads[i], payloads[i-1]) {
				result.Summary.Fail(JWSPayload)
				success = false
			}
		}
	}

	if success {
		log.Trace("Successfully verified JWS object")
	}

	payload := payloads[0]

	return result, payload, success
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

// Used for the JOSE Opaque Signer Interface. This enables signing with
// hardware-based keys (such as TPM-based keys)
type hwSigner struct {
	pk     *jose.JSONWebKey
	signer crypto.PrivateKey
	alg    jose.SignatureAlgorithm
}

// Implements the JOSE Opaque Signer Interface. This enables signing
// with hardware-based keys (such as TPM-based keys)
func (hws *hwSigner) Public() *jose.JSONWebKey {
	return hws.pk
}

// Implements the JOSE Opaque Signer Interface. This enables signing
// with hardware-based keys (such as TPM-based keys)
func (hws *hwSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{hws.alg}
}

// Implements the JOSE Opaque Signer Interface. This enables signing
// with hardware-based keys (such as TPM-based keys)
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
	n, err := hasher.Write(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to hash: %w", err)
	}
	hashed := hasher.Sum(nil)

	// Sign payload
	switch alg {
	case jose.ES256, jose.ES384, jose.ES512:
		// Obtain signature
		asn1Sig, err := hws.signer.(crypto.Signer).Sign(rand.Reader, hashed, opts)
		if err != nil {
			return nil, fmt.Errorf("signing failed: %w. Additional info: "+
				"opts: %v, keySize: %v, len(data): %v, len(hash): %v",
				err, opts, keySize, n, len(hashed))
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
