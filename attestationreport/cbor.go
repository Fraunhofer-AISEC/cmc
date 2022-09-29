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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	log "github.com/sirupsen/logrus"
	"github.com/veraison/go-cose"
)

type CborSerializer struct{}

func (s CborSerializer) GetPayload(raw []byte) ([]byte, error) {
	var msg cose.SignMessage
	err := msg.UnmarshalCBOR(raw)
	if err != nil {
		return nil, fmt.Errorf("Failed to get payload: %v", err)
	}
	return msg.Payload, nil
}

func (s CborSerializer) Marshal(v any) ([]byte, error) {
	return cbor.Marshal(v)
}

func (s CborSerializer) Unmarshal(data []byte, v any) error {
	return cbor.Unmarshal(data, v)
}

func (s CborSerializer) Sign(report []byte, signer Signer) (bool, []byte) {

	private, _, err := signer.GetSigningKeys()
	if err != nil {
		log.Errorf("failed to get signing keys: %v", err)
		return false, nil
	}

	certChain, err := certChainToDer(signer.GetCertChain())
	if err != nil {
		log.Errorf("failed to get certificate chain (DER): %v", err)
		return false, nil
	}

	// create a cose signer TODO support RSA
	stmp, ok := private.(*ecdsa.PrivateKey)
	if !ok {
		log.Errorf("failed to convert signing key %v", private)
		return false, nil
	}
	coseSigner, err := cose.NewSigner(cose.AlgorithmES256, stmp)
	if err != nil {
		log.Errorf("Failed to create signer: %v", err)
		return false, nil
	}

	// create a signature holder
	sigHolder := cose.NewSignature()
	sigHolder.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)

	// https://datatracker.ietf.org/doc/draft-ietf-cose-x509/08/ section 2
	// If multiple certificates are conveyed, a CBOR array of byte strings is used,
	// with each certificate being in its own byte string (DER Encoded)
	sigHolder.Headers.Unprotected[cose.HeaderLabelX5Chain] = certChain

	msgToSign := cose.NewSignMessage()
	msgToSign.Payload = report
	msgToSign.Signatures = append(msgToSign.Signatures, sigHolder)

	err = msgToSign.Sign(rand.Reader, nil, coseSigner)
	if err != nil {
		log.Errorf("failed to sign cbor object: %v", err)
		return false, nil
	}

	// sign and marshal message
	coseRaw, err := msgToSign.MarshalCBOR()
	if err != nil {
		log.Errorf("failed to marshal cbor object: %v", err)
		return false, nil
	}

	return true, coseRaw
}

func (s CborSerializer) VerifyToken(data []byte, roots []*x509.Certificate) (JwsResult, []byte, bool) {

	// TODO JwsResult (Naming)
	result := JwsResult{}

	// create a sign message from a raw COSE_Sign payload
	var msgToVerify cose.SignMessage
	err := msgToVerify.UnmarshalCBOR(data)
	if err != nil {
		log.Warnf("error unmarshalling cose: %v", err)
		return result, nil, false
	}

	// Extract leaf certificates, use its public keys for the verifiers and create verifiers
	if len(msgToVerify.Signatures) == 0 {
		log.Warnf("failed to verify COSE: no signatures present")
	}
	log.Tracef("Number of COSE signatures: %v", len(msgToVerify.Signatures))
	verifiers := make([]cose.Verifier, 0)
	for _, sig := range msgToVerify.Signatures {

		x5Chain := sig.Headers.Unprotected[cose.HeaderLabelX5Chain].([]interface{})
		certChain := make([]*x509.Certificate, 0, len(x5Chain))
		for _, rawCert := range x5Chain {
			cert, ok := rawCert.([]byte)
			if !ok {
				log.Warnf("failed to decode certificate chain")
				return result, nil, false
			}
			x509Cert, err := x509.ParseCertificate(cert)
			if err != nil {
				log.Warnf("failed to parse leaf certificate: %v", err)
				return result, nil, false
			}

			certChain = append(certChain, x509Cert)
		}

		// TODO Verify Cert Chain, error handling
		err := verifyCertChainX509(certChain, roots)
		if err != nil {
			log.Warnf("failed to verify certificate chain")
			return result, nil, false
		}

		publicKey, ok := certChain[0].PublicKey.(*ecdsa.PublicKey)
		if !ok {
			log.Warnf("failed to convert certificate key to ecdsa key")
			return result, nil, false
		}

		// create a verifier from a trusted private key
		verifier, err := cose.NewVerifier(cose.AlgorithmES256, publicKey)
		if err != nil {
			log.Warnf("failed to create verifier: %v", err)
			return result, nil, false
		}

		verifiers = append(verifiers, verifier)
	}

	err = msgToVerify.Verify(nil, verifiers...)
	if err != nil {
		log.Warnf("error verifying cbor: %v", err)
		return result, nil, false
	}

	return result, msgToVerify.Payload, true
}
