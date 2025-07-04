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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type CborSerializer struct{}

func (s CborSerializer) String() string {
	return "CBOR"
}

func (s CborSerializer) GetPayload(raw []byte) ([]byte, error) {
	// TODO better option to subdivide?
	// Try unmarshalling as Sign1Message
	var msg cose.SignMessage
	err1 := msg.UnmarshalCBOR(raw)
	if err1 != nil {
		// Try unmarshalling as SignMessage
		var msg cose.Sign1Message
		err2 := msg.UnmarshalCBOR(raw)
		if err2 != nil {
			return nil, fmt.Errorf("failed to get payload. Decode as SignMessage failed (%v), decode as Sign1Message failed (%v)", err1, err2)
		}
		return msg.Payload, nil
	}
	return msg.Payload, nil
}

func (s CborSerializer) Marshal(v any) ([]byte, error) {
	log.Tracef("Marshalling data using %v serialization", s.String())
	return cbor.Marshal(v)
}

func (s CborSerializer) Unmarshal(data []byte, v any) error {
	log.Tracef("Unmarshalling data using %v serialization", s.String())
	return cbor.Unmarshal(data, v)
}

func (s CborSerializer) Sign(data []byte, signer Driver, sel KeySelection) ([]byte, error) {

	log.Debugf("Signing CBOR data length %v...", len(data))

	private, _, err := signer.GetKeyHandles(sel)
	if err != nil {
		return nil, fmt.Errorf("failed to get signing keys: %w", err)
	}

	certChain, err := signer.GetCertChain(sel)
	if err != nil {
		return nil, fmt.Errorf("failed to get cert chain: %w", err)
	}
	certChainRaw := make([][]byte, 0)
	for _, cert := range certChain {
		certChainRaw = append(certChainRaw, cert.Raw)
	}

	stmp, ok := private.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("failed to convert signing key of type %T", private)
	}
	coseSigner, err := cose.NewSigner(cose.AlgorithmES256, stmp)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	// create a signature holder
	sigHolder := cose.NewSignature()
	sigHolder.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)

	// https://datatracker.ietf.org/doc/draft-ietf-cose-x509/08/ section 2
	// If multiple certificates are conveyed, a CBOR array of byte strings is used,
	// with each certificate being in its own byte string (DER Encoded)
	sigHolder.Headers.Unprotected[cose.HeaderLabelX5Chain] = certChainRaw

	msgToSign := cose.NewSignMessage()
	msgToSign.Payload = data
	msgToSign.Signatures = append(msgToSign.Signatures, sigHolder)

	// This allows the signer to ensure mutual access for signing, if required
	signer.Lock()
	defer signer.Unlock()

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

// Verify verifies the COSE structure with either provided trusted root CA certificate, or the
// system root CA certificates, or the provided public key
func (s CborSerializer) Verify(data []byte, roots []*x509.Certificate, useSystemCerts bool, pubKey crypto.PublicKey,
) (MetadataResult, []byte, bool) {

	log.Debugf("Verifying COSE object...")

	result := MetadataResult{}
	ok := true

	if useSystemCerts {
		log.Warnf("No CAs specified. Using system cert pool not implemented for CBOR")
		result.Summary.Success = false
		result.Summary.ErrorCode = SetupSystemCA
		return result, nil, false
	}

	// create a sign message from a raw COSE_Sign payload
	var msgToVerify cose.SignMessage
	err := msgToVerify.UnmarshalCBOR(data)
	if err != nil {
		log.Warnf("error unmarshalling cose: %v", err)
		log.Tracef("%v -> this is the hex-byte representation that could not be unmarshalled",
			hex.EncodeToString(data))
		log.Tracef("%v -> this is the string representation that could not be unmarshalled",
			string(data))
		log.Tracef("Length: %v (0x%x)", len(data), len(data))
		result.Summary.Success = false
		result.Summary.ErrorCode = ParseCBOR
		return result, nil, false
	}

	if len(msgToVerify.Signatures) == 0 {
		log.Warnf("failed to verify COSE: no signatures present")
		result.Summary.Success = false
		result.Summary.ErrorCode = COSENoSignatures
		return result, nil, false
	}

	// Create verifiers
	verifiers := make([]cose.Verifier, 0)
	for i, sig := range msgToVerify.Signatures {
		result.SignatureCheck = append(result.SignatureCheck, SignatureResult{})

		// Key(s) for verifying the signature(s)
		var verifyingKey crypto.PublicKey

		if len(roots) > 0 {

			log.Debugf("Verifying signature against certificate chain with %v roots", len(roots))

			// Only verify certificate chain(s) if roots are given
			x5Chain, okConv := sig.Headers.Unprotected[cose.HeaderLabelX5Chain].([]interface{})
			if !okConv {
				log.Warnf("failed to parse x5c header: %v", err)
				result.Summary.ErrorCode = ParseX5C
				result.SignatureCheck[i].CertChainCheck.Success = false
				result.SignatureCheck[i].CertChainCheck.ErrorCode = ParseX5C
				ok = false
				continue
			}
			certChain := make([]*x509.Certificate, 0, len(x5Chain))
			for _, rawCert := range x5Chain {
				cert, okCert := rawCert.([]byte)
				if !okCert {
					log.Warnf("failed to decode certificate chain")
					result.Summary.ErrorCode = DecodeCertChain
					result.SignatureCheck[i].CertChainCheck.Success = false
					result.SignatureCheck[i].CertChainCheck.ErrorCode = DecodeCertChain
					ok = false
					continue
				}
				x509Cert, err := x509.ParseCertificate(cert)
				if err != nil {
					log.Warnf("failed to parse leaf certificate: %v", err)
					result.Summary.ErrorCode = ParseCert
					result.SignatureCheck[i].CertChainCheck.Success = false
					result.SignatureCheck[i].CertChainCheck.ErrorCode = ParseCert
					ok = false
					continue
				}

				certChain = append(certChain, x509Cert)
			}

			x509Chains, err := internal.VerifyCertChain(certChain, roots)
			if err != nil {
				log.Warnf("failed to verify certificate chain: %v", err)
				result.Summary.ErrorCode = VerifyCertChain
				result.SignatureCheck[i].CertChainCheck.Success = false
				result.SignatureCheck[i].CertChainCheck.ErrorCode = VerifyCertChain
				ok = false

				// Store details from invalid certs for diagnostic information
				chainExtracted := []X509CertExtracted{}
				for _, cert := range certChain {
					chainExtracted = append(chainExtracted, ExtractX509Infos(cert))
				}
				result.SignatureCheck[i].Certs = append(result.SignatureCheck[i].Certs, chainExtracted)

			} else {
				result.SignatureCheck[i].CertChainCheck.Success = true
				//Store details from validated certificate chains
				for _, chain := range x509Chains {
					chainExtracted := []X509CertExtracted{}
					for _, cert := range chain {
						chainExtracted = append(chainExtracted, ExtractX509Infos(cert))
					}
					result.SignatureCheck[i].Certs = append(result.SignatureCheck[i].Certs, chainExtracted)
				}
			}
			var keyOk bool
			verifyingKey, keyOk = certChain[0].PublicKey.(*ecdsa.PublicKey)
			if !keyOk {
				log.Warnf("Failed to extract public key from certificate")
				result.Summary.ErrorCode = ExtractPubKey
				result.SignatureCheck[i].SignCheck.Success = false
				result.SignatureCheck[i].SignCheck.ErrorCode = ExtractPubKey
				ok = false
				continue
			}
		} else {
			// If no roots are given, look for a public key
			log.Debugf("Verifying signature against provided key %T", pubKey)
			verifyingKey = pubKey
		}

		verifier, err := cose.NewVerifier(cose.AlgorithmES256, verifyingKey)
		if err != nil {
			log.Warnf("Failed to create verifier: %v", err)
			result.Summary.ErrorCode = Internal
			result.SignatureCheck[i].SignCheck.Success = false
			result.SignatureCheck[i].SignCheck.ErrorCode = Internal
			ok = false
			continue
		}

		verifiers = append(verifiers, verifier)
	}

	err = msgToVerify.Verify(nil, verifiers...)
	if err != nil {
		log.Warnf("Error verifying cbor signature: %v", err)
		// Can only be set for all signatures here
		for i := range result.SignatureCheck {
			result.Summary.ErrorCode = VerifySignature
			result.SignatureCheck[i].SignCheck.Success = false
			result.SignatureCheck[i].SignCheck.ErrorCode = VerifySignature
			ok = false
		}
		return result, nil, false
	} else {
		// Can only be set for all signatures here
		for i := range result.SignatureCheck {
			result.SignatureCheck[i].SignCheck.Success = true
		}
	}

	if ok {
		log.Debug("Successfully verified COSE object")
	}

	result.Summary.Success = ok

	return result, msgToVerify.Payload, ok
}
