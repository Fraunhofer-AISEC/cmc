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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type CborSerializer struct{}

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

	certChain := make([][]byte, 0)
	for _, cert := range signer.GetCertChain() {
		certChain = append(certChain, cert.Raw)
	}

	stmp, ok := private.(crypto.Signer)
	if !ok {
		log.Errorf("failed to convert signing key of type %T", private)
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

	// This allows the signer to ensure mutual access for signing, if required
	signer.Lock()
	defer signer.Unlock()

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

func (s CborSerializer) VerifyToken(data []byte, roots []*x509.Certificate) (TokenResult, []byte, bool) {

	// TODO TokenResult (Naming)
	result := TokenResult{}
	ok := true

	if len(roots) == 0 {
		log.Warnf("No CAs specified. Using system cert pool not implemented for CBOR")
		return result, nil, false
	}

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
		return result, nil, false
	}
	verifiers := make([]cose.Verifier, 0)
	for i, sig := range msgToVerify.Signatures {
		result.SignatureCheck = append(result.SignatureCheck, SignatureResult{})

		x5Chain, okConv := sig.Headers.Unprotected[cose.HeaderLabelX5Chain].([]interface{})
		if !okConv {
			msg := fmt.Sprintf("failed to parse x5c header: %v", err)
			result.SignatureCheck[i].CertChainCheck.setFalse(&msg)
			ok = false
			continue
		}
		certChain := make([]*x509.Certificate, 0, len(x5Chain))
		for _, rawCert := range x5Chain {
			cert, okCert := rawCert.([]byte)
			if !okCert {
				msg := "failed to decode certificate chain"
				result.SignatureCheck[i].CertChainCheck.setFalse(&msg)
				ok = false
				continue
			}
			x509Cert, err := x509.ParseCertificate(cert)
			if err != nil {
				msg := fmt.Sprintf("failed to parse leaf certificate: %v", err)
				result.SignatureCheck[i].CertChainCheck.setFalse(&msg)
				ok = false
				continue
			}

			certChain = append(certChain, x509Cert)
		}

		x509Chains, err := internal.VerifyCertChain(certChain, roots)
		if err != nil {
			msg := fmt.Sprintf("failed to verify certificate chain: %v", err)
			result.SignatureCheck[i].CertChainCheck.setFalse(&msg)
			ok = false
			continue
		}

		//Store details from (all) validated certificate chain(s) in the report
		for _, chain := range x509Chains {
			chainExtracted := []X509CertExtracted{}
			for _, cert := range chain {
				chainExtracted = append(chainExtracted, ExtractX509Infos(cert))
			}
			result.SignatureCheck[i].ValidatedCerts = append(result.SignatureCheck[i].ValidatedCerts, chainExtracted)
		}

		result.SignatureCheck[i].CertChainCheck.Success = true

		publicKey, okKey := certChain[0].PublicKey.(*ecdsa.PublicKey)
		if !okKey {
			msg := fmt.Sprintf("Failed to extract public key from certificate: %v", err)
			result.SignatureCheck[i].SignCheck.setFalse(&msg)
			ok = false
			continue
		}

		// create a verifier from a trusted private key
		verifier, err := cose.NewVerifier(cose.AlgorithmES256, publicKey)
		if err != nil {
			msg := fmt.Sprintf("Failed to create verifier: %v", err)
			result.SignatureCheck[i].SignCheck.setFalse(&msg)
			ok = false
			continue
		}

		verifiers = append(verifiers, verifier)
	}

	err = msgToVerify.Verify(nil, verifiers...)
	if err != nil {
		msg := fmt.Sprintf("Error verifying cbor signature: %v", err)
		// Can only be set for all signatures here
		for i := range result.SignatureCheck {
			result.SignatureCheck[i].SignCheck.setFalse(&msg)
		}
		return result, nil, false
	} else {
		// Can only be set for all signatures here
		for i := range result.SignatureCheck {
			result.SignatureCheck[i].SignCheck.Success = true
		}
	}

	result.Summary.Success = ok

	return result, msgToVerify.Payload, true
}
