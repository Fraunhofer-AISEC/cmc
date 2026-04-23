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
	"crypto/x509"
	"fmt"
	"reflect"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type cborSerializer struct {
	enc cbor.EncMode
	dec cbor.DecMode
}

var (
	ENC_OPTIONS = cbor.CTAP2EncOptions()
	DEC_OPTIONS = cbor.DecOptions{
		DefaultMapType: reflect.TypeOf(map[string]interface{}{}),
	}
)

func NewCborSerializer() (cborSerializer, error) {
	enc, err := ENC_OPTIONS.EncMode()
	if err != nil {
		return cborSerializer{}, err
	}
	dec, err := DEC_OPTIONS.DecMode()
	if err != nil {
		return cborSerializer{}, err
	}
	return cborSerializer{enc: enc, dec: dec}, nil
}

func (s cborSerializer) String() string {
	return "CBOR"
}

func (s cborSerializer) GetPayload(raw []byte) ([]byte, error) {
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

func (s cborSerializer) Marshal(v any) ([]byte, error) {
	if s.enc == nil {
		return nil, fmt.Errorf("internal error: cbor encoder not initialized")
	}
	return s.enc.Marshal(v)
}

func (s cborSerializer) Unmarshal(data []byte, v any) error {
	if s.dec == nil {
		return fmt.Errorf("internal error: cbor decoder not initialized")
	}
	return s.dec.Unmarshal(data, v)
}

// Verify verifies signatures and certificate chains of COSE messages. The verifier interface must
// either be a list of trusted CA certificates, or a trusted public key, or a VerifierOption,
// which can be using the system certificates or the embedded self-signed certificate.
func (s cborSerializer) Verify(data []byte, verifier Verifier) (MetadataResult, []byte, bool) {

	result := MetadataResult{
		Summary: Result{
			Status: StatusSuccess,
		},
	}
	var roots []*x509.Certificate
	var verifyingKey crypto.PublicKey
	success := true

	log.Tracef("Verifying COSE message...")

	// Parse the signed COSE message
	var msgToVerify cose.SignMessage
	err := msgToVerify.UnmarshalCBOR(data)
	if err != nil {
		result.Summary.Fail(ParseCBOR, err)
		return result, nil, false
	}
	if len(msgToVerify.Signatures) == 0 {
		result.Summary.Fail(COSENoSignatures)
		return result, nil, false
	}

	// Determine verifier type
	switch verifier := verifier.(type) {
	case []*x509.Certificate:
		roots = verifier
		log.Tracef("Using %v provided root CAs for COSE verification", len(roots))
	case crypto.PublicKey:
		verifyingKey = verifier
		log.Tracef("Verifying signature against provided key %T", verifyingKey)
	case nil:
		log.Warnf("Using system cert pool not implemented for CBOR")
		result.Summary.Fail(SetupSystemCA)
		return result, nil, false
	default:
		result.Summary.Fail(COSEUnknownVerifierType)
		return result, nil, false

	}

	// Create verifiers
	verifiers := make([]cose.Verifier, 0)
	for i, sig := range msgToVerify.Signatures {
		result.SignatureCheck = append(result.SignatureCheck, SignatureResult{})

		if len(roots) > 0 {

			log.Tracef("Verifying signature against certificate chain with %v roots", len(roots))

			// Only verify certificate chain(s) if roots are given
			x5Chain, ok := sig.Headers.Unprotected[cose.HeaderLabelX5Chain].([]interface{})
			if !ok {
				result.Summary.Status = StatusFail
				result.SignatureCheck[i].CertChainCheck.Fail(ParseX5C)
				success = false
				continue
			}
			certChain := make([]*x509.Certificate, 0, len(x5Chain))
			for _, rawCert := range x5Chain {
				cert, okCert := rawCert.([]byte)
				if !okCert {
					log.Warnf("failed to decode certificate chain")
					result.Summary.Fail(DecodeCertChain)
					result.SignatureCheck[i].CertChainCheck.Fail(DecodeCertChain)
					success = false
					continue
				}
				x509Cert, err := x509.ParseCertificate(cert)
				if err != nil {
					log.Warnf("failed to parse leaf certificate: %v", err)
					result.Summary.Status = StatusFail
					result.SignatureCheck[i].CertChainCheck.Fail(ParseCert, err)
					success = false
					continue
				}

				certChain = append(certChain, x509Cert)
			}

			x509Chains, err := internal.VerifyCertChain(certChain, roots)
			if err != nil {
				result.Summary.Status = StatusFail
				result.SignatureCheck[i].CertChainCheck.Fail(VerifyCertChain, err)
				success = false

				// Store details from invalid certs for diagnostic information
				chainExtracted := []X509CertExtracted{}
				for _, cert := range certChain {
					chainExtracted = append(chainExtracted, ExtractX509Infos(cert))
				}
				result.SignatureCheck[i].Certs = append(result.SignatureCheck[i].Certs, chainExtracted)

			} else {
				result.SignatureCheck[i].CertChainCheck.Status = StatusSuccess
				//Store details from validated certificate chains
				for _, chain := range x509Chains {
					chainExtracted := []X509CertExtracted{}
					for _, cert := range chain {
						chainExtracted = append(chainExtracted, ExtractX509Infos(cert))
					}
					result.SignatureCheck[i].Certs = append(result.SignatureCheck[i].Certs, chainExtracted)
				}
			}
			verifyingKey = certChain[0].PublicKey
		}

		// Get algorithm from the signature's protected headers
		alg, err := sig.Headers.Protected.Algorithm()
		if err != nil {
			result.Summary.Fail(UnsupportedAlgorithm, fmt.Errorf("failed to get COSE algorithm from protected headers: %w", err))
			result.SignatureCheck[i].SignCheck.Fail(UnsupportedAlgorithm, err)
			success = false
			continue
		}

		verifier, err := cose.NewVerifier(alg, verifyingKey)
		if err != nil {
			result.Summary.Fail(UnsupportedAlgorithm, err)
			result.SignatureCheck[i].SignCheck.Fail(UnsupportedAlgorithm, err)
			success = false
			continue
		}

		verifiers = append(verifiers, verifier)
	}

	err = msgToVerify.Verify(nil, verifiers...)
	if err != nil {
		// Can only be set for all signatures here
		for i := range result.SignatureCheck {
			result.Summary.Status = StatusFail
			result.SignatureCheck[i].SignCheck.Fail(VerifySignature)
			success = false
		}
		return result, nil, false
	} else {
		// Can only be set for all signatures here
		for i := range result.SignatureCheck {
			result.SignatureCheck[i].SignCheck.Status = StatusSuccess
		}
	}

	if success {
		log.Trace("Successfully verified COSE object")
	}

	return result, msgToVerify.Payload, success
}

// UnmarshalCBOR unmarshals an attestation report and also stores the
// encoded context internally for metadara integrity verification
func (r *AttestationReport) UnmarshalCBOR(data []byte) error {

	// Prepare TODO avoid additional initialization
	enc, err := ENC_OPTIONS.EncMode()
	if err != nil {
		return fmt.Errorf("failed to set up encode mode: %w", err)
	}
	dec, err := DEC_OPTIONS.DecMode()
	if err != nil {
		return fmt.Errorf("failed to set up decode mode: %w", err)
	}

	// Regular unmarshal
	type alias AttestationReport
	aux := &struct {
		*alias
	}{
		alias: (*alias)(r),
	}
	if err := dec.Unmarshal(data, aux); err != nil {
		return fmt.Errorf("failed to unmarshal cbor: %w", err)
	}

	// Marshal context just for hashing
	raw, err := enc.Marshal(r.Context)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata")
	}

	switch r.Encoding {
	case TYPE_ENCODING_CBOR:
		r.encodedContext = raw
	default:
		return fmt.Errorf("unsupported CBOR metadata encoding %q", r.Encoding)
	}

	return nil
}
