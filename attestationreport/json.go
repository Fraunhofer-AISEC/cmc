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
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

type jsonSerializer struct{}

func NewJsonSerializer() (jsonSerializer, error) {
	return jsonSerializer{}, nil
}

func (s jsonSerializer) String() string {
	return "JSON"
}

func (s jsonSerializer) GetPayload(raw []byte) ([]byte, error) {
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

func (s jsonSerializer) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (s jsonSerializer) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// Verify verifies signatures and certificate chains of JWS tokens. The verifier interface must
// either be a list of trusted CA certificates, or a trusted public key, or a VerifierOption,
// which can be using the system certificates or the embedded self-signed certificate.
func (s jsonSerializer) Verify(data []byte, verifier Verifier) (MetadataResult, []byte, bool) {

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

// MarshalJSON marshals an attestation report with encoded context,
// which is required for the context integrity hash calculation
func (r AttestationReport) MarshalJSON() ([]byte, error) {

	if r.encodedContext == nil {
		return nil, fmt.Errorf("attestation report not prepared")
	}

	type alias AttestationReport
	return json.Marshal(&struct {
		*alias
		Context string `json:"context"`
	}{
		alias:   (*alias)(&r),
		Context: string(r.encodedContext),
	})
}

// UnmarshalJSON unmarshals an attestation report and also stores the
// encoded metadata internally for metadara integrity verification
func (r *AttestationReport) UnmarshalJSON(data []byte) error {

	type alias AttestationReport
	aux := &struct {
		*alias
		Context string `json:"context"`
	}{
		alias: (*alias)(r),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return fmt.Errorf("failed to unmarshal attestation report: %w", err)
	}

	r.encodedContext = []byte(aux.Context)

	var raw []byte
	switch r.Encoding {
	case TYPE_ENCODING_B64:
		r, err := base64.RawURLEncoding.DecodeString(aux.Context)
		if err != nil {
			return fmt.Errorf("failed to decode: %w", err)
		}
		raw = r
	default:
		return fmt.Errorf("unsupported JSON metadata encoding %q", r.Encoding)
	}

	return json.Unmarshal(raw, &r.Context)
}
