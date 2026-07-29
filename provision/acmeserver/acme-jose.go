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

package main

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/jsoncanonicalizer"
	"github.com/go-jose/go-jose/v4"
)

type jwsJSONBody struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type jwsJSONProtected struct {
	Algorithm string `json:"alg"`
	Key       any    `json:"jwk"`
	Kid       string `json:"kid"`
	Nonce     string `json:"nonce"`
	URL       string `json:"url"`
}
type RequestPayload struct {
	Algorithm string
	Key       string
	Kid       string
	Nonce     string
	Payload   []byte
	Signature []byte
	Encoded   string
}

const (
	MaxJsonPayloadSize = (1 << 24)
)

func CanonicalJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return "", err
	}
	return string(canonical), nil
}

func RawKeyThumbprint(jwkRaw string) ([]byte, error) {
	var jwk jose.JSONWebKey
	if err := json.Unmarshal([]byte(jwkRaw), &jwk); err != nil {
		return nil, fmt.Errorf("parsing JWK: %w", err)
	}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("computing JWK thumbprint: %w", err)
	}
	return thumbprint, nil
}

func ParseJWS(data []byte, url *url.URL, resp http.ResponseWriter, label string) *RequestPayload {
	var body jwsJSONBody
	if err := json.Unmarshal(data, &body); err != nil {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed "+label+" JSON payload")
		return nil
	}
	if body.Protected == "" || body.Signature == "" {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed "+label+" JSON object")
		return nil
	}

	jwsPayload, err := base64.RawURLEncoding.DecodeString(body.Payload)
	if err != nil {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed "+label+" payload")
		return nil
	}

	jwsProtected, err := base64.RawURLEncoding.DecodeString(body.Protected)
	if err != nil {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed "+label+" protected header")
		return nil
	}
	var protected jwsJSONProtected
	if err := json.Unmarshal(jwsProtected, &protected); err != nil || protected.Algorithm == "" || protected.URL == "" {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed "+label+" protected header")
		return nil
	}

	jwsSignature, err := base64.RawURLEncoding.DecodeString(body.Signature)
	if err != nil {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed "+label+" signature")
		return nil
	}

	if protected.URL != url.String() {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed "+label+" request URL")
		return nil
	}

	keyString := ""
	if protected.Key != nil {
		canonical, err := CanonicalJSON(protected.Key)
		if err != nil {
			acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed "+label+" key")
			return nil
		}
		keyString = canonical
	}

	return &RequestPayload{
		Algorithm: protected.Algorithm,
		Key:       keyString,
		Kid:       protected.Kid,
		Nonce:     protected.Nonce,
		Payload:   jwsPayload,
		Signature: jwsSignature,
		Encoded:   fmt.Sprintf("%v.%v", body.Protected, body.Payload),
	}
}

func UnpackAndParseJWS(url *url.URL, req *http.Request, resp http.ResponseWriter) *RequestPayload {
	if ct := req.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/jose+json") {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "expected body of [application/jose+json]")
		return nil
	}

	data, err := io.ReadAll(io.LimitReader(req.Body, MaxJsonPayloadSize))
	if err != nil {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "too large payload")
		return nil
	}

	result := ParseJWS(data, url, resp, "JWS")
	if result == nil {
		return nil
	}

	if result.Nonce == "" || (result.Key == "" && result.Kid == "") {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed JWS protected header")
		return nil
	}

	return result
}

func ValidateJWSWithJWK(payload *RequestPayload, resp http.ResponseWriter, jwkRaw string) bool {
	// parse the JWK
	var jwk jose.JSONWebKey
	if err := json.Unmarshal([]byte(jwkRaw), &jwk); err != nil {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "unsupported JWS key format")
		return false
	}

	// map the algorithm string to a go-jose SignatureAlgorithm
	alg := jose.SignatureAlgorithm(payload.Algorithm)

	// reconstruct the JWS compact serialization so go-jose can verify it
	compactSerialization := fmt.Sprintf("%v.%v", payload.Encoded, base64.RawURLEncoding.EncodeToString(payload.Signature))
	jws, err := jose.ParseSigned(compactSerialization, []jose.SignatureAlgorithm{alg})
	if err != nil {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "unsupported JWS algorithm")
		return false
	}

	// verify the signature
	if _, err := jws.Verify(jwk.Key); err != nil {
		acmeError(resp, http.StatusUnauthorized, AcmeErrUnauthorized, "JWS signature verification failed")
		return false
	}
	return true
}
