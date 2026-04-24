package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
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

func UnpackAndParseJWS(url *url.URL, req *http.Request, resp http.ResponseWriter) *RequestPayload {
	if ct := req.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/jose+json") {
		http.Error(resp, "Expected body of [application/jose+json]", http.StatusBadRequest)
		return nil
	}

	jwsBody, err := io.ReadAll(io.LimitReader(req.Body, MaxJsonPayloadSize))
	if err != nil {
		http.Error(resp, "Too large payload", http.StatusBadRequest)
		return nil
	}

	// unpack the overall body
	var body jwsJSONBody
	if err := json.Unmarshal(jwsBody, &body); err != nil {
		http.Error(resp, "malformed JWS JSON payload", http.StatusBadRequest)
		return nil
	}
	if body.Protected == "" || body.Signature == "" {
		http.Error(resp, "malformed JWS JSON object", http.StatusBadRequest)
		return nil
	}

	// unpack the payload
	jwsPayload, err := base64.RawURLEncoding.DecodeString(body.Payload)
	if err != nil {
		http.Error(resp, "malformed JWS payload", http.StatusBadRequest)
		return nil
	}

	// unpack the protected field (key or kid can be empty)
	jwsProtected, err := base64.RawURLEncoding.DecodeString(body.Protected)
	if err != nil {
		http.Error(resp, "malformed JWS Protected", http.StatusBadRequest)
		return nil
	}
	var protected jwsJSONProtected
	if err := json.Unmarshal(jwsProtected, &protected); err != nil || protected.Algorithm == "" || protected.Nonce == "" || protected.URL == "" || (protected.Key == nil && protected.Kid == "") {
		http.Error(resp, "malformed JWS Protected", http.StatusBadRequest)
		return nil
	}

	// unpack the signature
	jwsSignature, err := base64.RawURLEncoding.DecodeString(body.Signature)
	if err != nil {
		http.Error(resp, "malformed JWS signature", http.StatusBadRequest)
		return nil
	}

	// validate the request url
	if protected.URL != url.String() {
		http.Error(resp, "malformed JWS request URL", http.StatusBadRequest)
		return nil
	}

	// re-serialize the key to the correct format
	keyString := ""
	if protected.Key != nil {
		key, err := json.Marshal(protected.Key)
		if err != nil {
			http.Error(resp, "malformed JWS Protected", http.StatusBadRequest)
			return nil
		}
		keyString = string(key)
	}

	// construct the final parsed payload object
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

func ValidateJWSWithJWK(payload *RequestPayload, resp http.ResponseWriter, jwkRaw string) bool {
	// parse the signature algorithm
	alg, ok := jwa.LookupSignatureAlgorithm(payload.Algorithm)
	if !ok {
		http.Error(resp, "Unsupported JWS algorithm", http.StatusBadRequest)
		return false
	}
	verifier, err := jws.VerifierFor(alg)
	if err != nil {
		http.Error(resp, "Unsupported JWS algorithm", http.StatusBadRequest)
		return false
	}

	// parse the key itself
	key, err := jwk.ParseKey([]byte(jwkRaw))
	if err != nil {
		http.Error(resp, "Unsupported JWS key format", http.StatusBadRequest)
		return false
	}

	// verify the signature for the given payload
	if verifier.Verify(key, []byte(payload.Encoded), payload.Signature) != nil {
		http.Error(resp, "JWS payload verification error", http.StatusBadRequest)
		return false
	}
	return true
}
