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

package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-attestation/attest"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "acmeclient")

type Client struct {
	directory  string
	key        *ecdsa.PrivateKey
	ephemeral  bool
	httpClient *http.Client
}

func New(addr string, key *ecdsa.PrivateKey) (*Client, error) {
	ephemeral := false
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating ephemeral account key: %w", err)
		}
		ephemeral = true
	}
	return &Client{
		directory:  addr,
		key:        key,
		ephemeral:  ephemeral,
		httpClient: &http.Client{},
	}, nil
}

type acmeDirectory struct {
	newNonce   string
	newAccount string
	newOrder   string
}

type acmeChallenge struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Status string `json:"status"`
	Token  string `json:"token"`
}

type acmeAuth struct {
	Status     string          `json:"status"`
	Challenges []acmeChallenge `json:"challenges"`
}

type acmeOrder struct {
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
}

func (c *Client) fetchDirectory() (*acmeDirectory, error) {
	resp, err := c.httpClient.Get(c.directory)
	if err != nil {
		return nil, fmt.Errorf("fetching directory: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("directory returned status %d", resp.StatusCode)
	}
	var body struct {
		NewNonce   string `json:"newNonce"`
		NewAccount string `json:"newAccount"`
		NewOrder   string `json:"newOrder"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decoding directory: %w", err)
	}
	return &acmeDirectory{
		newNonce:   body.NewNonce,
		newAccount: body.NewAccount,
		newOrder:   body.NewOrder,
	}, nil
}

func (c *Client) fetchNonce(nonceURL string) (string, error) {
	resp, err := c.httpClient.Head(nonceURL)
	if err != nil {
		return "", fmt.Errorf("fetching nonce: %w", err)
	}
	resp.Body.Close()
	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", fmt.Errorf("no Replay-Nonce in response")
	}
	return nonce, nil
}

type staticNonce string

func (n staticNonce) Nonce() (string, error) { return string(n), nil }

func (c *Client) signedPost(url string, nonce *string, nonceURL, accountURL string, payload any) (*http.Response, []byte, *string, error) {
	var n string

	// check if a nonce is already available and otherwise fetch a new nonce to be used for this signed post-message
	if nonce != nil {
		n = *nonce
	} else {
		var err error
		n, err = c.fetchNonce(nonceURL)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("fetching nonce: %w", err)
		}
	}
	var payloadBytes []byte
	if payload != nil {
		var err error
		payloadBytes, err = json.Marshal(payload)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("marshaling payload: %w", err)
		}
	} else {
		payloadBytes = []byte{}
	}

	opts := (&jose.SignerOptions{
		NonceSource: staticNonce(n),
	}).WithHeader("url", url)

	// check if an account already exists and embed the id into the protected header
	var signingKey jose.SigningKey
	if accountURL == "" {
		opts.EmbedJWK = true
		signingKey = jose.SigningKey{Algorithm: jose.ES256, Key: c.key}
	} else {
		signingKey = jose.SigningKey{
			Algorithm: jose.ES256,
			Key:       &jose.JSONWebKey{Key: c.key, KeyID: accountURL, Algorithm: string(jose.ES256)},
		}
	}

	signer, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating signer: %w", err)
	}

	jws, err := signer.Sign(payloadBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("signing payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(jws.FullSerialize()))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/jose+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("performing request: %w", err)
	}
	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading response body: %w", err)
	}

	// check if the response contained a new nonce to be used for the upcoming requests
	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		return resp, respBody, &n, nil
	}
	return resp, respBody, nil, nil
}

func (c *Client) ensureAccount(newAccountURL, nonceURL string, nonce *string) (string, *string, error) {
	// check if an account key was provided, in which case we first need to check if an account URL for it already exists
	if !c.ephemeral {
		resp, _, nextNonce, err := c.signedPost(newAccountURL, nonce, nonceURL, "", map[string]any{
			"onlyReturnExisting": true,
		})
		if err != nil {
			return "", nextNonce, fmt.Errorf("looking up existing account: %w", err)
		}
		if resp.StatusCode == http.StatusOK {
			loc := resp.Header.Get("Location")
			if loc == "" {
				return "", nextNonce, fmt.Errorf("no Location header in account lookup response")
			}
			log.Debug("Found existing ACME account")
			return loc, nextNonce, nil
		}
		log.Debug("No existing account found, creating new one")
		nonce = nextNonce
	}

	// important: tos are automatically accepted!
	resp, body, nextNonce, err := c.signedPost(newAccountURL, nonce, nonceURL, "", map[string]any{
		"termsOfServiceAgreed": true,
	})
	if err != nil {
		return "", nextNonce, fmt.Errorf("creating account: %w", err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", nextNonce, fmt.Errorf("account creation failed (status %d): %s", resp.StatusCode, body)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", nextNonce, fmt.Errorf("no Location header in account creation response")
	}
	log.Debug("Created new ACME account")
	return loc, nextNonce, nil
}

func (c *Client) CaCerts() ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("ACME provisioner: CaCerts not yet implemented")
}

func (c *Client) createOrder(csr *x509.CertificateRequest, nonce *string, dir *acmeDirectory, accountURL string) (*acmeOrder, *string, error) {
	identifiers := make([]map[string]string, len(csr.DNSNames))
	for i, name := range csr.DNSNames {
		identifiers[i] = map[string]string{"type": "dns", "value": name}
	}
	resp, body, nonce, err := c.signedPost(dir.newOrder, nonce, dir.newNonce, accountURL, map[string]any{
		"identifiers": identifiers,
	})
	if err != nil {
		return nil, nonce, fmt.Errorf("creating order: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, nonce, fmt.Errorf("order creation failed (status %d): %s", resp.StatusCode, body)
	}

	var order acmeOrder
	if err := json.Unmarshal(body, &order); err != nil {
		return nil, nonce, fmt.Errorf("decoding order response: %w", err)
	}
	log.Debugf("Created order with %d authorization(s)", len(order.Authorizations))
	return &order, nonce, nil
}

type challengeHandler func(ch acmeChallenge) (any, error)

func (c *Client) completeChallenges(authURLs []string, handler challengeHandler, nonce *string, dir *acmeDirectory, accountURL string) (*string, error) {
	for _, authURL := range authURLs {
		resp, body, nextNonce, err := c.signedPost(authURL, nonce, dir.newNonce, accountURL, nil)
		nonce = nextNonce
		if err != nil {
			return nonce, fmt.Errorf("fetching authorization: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nonce, fmt.Errorf("authorization fetch failed (status %d): %s", resp.StatusCode, body)
		}

		var auth acmeAuth
		if err := json.Unmarshal(body, &auth); err != nil {
			return nonce, fmt.Errorf("decoding authorization: %w", err)
		}

		if auth.Status == "valid" {
			continue
		}

		completed := false
		for _, ch := range auth.Challenges {
			payload, err := handler(ch)
			if err != nil {
				return nonce, fmt.Errorf("preparing response for challenge %q: %w", ch.Type, err)
			}
			if payload == nil {
				continue
			}

			resp, body, nextNonce, err = c.signedPost(ch.URL, nonce, dir.newNonce, accountURL, payload)
			nonce = nextNonce
			if err != nil {
				return nonce, fmt.Errorf("responding to %s challenge: %w", ch.Type, err)
			}
			if resp.StatusCode != http.StatusOK {
				return nonce, fmt.Errorf("%s challenge failed (status %d): %s", ch.Type, resp.StatusCode, body)
			}
			completed = true
			break
		}
		if !completed {
			return nonce, fmt.Errorf("no supported challenge type found in authorization")
		}
	}
	return nonce, nil
}

func (c *Client) finalizeAndDownload(csr *x509.CertificateRequest, order *acmeOrder, nonce *string, dir *acmeDirectory, accountURL string) (*x509.Certificate, error) {
	csrB64 := base64.RawURLEncoding.EncodeToString(csr.Raw)
	resp, body, nonce, err := c.signedPost(order.Finalize, nonce, dir.newNonce, accountURL, map[string]any{
		"csr": csrB64,
	})
	if err != nil {
		return nil, fmt.Errorf("finalizing order: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("order finalization failed (status %d): %s", resp.StatusCode, body)
	}

	var finalized struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(body, &finalized); err != nil {
		return nil, fmt.Errorf("decoding finalized order: %w", err)
	}
	if finalized.Certificate == "" {
		return nil, fmt.Errorf("finalized order has no certificate URL")
	}

	resp, body, _, err = c.signedPost(finalized.Certificate, nonce, dir.newNonce, accountURL, nil)
	if err != nil {
		return nil, fmt.Errorf("downloading certificate: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certificate download failed (status %d): %s", resp.StatusCode, body)
	}

	block, _ := pem.Decode(body)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in certificate response")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing issued certificate: %w", err)
	}
	return cert, nil
}

func (c *Client) keyAuthorizationCSRNonce(token string, csr *x509.CertificateRequest) ([]byte, error) {
	jwk := jose.JSONWebKey{Key: c.key.Public(), Algorithm: string(jose.ES256)}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("computing JWK thumbprint: %w", err)
	}
	pubKeyDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling CSR public key: %w", err)
	}
	pubKeyHash := sha256.Sum256(pubKeyDER)
	keyAuth := token + "." + base64.RawURLEncoding.EncodeToString(thumbprint) + "." + base64.RawURLEncoding.EncodeToString(pubKeyHash[:])
	hash := sha256.Sum256([]byte(keyAuth))
	return hash[:], nil
}

func (c *Client) enroll(csr *x509.CertificateRequest, handler challengeHandler) (*x509.Certificate, error) {
	dir, err := c.fetchDirectory()
	if err != nil {
		return nil, fmt.Errorf("fetching directory: %w", err)
	}

	accountURL, nonce, err := c.ensureAccount(dir.newAccount, dir.newNonce, nil)
	if err != nil {
		return nil, fmt.Errorf("ensuring account: %w", err)
	}

	order, nonce, err := c.createOrder(csr, nonce, dir, accountURL)
	if err != nil {
		return nil, err
	}

	nonce, err = c.completeChallenges(order.Authorizations, handler, nonce, dir, accountURL)
	if err != nil {
		return nil, err
	}

	return c.finalizeAndDownload(csr, order, nonce, dir, accountURL)
}

func (c *Client) SimpleEnroll(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	return nil, errors.New("SimpleEnroll for ACME is not yet implemented")
}

func (c *Client) TpmCertifyEnroll(
	csr *x509.CertificateRequest,
	ikParams attest.CertificationParameters,
	akPublic []byte,
	generateReport func(nonce []byte) ([]byte, error),
) (*x509.Certificate, error) {
	cert, err := c.enroll(csr, func(ch acmeChallenge) (any, error) {
		if ch.Type != "cmc-tpm-certify-01" {
			return nil, nil
		}
		keyAuth, err := c.keyAuthorizationCSRNonce(ch.Token, csr)
		if err != nil {
			return nil, fmt.Errorf("computing key authorization: %w", err)
		}
		report, err := generateReport(keyAuth)
		if err != nil {
			return nil, fmt.Errorf("generating attestation report: %w", err)
		}
		b64 := base64.RawURLEncoding.EncodeToString
		return map[string]any{
			"report":              b64(report),
			"csr":                 b64(csr.Raw),
			"akPublic":            b64(akPublic),
			"ikPublic":            b64(ikParams.Public),
			"ikCreateData":        b64(ikParams.CreateData),
			"ikCreateAttestation": b64(ikParams.CreateAttestation),
			"ikCreateSignature":   b64(ikParams.CreateSignature),
		}, nil
	})
	if err != nil {
		return nil, err
	}

	log.Debug("ACME TPM certify enrollment completed successfully")
	return cert, nil
}

func (c *Client) AttestEnroll(csr *x509.CertificateRequest, generateReport func(nonce []byte) ([]byte, error)) (*x509.Certificate, error) {
	cert, err := c.enroll(csr, func(ch acmeChallenge) (any, error) {
		if ch.Type != "cmc-software-attest-01" {
			return nil, nil
		}
		keyAuth, err := c.keyAuthorizationCSRNonce(ch.Token, csr)
		if err != nil {
			return nil, fmt.Errorf("computing key authorization: %w", err)
		}
		report, err := generateReport(keyAuth)
		if err != nil {
			return nil, fmt.Errorf("generating attestation report: %w", err)
		}
		return map[string]any{
			"report": base64.RawURLEncoding.EncodeToString(report),
			"csr":    base64.RawURLEncoding.EncodeToString(csr.Raw),
		}, nil
	})
	if err != nil {
		return nil, err
	}

	log.Debug("ACME attestation enrollment completed successfully")
	return cert, nil
}
