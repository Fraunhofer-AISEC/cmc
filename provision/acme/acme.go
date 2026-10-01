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
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-attestation/attest"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "acmeclient")

const (
	ChallengeSimple         = "cmc-simple-01"
	ChallengeSoftwareAttest = "cmc-software-attest-01"
	ChallengeTpmCertify     = "cmc-tpm-certify-01"
)

const (
	DefaultPollInterval    = 2 * time.Second
	DefaultMaxPollInterval = 30 * time.Second
	DefaultPollTimeout     = 10 * time.Minute
)

type Client struct {
	directory       string
	key             *ecdsa.PrivateKey
	ephemeral       bool
	httpClient      *http.Client
	pollInterval    time.Duration
	maxPollInterval time.Duration
	pollTimeout     time.Duration
}

type Options struct {
	AccountKey       *ecdsa.PrivateKey
	RootCAs          []*x509.Certificate
	AllowSystemCerts bool
	PollInterval     time.Duration
	MaxPollInterval  time.Duration
	PollTimeout      time.Duration
}

func New(directoryURL string, opts Options) (*Client, error) {
	if directoryURL == "" {
		return nil, fmt.Errorf("ACME directory URL must not be empty")
	}

	key, ephemeral := opts.AccountKey, false
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating ephemeral account key: %w", err)
		}
		ephemeral = true
	}

	httpClient, err := internal.NewHttpClient(opts.RootCAs, opts.AllowSystemCerts, nil)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP client: %w", err)
	}

	c := &Client{
		directory:       directoryURL,
		key:             key,
		ephemeral:       ephemeral,
		httpClient:      httpClient,
		pollInterval:    opts.PollInterval,
		maxPollInterval: opts.MaxPollInterval,
		pollTimeout:     opts.PollTimeout,
	}
	if c.pollInterval <= 0 {
		c.pollInterval = DefaultPollInterval
	}
	if c.maxPollInterval <= 0 {
		c.maxPollInterval = DefaultMaxPollInterval
	}
	if c.pollTimeout <= 0 {
		c.pollTimeout = DefaultPollTimeout
	}
	return c, nil
}

type acmeDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}

type acmeProblem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

func (p *acmeProblem) String() string {
	if p == nil {
		return "no error details"
	}
	return fmt.Sprintf("%s (%s)", p.Detail, p.Type)
}

type acmeIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type OrderStatus string
type AuthStatus string
type ChallengeStatus string

const (
	OrderStatusProcessing OrderStatus = "processing"
	OrderStatusValid      OrderStatus = "valid"

	AuthStatusPending AuthStatus = "pending"
	AuthStatusValid   AuthStatus = "valid"

	ChallengeStatusPending    ChallengeStatus = "pending"
	ChallengeStatusProcessing ChallengeStatus = "processing"
	ChallengeStatusValid      ChallengeStatus = "valid"
)

type acmeChallenge struct {
	Type   string          `json:"type"`
	URL    string          `json:"url"`
	Status ChallengeStatus `json:"status"`
	Token  string          `json:"token"`
	Error  *acmeProblem    `json:"error"`
}

type acmeAuth struct {
	Identifier acmeIdentifier  `json:"identifier"`
	Status     AuthStatus      `json:"status"`
	Challenges []acmeChallenge `json:"challenges"`
}

type acmeOrder struct {
	Status         OrderStatus  `json:"status"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate"`
	Error          *acmeProblem `json:"error"`
	URL            string       `json:"-"`
}

type session struct {
	client     *Client
	dir        *acmeDirectory
	accountURL string
	nonce      string
}

func (c *Client) newSession() (*session, error) {
	// fetch the current acme directory with all relevant URLs
	resp, err := c.httpClient.Get(c.directory)
	if err != nil {
		return nil, fmt.Errorf("fetching directory: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("directory returned status %d", resp.StatusCode)
	}
	var dir acmeDirectory
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		return nil, fmt.Errorf("decoding directory: %w", err)
	}
	if dir.NewNonce == "" || dir.NewAccount == "" || dir.NewOrder == "" {
		return nil, fmt.Errorf("directory is missing required resources")
	}
	s := &session{client: c, dir: &dir}

	// check if an account key was provided, in which case we first need to check if an account URL for it already exists
	if !c.ephemeral {
		resp, _, err := s.signedPost(s.dir.NewAccount, map[string]any{
			"onlyReturnExisting": true,
		})
		if err != nil {
			return nil, fmt.Errorf("looking up existing account: %w", err)
		}
		if resp.StatusCode == http.StatusOK {
			s.accountURL = resp.Header.Get("Location")
			if s.accountURL == "" {
				return nil, fmt.Errorf("no Location header in account lookup response")
			}
			log.Debug("Found existing ACME account")
			return s, nil
		}
		log.Debug("No existing account found, creating new one")
	}

	// request the new account (IMPORTANT: tos are automatically accepted!)
	resp, body, err := s.signedPost(s.dir.NewAccount, map[string]any{
		"termsOfServiceAgreed": true,
	})
	if err != nil {
		return nil, fmt.Errorf("creating account: %w", err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("account creation failed (status %d): %s", resp.StatusCode, body)
	}
	s.accountURL = resp.Header.Get("Location")
	if s.accountURL == "" {
		return nil, fmt.Errorf("no Location header in account creation response")
	}
	log.Debug("Created new ACME account")
	return s, nil
}

func (s *session) fetchNonce() (string, error) {
	nonce := s.nonce
	s.nonce = ""

	if nonce != "" {
		return nonce, nil
	}

	resp, err := s.client.httpClient.Head(s.dir.NewNonce)
	if err != nil {
		return "", fmt.Errorf("fetching nonce: %w", err)
	}
	resp.Body.Close()

	nonce = resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", fmt.Errorf("no Replay-Nonce in response")
	}
	return nonce, nil
}

type staticNonce string

func (n staticNonce) Nonce() (string, error) { return string(n), nil }

func (s *session) signedPost(url string, payload any) (*http.Response, []byte, error) {
	var payloadBytes []byte
	if payload != nil {
		var err error
		payloadBytes, err = json.Marshal(payload)
		if err != nil {
			return nil, nil, fmt.Errorf("marshaling payload: %w", err)
		}
	} else {
		payloadBytes = []byte{}
	}

	nonce, err := s.fetchNonce()
	if err != nil {
		return nil, nil, err
	}

	opts := (&jose.SignerOptions{
		NonceSource: staticNonce(nonce),
	}).WithHeader("url", url)

	// check if an account already exists and embed the id into the protected header
	var signingKey jose.SigningKey
	if s.accountURL == "" {
		opts.EmbedJWK = true
		signingKey = jose.SigningKey{Algorithm: jose.ES256, Key: s.client.key}
	} else {
		signingKey = jose.SigningKey{
			Algorithm: jose.ES256,
			Key:       &jose.JSONWebKey{Key: s.client.key, KeyID: s.accountURL, Algorithm: string(jose.ES256)},
		}
	}

	signer, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("creating signer: %w", err)
	}

	jws, err := signer.Sign(payloadBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("signing payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(jws.FullSerialize()))
	if err != nil {
		return nil, nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/jose+json")

	resp, err := s.client.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("performing request: %w", err)
	}
	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("reading response body: %w", err)
	}

	// check if the response contained a new nonce to be used for the upcoming requests
	if nonce = resp.Header.Get("Replay-Nonce"); nonce != "" {
		s.nonce = nonce
	}
	return resp, respBody, nil
}

func (c *Client) CaCerts() ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("ACME provisioner: CaCerts not yet implemented")
}

func (s *session) createOrder(csr *x509.CertificateRequest) (*acmeOrder, error) {
	identifiers := make([]acmeIdentifier, 0, len(csr.DNSNames))
	for _, name := range csr.DNSNames {
		identifiers = append(identifiers, acmeIdentifier{Type: "dns", Value: name})
	}
	resp, body, err := s.signedPost(s.dir.NewOrder, map[string]any{
		"identifiers": identifiers,
	})
	if err != nil {
		return nil, fmt.Errorf("creating order: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("order creation failed (status %d): %s", resp.StatusCode, body)
	}

	var order acmeOrder
	if err := json.Unmarshal(body, &order); err != nil {
		return nil, fmt.Errorf("decoding order response: %w", err)
	}
	order.URL = resp.Header.Get("Location")
	log.Debugf("Created order with %d authorization(s)", len(order.Authorizations))
	return &order, nil
}

type challengeHandler func(ch acmeChallenge) (any, error)

func (s *session) completeChallenges(authURLs []string, handler challengeHandler) error {
	for _, authURL := range authURLs {
		auth, _, err := s.fetchAuthorization(authURL)
		if err != nil {
			return err
		}

		if auth.Status == AuthStatusValid {
			continue
		}
		if auth.Status != AuthStatusPending {
			return fmt.Errorf("authorization for %s is in state %q", auth.Identifier.Value, auth.Status)
		}

		completed := false
		for _, ch := range auth.Challenges {
			payload, err := handler(ch)
			if err != nil {
				return fmt.Errorf("preparing response for challenge %q: %w", ch.Type, err)
			}
			if payload == nil {
				continue
			}

			resp, body, err := s.signedPost(ch.URL, payload)
			if err != nil {
				return fmt.Errorf("responding to %s challenge: %w", ch.Type, err)
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("%s challenge failed (status %d): %s", ch.Type, resp.StatusCode, body)
			}

			var updated acmeChallenge
			if err := json.Unmarshal(body, &updated); err != nil {
				return fmt.Errorf("decoding %s challenge response: %w", ch.Type, err)
			}

			if updated.Status == ChallengeStatusPending || updated.Status == ChallengeStatusProcessing {
				if err := s.waitAuthorization(authURL, s.client.retryAfter(resp)); err != nil {
					return fmt.Errorf("%s challenge: %w", ch.Type, err)
				}
			} else if updated.Status != ChallengeStatusValid {
				return fmt.Errorf("%s challenge failed with status %q: %s", ch.Type, updated.Status, updated.Error)
			}

			completed = true
			break
		}
		if !completed {
			return fmt.Errorf("no supported challenge type found in authorization for %s", auth.Identifier.Value)
		}
	}
	return nil
}

func (s *session) fetchAuthorization(authURL string) (*acmeAuth, *http.Response, error) {
	resp, body, err := s.signedPost(authURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching authorization: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("authorization fetch failed (status %d): %s", resp.StatusCode, body)
	}
	var auth acmeAuth
	if err := json.Unmarshal(body, &auth); err != nil {
		return nil, nil, fmt.Errorf("decoding authorization: %w", err)
	}
	return &auth, resp, nil
}

func (s *session) waitAuthorization(authURL string, interval time.Duration) error {
	deadline := time.Now().Add(s.client.pollTimeout)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for authorization %s to be validated", authURL)
		}
		log.Debugf("Authorization is pending, polling again in %v", interval)
		time.Sleep(interval)

		auth, resp, err := s.fetchAuthorization(authURL)
		if err != nil {
			return fmt.Errorf("polling authorization: %w", err)
		}

		if auth.Status == AuthStatusValid {
			return nil
		} else if auth.Status == AuthStatusPending {
			interval = s.client.retryAfter(resp)
			continue
		}

		// report the error of the failed challenge, if the server provided one
		for _, ch := range auth.Challenges {
			if ch.Error != nil {
				return fmt.Errorf("authorization for %s failed with status %q: %s", auth.Identifier.Value, auth.Status, ch.Error)
			}
		}
		return fmt.Errorf("authorization for %s failed with status %q", auth.Identifier.Value, auth.Status)
	}
}

func (s *session) finalizeAndDownload(csr *x509.CertificateRequest, order *acmeOrder) ([]*x509.Certificate, error) {
	resp, body, err := s.signedPost(order.Finalize, map[string]any{
		"csr": base64.RawURLEncoding.EncodeToString(csr.Raw),
	})
	if err != nil {
		return nil, fmt.Errorf("finalizing order: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("order finalization failed (status %d): %s", resp.StatusCode, body)
	}

	var finalized acmeOrder
	if err := json.Unmarshal(body, &finalized); err != nil {
		return nil, fmt.Errorf("decoding finalized order: %w", err)
	}
	finalized.URL = order.URL
	if finalized.URL == "" {
		finalized.URL = resp.Header.Get("Location")
	}

	if finalized.Status == OrderStatusProcessing {
		polled, err := s.waitOrder(&finalized, s.client.retryAfter(resp))
		if err != nil {
			return nil, err
		}
		finalized = *polled
	}

	if finalized.Status != OrderStatusValid {
		return nil, fmt.Errorf("order finalization failed with status %q: %s", finalized.Status, finalized.Error)
	}
	if finalized.Certificate == "" {
		return nil, fmt.Errorf("finalized order has no certificate URL")
	}

	resp, body, err = s.signedPost(finalized.Certificate, nil)
	if err != nil {
		return nil, fmt.Errorf("downloading certificate: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certificate download failed (status %d): %s", resp.StatusCode, body)
	}

	var chain []*x509.Certificate
	for {
		var block *pem.Block
		block, body = pem.Decode(body)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing issued certificate chain: %w", err)
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificate found in response")
	}

	log.Debugf("Downloaded certificate chain with %d certificate(s)", len(chain))
	return chain, nil
}

func (c *Client) retryAfter(resp *http.Response) time.Duration {
	interval := c.pollInterval
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil {
			interval = time.Duration(secs) * time.Second
		} else if t, err := http.ParseTime(v); err == nil {
			interval = time.Until(t)
		}
	}
	return max(min(interval, c.maxPollInterval), c.pollInterval)
}

func (s *session) waitOrder(order *acmeOrder, interval time.Duration) (*acmeOrder, error) {
	if order.URL == "" {
		return nil, fmt.Errorf("order is processing but no order URL is known for polling")
	}
	deadline := time.Now().Add(s.client.pollTimeout)
	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for order %s to be processed", order.URL)
		}
		log.Debugf("Order is processing, polling again in %v", interval)
		time.Sleep(interval)

		resp, body, err := s.signedPost(order.URL, nil)
		if err != nil {
			return nil, fmt.Errorf("polling order: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("order poll failed (status %d): %s", resp.StatusCode, body)
		}

		var polled acmeOrder
		if err := json.Unmarshal(body, &polled); err != nil {
			return nil, fmt.Errorf("decoding polled order: %w", err)
		}
		polled.URL = order.URL
		if polled.Status != OrderStatusProcessing {
			return &polled, nil
		}
		interval = s.client.retryAfter(resp)
	}
}

func (c *Client) accountThumbprint() ([]byte, error) {
	jwk := jose.JSONWebKey{Key: c.key.Public(), Algorithm: string(jose.ES256)}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("computing JWK thumbprint: %w", err)
	}
	return thumbprint, nil
}

func (c *Client) keyAuthorizationToken(token string) (string, error) {
	thumbprint, err := c.accountThumbprint()
	if err != nil {
		return "", err
	}
	return token + "." + base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

func (c *Client) keyAuthorizationCSR(token string, csr *x509.CertificateRequest) ([]byte, error) {
	thumbprint, err := c.accountThumbprint()
	if err != nil {
		return nil, err
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

func (c *Client) enroll(csr *x509.CertificateRequest, handler challengeHandler) ([]*x509.Certificate, error) {
	s, err := c.newSession()
	if err != nil {
		return nil, err
	}

	order, err := s.createOrder(csr)
	if err != nil {
		return nil, err
	}

	if err := s.completeChallenges(order.Authorizations, handler); err != nil {
		return nil, err
	}

	return s.finalizeAndDownload(csr, order)
}

func (c *Client) SimpleEnroll(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	chain, err := c.enroll(csr, func(ch acmeChallenge) (any, error) {
		if ch.Type != ChallengeSimple {
			return nil, nil
		}

		keyAuth, err := c.keyAuthorizationToken(ch.Token)
		if err != nil {
			return nil, fmt.Errorf("computing key authorization: %w", err)
		}
		return map[string]any{
			"authorization": keyAuth,
		}, nil
	})

	if err != nil {
		return nil, err
	}
	log.Debug("ACME simple enrollment completed successfully")
	return chain[0], nil
}

func (c *Client) TpmCertifyEnroll(
	csr *x509.CertificateRequest,
	ikParams attest.CertificationParameters,
	akPublic []byte,
	generateReport func(nonce []byte) ([]byte, error),
) (*x509.Certificate, error) {
	chain, err := c.enroll(csr, func(ch acmeChallenge) (any, error) {
		if ch.Type != ChallengeTpmCertify {
			return nil, nil
		}

		keyAuth, err := c.keyAuthorizationCSR(ch.Token, csr)
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
	return chain[0], nil
}

func (c *Client) AttestEnroll(csr *x509.CertificateRequest, generateReport func(nonce []byte) ([]byte, error)) (*x509.Certificate, error) {
	chain, err := c.enroll(csr, func(ch acmeChallenge) (any, error) {
		if ch.Type != ChallengeSoftwareAttest {
			return nil, nil
		}

		keyAuth, err := c.keyAuthorizationCSR(ch.Token, csr)
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
	return chain[0], nil
}
