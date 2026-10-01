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
	"fmt"
	"net/http"
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

func (c *Client) CaCerts() ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("ACME provisioner: CaCerts not yet implemented")
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
