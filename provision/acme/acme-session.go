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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

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
