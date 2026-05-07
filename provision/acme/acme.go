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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/go-attestation/attest"
	"github.com/go-jose/go-jose/v4"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "acmeclient")

type Client struct {
	directory  string
	key        *ecdsa.PrivateKey
	ephemeral  bool
	httpClient *http.Client
}

// New creates a new ACME provisioner client. If key is nil, an ephemeral ECDSA
// P-256 key is generated and SimpleEnroll will always create a new account. If
// a key is provided, SimpleEnroll will first attempt to look up an existing
// account before creating one.
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

// signedPost sends a JWS-signed POST to the given URL. If nonce is nil, a fresh nonce is fetched from nonceURL.
// If accountURL is empty, the public key is embedded in the protected header (for new-account requests). Otherwise kid is set to accountURL.
// Returns the fresh nonce from the Replay-Nonce response header, or nil if none was present.
func (c *Client) signedPost(url string, nonce *string, nonceURL, accountURL string, payload any) (*http.Response, []byte, *string, error) {
	var n string
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

	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		return resp, respBody, &n, nil
	}
	return resp, respBody, nil, nil
}

// ensureAccount either looks up an existing account (when a key was provided externally) or creates a new one (when the key is ephemeral).
func (c *Client) ensureAccount(newAccountURL, nonceURL string, nonce *string) (string, *string, error) {
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

// automatically agrees to ToS
func (c *Client) SimpleEnroll(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	dir, err := c.fetchDirectory()
	if err != nil {
		return nil, fmt.Errorf("fetching directory: %w", err)
	}

	accountURL, nonce, err := c.ensureAccount(dir.newAccount, dir.newNonce, nil)
	if err != nil {
		return nil, fmt.Errorf("ensuring account: %w", err)
	}

	// Create order with DNS identifiers from the CSR
	dnsNames := csr.DNSNames
	identifiers := make([]map[string]string, len(dnsNames))
	for i, name := range dnsNames {
		identifiers[i] = map[string]string{"type": "dns", "value": name}
	}
	resp, body, nonce, err := c.signedPost(dir.newOrder, nonce, dir.newNonce, accountURL, map[string]any{
		"identifiers": identifiers,
	})
	if err != nil {
		return nil, fmt.Errorf("creating order: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("order creation failed (status %d): %s", resp.StatusCode, body)
	}

	var order struct {
		Status         string   `json:"status"`
		Authorizations []string `json:"authorizations"`
		Finalize       string   `json:"finalize"`
		Certificate    string   `json:"certificate"`
	}
	if err := json.Unmarshal(body, &order); err != nil {
		return nil, fmt.Errorf("decoding order response: %w", err)
	}
	log.Debugf("Created order with %d authorization(s)", len(order.Authorizations))

	// Complete challenges for each authorization
	for _, authURL := range order.Authorizations {
		resp, body, nonce, err = c.signedPost(authURL, nonce, dir.newNonce, accountURL, nil)
		if err != nil {
			return nil, fmt.Errorf("fetching authorization: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("authorization fetch failed (status %d): %s", resp.StatusCode, body)
		}

		var auth struct {
			Status     string `json:"status"`
			Challenges []struct {
				URL    string `json:"url"`
				Status string `json:"status"`
			} `json:"challenges"`
		}
		if err := json.Unmarshal(body, &auth); err != nil {
			return nil, fmt.Errorf("decoding authorization: %w", err)
		}

		if auth.Status == "valid" {
			continue
		}
		if len(auth.Challenges) == 0 {
			return nil, fmt.Errorf("authorization has no challenges")
		}

		for index, challenge := range auth.Challenges {
			resp, body, nonce, err = c.signedPost(challenge.URL, nonce, dir.newNonce, accountURL, map[string]any{})
			if err != nil {
				return nil, fmt.Errorf("responding to challenge[%d]: %w", index, err)
			}
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("challenge[%d] response failed (status %d): %s", index, resp.StatusCode, body)
			}
		}
	}

	// Finalize order with the CSR
	csrB64 := base64.RawURLEncoding.EncodeToString(csr.Raw)
	resp, body, nonce, err = c.signedPost(order.Finalize, nonce, dir.newNonce, accountURL, map[string]any{
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

	// Download the issued certificate
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

	log.Debug("ACME enrollment completed successfully")
	return cert, nil
}

func (c *Client) TpmActivateEnroll(
	tpmManufacturer, ekCertUrl string,
	tpmMajor, tpmMinor int,
	csr *x509.CertificateRequest,
	akParams attest.AttestationParameters,
	ekPublic, ekCertDer []byte,
) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, fmt.Errorf("ACME provisioner: TpmActivateEnroll not yet implemented")
}

func (c *Client) TpmCertifyEnroll(
	csr *x509.CertificateRequest,
	ikParams attest.CertificationParameters,
	akPublic []byte,
	report []byte,
	metadata [][]byte,
) (*x509.Certificate, error) {
	return nil, fmt.Errorf("ACME provisioner: TpmCertifyEnroll not yet implemented")
}

func (c *Client) CcEnroll(csr *x509.CertificateRequest, report []byte, metadata [][]byte) (*x509.Certificate, error) {
	return nil, fmt.Errorf("ACME provisioner: CcEnroll not yet implemented")
}

func (c *Client) GetSnpCa(codeName string, akType internal.AkType) ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("ACME provisioner: GetSnpCa not yet implemented")
}

func (c *Client) GetSnpVcek(codeName string, chipId [64]byte, tcb uint64) (*x509.Certificate, error) {
	return nil, fmt.Errorf("ACME provisioner: GetSnpVcek not yet implemented")
}
