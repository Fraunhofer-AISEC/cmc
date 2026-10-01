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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

type challengeHandler func(ch acmeChallenge) (any, error)

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
				if err := s.waitAuthorization(authURL, s.retryAfter(resp)); err != nil {
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
			interval = s.retryAfter(resp)
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
		polled, err := s.waitOrder(&finalized, s.retryAfter(resp))
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

func (c *session) retryAfter(resp *http.Response) time.Duration {
	interval := c.client.pollInterval
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil {
			interval = time.Duration(secs) * time.Second
		} else if t, err := http.ParseTime(v); err == nil {
			interval = time.Until(t)
		}
	}
	return max(min(interval, c.client.maxPollInterval), c.client.pollInterval)
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
		interval = s.retryAfter(resp)
	}
}
