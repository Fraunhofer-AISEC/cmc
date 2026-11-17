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
	"errors"
	"fmt"
	"net/http"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision/est"
	log "github.com/sirupsen/logrus"
)

// attestFunc verifies the attestation report of an enrollment request
type attestFunc func() (*ar.AttestationResult, error)

// authorize authenticates a request to an enrollment endpoint with the configured methods. The
// attestation report verifier attest is nil if the request carries no report. A report requires
// attestation to be configured and must verify.
func (s *Server) authorize(endpoint string, req *http.Request, attest attestFunc,
) (*ar.AttestationResult, error) {

	methods, ok := s.auth[endpoint]
	if !ok {
		return nil, fmt.Errorf("no authentication methods configured for %v", endpoint)
	}

	if attest != nil && !methods.Has(internal.AuthAttestation) {
		return nil, fmt.Errorf("request carries an attestation report, but %v is configured "+
			"for %v instead of attestation (configuration mismatch)", methods, endpoint)
	}

	if methods.Has(internal.AuthNone) {
		log.Debugf("Serving %v without client authentication", endpoint)
		return nil, nil
	}

	var errs []error

	if methods.Has(internal.AuthAttestation) {
		if attest == nil {
			errs = append(errs, errors.New("attestation: no attestation report provided"))
		} else {
			result, err := attest()
			if err != nil {
				return nil, fmt.Errorf("attestation: %w", err)
			}
			log.Debugf("Authenticated %v request via attestation", endpoint)
			return result, nil
		}
	}

	if methods.Has(internal.AuthCertificate) {
		if req.TLS == nil || len(req.TLS.VerifiedChains) == 0 {
			errs = append(errs, errors.New("certificate: no verified client certificate"))
		} else {
			log.Debugf("Authenticated %v request via client certificate", endpoint)
			return nil, nil
		}
	}

	if methods.Has(internal.AuthToken) {
		if err := verifyBootStrapToken(s.tokenPath, req); err != nil {
			errs = append(errs, fmt.Errorf("token: %w", err))
		} else {
			log.Debugf("Authenticated %v request via token", endpoint)
			return nil, nil
		}
	}

	if len(errs) == 0 {
		return nil, fmt.Errorf("no applicable authentication method configured for %v", endpoint)
	}
	return nil, errors.Join(errs...)
}

// authorizeReenroll authenticates a /simplereenroll request, which requires all configured
// methods to succeed. The client certificate is always required, as the request renews it. The
// attestation report verifier attest is nil if the request carries no report
func (s *Server) authorizeReenroll(req *http.Request, attest attestFunc,
) (*ar.AttestationResult, error) {

	methods, ok := s.auth[est.ReenrollEndpoint]
	if !ok {
		return nil, fmt.Errorf("no authentication methods configured for %v", est.ReenrollEndpoint)
	}

	if attest != nil && !methods.Has(internal.AuthAttestation) {
		return nil, fmt.Errorf("request carries an attestation report, but %v is configured "+
			"for %v instead of attestation (configuration mismatch)", methods,
			est.ReenrollEndpoint)
	}

	if !methods.Has(internal.AuthCertificate) {
		return nil, fmt.Errorf("certificate authentication not configured for %v",
			est.ReenrollEndpoint)
	}
	if req.TLS == nil || len(req.TLS.VerifiedChains) == 0 {
		return nil, errors.New("certificate: no verified client certificate")
	}

	if !methods.Has(internal.AuthAttestation) {
		log.Debugf("Authenticated %v request via client certificate", est.ReenrollEndpoint)
		return nil, nil
	}
	if attest == nil {
		return nil, errors.New("attestation: no attestation report provided")
	}
	result, err := attest()
	if err != nil {
		return nil, fmt.Errorf("attestation: %w", err)
	}
	log.Debugf("Authenticated %v request via client certificate and attestation",
		est.ReenrollEndpoint)

	return result, nil
}

func verifyBootStrapToken(tokenPath string, req *http.Request) error {

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return fmt.Errorf("missing or invalid authorization header")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	token = strings.TrimSpace(token)

	if err := est.VerifyToken(tokenPath, token, ""); err != nil {
		return fmt.Errorf("failed to verify bootstrap token: %w", err)
	}

	return nil
}
