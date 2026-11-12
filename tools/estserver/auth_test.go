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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"testing"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

func TestAuthorize(t *testing.T) {

	const endpoint = "/test"

	result := &ar.AttestationResult{}
	attestOk := func() (*ar.AttestationResult, error) { return result, nil }
	attestFail := func() (*ar.AttestationResult, error) { return nil, errors.New("invalid report") }

	withCert := httptest.NewRequest("POST", endpoint, nil)
	withCert.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}

	for _, tt := range []struct {
		name       string
		configured bool
		methods    internal.AuthMethod
		cert       bool
		attest     attestFunc
		wantErr    bool
		wantResult bool
	}{
		{"not configured", false, 0, false, nil, true, false},
		{"none", true, internal.AuthNone, false, nil, false, false},
		{"attestation", true, internal.AuthAttestation, false, attestOk, false, true},
		{"attestation fails", true, internal.AuthAttestation, false, attestFail, true, false},
		{"attestation not applicable", true, internal.AuthAttestation, false, nil, true, false},
		{"certificate", true, internal.AuthCertificate, true, nil, false, false},
		{"certificate missing", true, internal.AuthCertificate, false, nil, true, false},
		{"token missing", true, internal.AuthToken, false, nil, true, false},
		{"certificate fallback", true, internal.AuthAttestation | internal.AuthCertificate, true,
			attestFail, false, false},
		{"all fail", true, internal.AuthAttestation | internal.AuthCertificate | internal.AuthToken,
			false, attestFail, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{auth: map[string]internal.AuthMethod{}, tokenPath: t.TempDir()}
			if tt.configured {
				s.auth[endpoint] = tt.methods
			}
			req := httptest.NewRequest("POST", endpoint, nil)
			if tt.cert {
				req = withCert
			}

			r, err := s.authorize(endpoint, req, tt.attest)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, want error %v", err, tt.wantErr)
			}
			if (r != nil) != tt.wantResult {
				t.Errorf("result = %v, want result %v", r, tt.wantResult)
			}
		})
	}
}
