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

//go:build !nodefaults || libapi

package attestedtls

import (
	"strings"
	"testing"
)

// TestLibApiRequiresEmbeddedCmc checks that the Lib API fails with a clear
// error instead of silently building an unconfigured CMC when the
// connection has no embedded CMC.
func TestLibApiRequiresEmbeddedCmc(t *testing.T) {

	cc, err := NewCmcConfig()
	if err != nil {
		t.Fatalf("failed to create CMC config: %v", err)
	}
	cc.CmcApi = LibApi{}

	calls := map[string]func() error{
		"obtainAR": func() error {
			_, err := cc.CmcApi.obtainAR(cc, nil, nil)
			return err
		},
		"verifyAR": func() error {
			return cc.CmcApi.verifyAR(cc, nil, nil, nil, "", "")
		},
		"createKey": func() error {
			_, err := cc.CmcApi.createKey(cc)
			return err
		},
		"fetchSignature": func() error {
			_, err := cc.CmcApi.fetchSignature(cc, nil, nil)
			return err
		},
		"fetchCerts": func() error {
			_, err := cc.CmcApi.fetchCerts(cc)
			return err
		},
		"fetchPeerCache": func() error {
			_, err := cc.CmcApi.fetchPeerCache(cc, "")
			return err
		},
	}

	want := "no embedded CMC configured: use WithLibApiCmc"
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			if err == nil {
				t.Fatal("expected an error when no embedded CMC is configured")
			}
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not contain %q", err, want)
			}
		})
	}
}
