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

package endorser

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

const intelRootCrlUrl = "https://certificates.trustedservices.intel.com" + IntelRootCaCrlPath

func TestRootCrlUrls(t *testing.T) {

	tests := []struct {
		name         string
		baseUrl      string
		proxyRootCrl bool
		urls         []string
		expected     []string
	}{
		{
			name:     "direct mode uses the distribution points",
			baseUrl:  PcsUrl,
			urls:     []string{intelRootCrlUrl},
			expected: []string{intelRootCrlUrl},
		},
		{
			name:         "cps mode prefers the proxy",
			baseUrl:      "https://est.example.com:9000",
			proxyRootCrl: true,
			urls:         []string{intelRootCrlUrl},
			expected: []string{
				"https://est.example.com:9000" + IntelRootCaCrlPath,
				intelRootCrlUrl,
			},
		},
		{
			name:         "cps mode keeps all distribution points as fallback",
			baseUrl:      "https://est.example.com:9000",
			proxyRootCrl: true,
			urls: []string{
				"https://certificates.trustedservices.intel.com/IntelSGXRootCA-v2.der",
				intelRootCrlUrl,
			},
			expected: []string{
				"https://est.example.com:9000/IntelSGXRootCA-v2.der",
				"https://est.example.com:9000" + IntelRootCaCrlPath,
				"https://certificates.trustedservices.intel.com/IntelSGXRootCA-v2.der",
				intelRootCrlUrl,
			},
		},
		{
			name:         "query parameters are not forwarded to the proxy",
			baseUrl:      "https://est.example.com:9000",
			proxyRootCrl: true,
			urls:         []string{intelRootCrlUrl + "?version=2"},
			expected: []string{
				"https://est.example.com:9000" + IntelRootCaCrlPath,
				intelRootCrlUrl + "?version=2",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endorser := &TdxEndorser{
				baseUrl:      test.baseUrl,
				proxyRootCrl: test.proxyRootCrl,
			}
			got := endorser.rootCrlUrls(test.urls)
			if !slices.Equal(got, test.expected) {
				t.Errorf("root CA CRL locations are %v, expected %v", got, test.expected)
			}
		})
	}
}

func TestValidateFmspc(t *testing.T) {

	valid := []string{"90c06f000000", "90C06F000000", "000000000000"}
	for _, fmspc := range valid {
		if err := ValidateFmspc(fmspc); err != nil {
			t.Errorf("fmspc %q was rejected: %v", fmspc, err)
		}
	}

	invalid := []string{"", "90c06f0000", "90c06f00000000", "90c06f00000z", "../../../etc"}
	for _, fmspc := range invalid {
		if err := ValidateFmspc(fmspc); err == nil {
			t.Errorf("fmspc %q was accepted", fmspc)
		}
	}
}

// TestCacheKeys ensures that cache keys cannot escape the cache folder, as they
// contain values originating from requests to collateral proxies
func TestCacheKeys(t *testing.T) {

	folder := t.TempDir()
	cache := newTdxCache(folder, tdxCacheTtl)

	for _, key := range []string{"tcb_129_90c06f000000", "qe_0", "pckcrl_platform", "rootcrl"} {
		filePath, err := cache.filePath(key)
		if err != nil {
			t.Errorf("cache key %q was rejected: %v", key, err)
			continue
		}
		if filepath.Dir(filePath) != folder {
			t.Errorf("cache file %v is not within %v", filePath, folder)
		}
	}

	for _, key := range []string{"", "..", "../../etc/passwd", "tcb_129_../../x", "a/b", "a.b"} {
		if _, err := cache.filePath(key); err == nil {
			t.Errorf("cache key %q was accepted", key)
		}
	}

	// Entries with an unusable key are not written to disk, but remain available
	// in memory for the lifetime of the endorser
	cache.put("../escaped", &cachedCollateral{FetchedAt: time.Now(), Body: []byte("collateral")})
	entries, err := os.ReadDir(folder)
	if err != nil {
		t.Fatalf("failed to read cache folder: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("cache wrote %v files for an invalid key, expected none", len(entries))
	}
	if _, fresh := cache.get("../escaped"); !fresh {
		t.Errorf("entry with invalid key is not cached in memory")
	}
}

func TestValidatePckCa(t *testing.T) {

	for _, ca := range []string{"platform", "processor"} {
		if err := ValidatePckCa(ca); err != nil {
			t.Errorf("PCK CA type %q was rejected: %v", ca, err)
		}
	}

	for _, ca := range []string{"", "Platform", "../../../etc"} {
		if err := ValidatePckCa(ca); err == nil {
			t.Errorf("PCK CA type %q was accepted", ca)
		}
	}
}
