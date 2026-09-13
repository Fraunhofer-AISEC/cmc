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

package verifier

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// cacheEntry holds the minimal metadata needed to bypass ocsp.ParseResponse
type cacheEntry struct {
	Status     int
	ThisUpdate time.Time
	NextUpdate time.Time
}

// Global thread-safe cache for verified OCSP responses
var ocspCache sync.Map

func VerifyCertificateChainWithOCSP(ocspResponses []string, chain []*x509.Certificate, isDeviceChain bool) error {
	currentTime := now()

	// Move invariant out of the loop
	skip := 0
	if isDeviceChain {
		skip = 1
	}

	// Initialize the hasher once outside the loop to optimize memory allocation
	hasher := sha256.New()

	for i, ocspResponseB64 := range ocspResponses {
		// Prevent out-of-bounds panic if chain is shorter than expected
		if i+1+skip >= len(chain) {
			return fmt.Errorf("certificate chain is too short for the provided OCSP responses")
		}

		subjectCert := chain[i+skip]
		issuerCert := chain[i+1+skip]

		// 1. Generate a fast cache key based on response, issuer, AND subject serial number.
		// Including the serial number guarantees we never accidentally apply cached results
		// to the wrong certificate under the same issuer.
		hasher.Reset()
		hasher.Write([]byte(ocspResponseB64))
		hasher.Write(issuerCert.RawSubject)
		hasher.Write(subjectCert.SerialNumber.Bytes())
		cacheKey := [32]byte(hasher.Sum(nil))

		var status int
		var thisUpdate, nextUpdate time.Time
		var cached bool

		// 2. Attempt Cache Lookup
		if val, found := ocspCache.Load(cacheKey); found {
			entry := val.(cacheEntry)
			// Ensure cached item hasn't expired relative to 'now'
			if !entry.NextUpdate.IsZero() && currentTime.Before(entry.NextUpdate) && !entry.ThisUpdate.After(currentTime) {
				status = entry.Status
				thisUpdate = entry.ThisUpdate
				nextUpdate = entry.NextUpdate
				cached = true
			}
		}

		// 3. Cache Miss: Decode, Parse, and Verify Cryptographic Signatures
		if !cached {
			var ocspDER []byte
			decoded, err := base64.StdEncoding.DecodeString(ocspResponseB64)
			if err != nil {
				ocspDER = []byte(ocspResponseB64)
			} else {
				ocspDER = decoded
			}

			// Expensive cryptographic operation happens here
			resp, err := ocsp.ParseResponseForCert(ocspDER, subjectCert, issuerCert)
			if err != nil {
				return fmt.Errorf("failed to parse OCSP response for chain[%d] (%s): %w",
					i, subjectCert.Subject.CommonName, err)
			}

			status = resp.Status
			thisUpdate = resp.ThisUpdate
			nextUpdate = resp.NextUpdate

			// Store in cache if it has a validity window
			if !nextUpdate.IsZero() && currentTime.Before(nextUpdate) {
				ocspCache.Store(cacheKey, cacheEntry{
					Status:     status,
					ThisUpdate: thisUpdate,
					NextUpdate: nextUpdate,
				})
			}
		}

		// 4. Evaluate Status
		switch status {
		case ocsp.Good:
			// Valid: continue
		case ocsp.Revoked:
			return fmt.Errorf("certificate chain[%d] (%s) is revoked", i, subjectCert.Subject.CommonName)
		case ocsp.Unknown:
			return fmt.Errorf("certificate chain[%d] (%s) has unknown OCSP status", i, subjectCert.Subject.CommonName)
		default:
			return fmt.Errorf("certificate chain[%d] (%s) has unexpected OCSP status: %d", i, subjectCert.Subject.CommonName, status)
		}

		// 5. Evaluate Freshness (Needed for both cached and non-cached branches)
		if nextUpdate.IsZero() {
			return fmt.Errorf("OCSP response for chain[%d] (%s) has no NextUpdate field", i, subjectCert.Subject.CommonName)
		}
		if currentTime.After(nextUpdate) {
			return fmt.Errorf("OCSP response for chain[%d] (%s) is stale", i, subjectCert.Subject.CommonName)
		}
		if thisUpdate.After(currentTime) {
			return fmt.Errorf("OCSP response for chain[%d] (%s) has a future ThisUpdate", i, subjectCert.Subject.CommonName)
		}
	}

	return nil
}
