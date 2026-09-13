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
	"errors"
	"fmt"
	"sync"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// rimCache caches the merged driver/VBIOS RIM union per version pair. Parsing and
// signature-verifying a RIM is expensive and the result is deterministic.
var (
	rimCache   = make(map[string]cachedRimEntry)
	rimCacheMu sync.RWMutex
)

// rimCacheTTL caps how long a verified RIM union is served from cache, so that a
// RIM signing certificate revoked after the entry was created stops being
// accepted within a bounded time
const rimCacheTTL = 5 * time.Minute

type cachedRimEntry struct {
	rim       internal.RIM
	expiresAt time.Time
}

func ClearRIMCache() {
	rimCacheMu.Lock()
	rimCache = make(map[string]cachedRimEntry)
	rimCacheMu.Unlock()
}

// verifyRIMwithOCSP checks that the certificate chain which signed the RIM has not
// been revoked, using the OCSP responses shipped in the collateral.
func verifyRIMwithOCSP(rim internal.RIM, collateral ar.Collateral) error {
	if collateral.Type != ar.TYPE_EVIDENCE_NVIDIA {
		return fmt.Errorf("unsupported collateral type: %s", collateral.Type)
	}
	nvidiaCollateral := extractNvidiaCollateral(collateral)
	if nvidiaCollateral == nil {
		return errors.New("nvidia collateral artifacts not found in the payload")
	}

	ocspResponses := nvidiaCollateral.OcspResponsesRIMCerts
	if len(ocspResponses) == 0 {
		return errors.New("no OCSP responses provided in collateral")
	}
	if len(ocspResponses) > len(rim.Certs)-1 {
		return fmt.Errorf("not enough certificates in chain (%d) to verify %d OCSP responses",
			len(rim.Certs), len(ocspResponses))
	}
	if _, exists := ocspResponses[rim.Name]; !exists {
		return fmt.Errorf("no OCSP response available for RIM %s", rim.Name)
	}
	return VerifyCertificateChainWithOCSP(ocspResponses[rim.Name], rim.Certs, false)
}
