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
	"fmt"
	"slices"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// verifyPeerAuthorization performs a role-based verification if we are allowed to interact with
// this peer. It verifies, that the peer-set defined in the prover's image description contains our
// local role, i.e., our image description name. If no peer policies are specified, interaction
// with any attested peer is allowed and this check passes.
func verifyPeerAuthorization(localRole string, meta *ar.MetadataSummary) ar.Result {
	if meta == nil {
		r := ar.Result{}
		r.Fail(ar.Internal, fmt.Errorf("internal error: metadata not present"))
		return r
	}
	if len(meta.ImageDescriptionResult.AllowedPeers) == 0 {
		// No peers specified, always pass
		return ar.Result{Status: ar.StatusSuccess}
	}
	allowed := meta.ImageDescriptionResult.AllowedPeers

	res := ar.Result{ExpectedOneOf: allowed}
	if localRole == "" {
		res.Fail(ar.LocalRoleUnknown)
		return res
	}

	res.Got = localRole
	if slices.Contains(allowed, localRole) {
		res.Status = ar.StatusSuccess
		return res
	}
	res.Fail(ar.PeerNotAuthorized)
	return res
}
