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
	"slices"
	"testing"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// buildMeta constructs a MetadataSummary whose image description carries the given allowed peers.
// A nil slice models an image description without peer policy
func buildMeta(allowed []string) *ar.MetadataSummary {
	id := ar.ImageDescription{}
	if allowed != nil {
		id.AllowedPeers = allowed
	}
	return &ar.MetadataSummary{
		ImageDescriptionResult: ar.MetadataResult{
			Metadata: ar.Metadata{ImageDescription: id},
		},
	}
}

func TestVerifyPeerAuthorization_NoPolicy(t *testing.T) {
	res := verifyPeerAuthorization("example:ns/a", buildMeta(nil))
	if res.Status != ar.StatusSuccess {
		t.Fatalf("expected success, got %q", res.Status)
	}
}

func TestVerifyPeerAuthorization_EmptyAllowedIsSuccess(t *testing.T) {
	res := verifyPeerAuthorization("example:ns/a", buildMeta([]string{}))
	if res.Status != ar.StatusSuccess {
		t.Fatalf("expected success for empty Allowed, got %q", res.Status)
	}
}

func TestVerifyPeerAuthorization_Success(t *testing.T) {
	meta := buildMeta([]string{"example:ns/a", "example:ns/b"})
	res := verifyPeerAuthorization("example:ns/a", meta)
	if res.Status != ar.StatusSuccess {
		t.Fatalf("expected success, got %q (errs=%v)", res.Status, res.ErrorCodes)
	}
	if res.Got != "example:ns/a" {
		t.Fatalf("Got = %q, want example:ns/a", res.Got)
	}
	if !slices.Equal(res.ExpectedOneOf, []string{"example:ns/a", "example:ns/b"}) {
		t.Fatalf("ExpectedOneOf = %v", res.ExpectedOneOf)
	}
}

func TestVerifyPeerAuthorization_RoleNotInSet(t *testing.T) {
	meta := buildMeta([]string{"example:ns/a"})
	res := verifyPeerAuthorization("example:ns/b", meta)
	if res.Status != ar.StatusFail {
		t.Fatalf("expected fail, got %q", res.Status)
	}
	if !slices.Contains(res.ErrorCodes, ar.PeerNotAuthorized) {
		t.Fatalf("expected PeerNotAuthorized error, got %v", res.ErrorCodes)
	}
}

func TestVerifyPeerAuthorization_UnknownLocalRoleWithPolicy(t *testing.T) {
	meta := buildMeta([]string{"example:ns/a"})
	res := verifyPeerAuthorization("", meta)
	if res.Status != ar.StatusFail {
		t.Fatalf("expected fail for empty local role with peer policy, got %q", res.Status)
	}
	if !slices.Contains(res.ErrorCodes, ar.LocalRoleUnknown) {
		t.Fatalf("expected LocalRoleUnknown, got %v", res.ErrorCodes)
	}
}

func TestVerifyPeerAuthorization_UnknownLocalRoleNoPolicy(t *testing.T) {
	res := verifyPeerAuthorization("", buildMeta(nil))
	if res.Status != ar.StatusSuccess {
		t.Fatalf("expected success, got %q", res.Status)
	}
}

func TestVerifyPeerAuthorization_NilMetadata(t *testing.T) {
	res := verifyPeerAuthorization("example:ns/a", nil)
	if res.Status != ar.StatusFail {
		t.Fatalf("expected fail for nil meta, got %q", res.Status)
	}
	if !slices.Contains(res.ErrorCodes, ar.Internal) {
		t.Fatalf("expected Internal error, got %v", res.ErrorCodes)
	}
}
