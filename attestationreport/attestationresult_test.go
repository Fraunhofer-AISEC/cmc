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

package attestationreport

import (
	"errors"
	"testing"
)

func TestResultDetailsAccumulate(t *testing.T) {
	var r Result
	r.Warn(NotSpecified, errors.New("first"))
	r.Fail(NotSpecified, errors.New("second"))
	r.Fail(NotSpecified)
	r.Warn(NotSpecified, errors.New("third"))

	if r.Details != "first; second; third" {
		t.Errorf("unexpected details %q", r.Details)
	}
	if r.Status != StatusFail {
		t.Errorf("unexpected status %v", r.Status)
	}
}

func TestAttestationResultDetailsAccumulate(t *testing.T) {
	var r AttestationResult
	r.Fail(VerifyMetadata, errors.New("first"), nil, errors.New("second"))
	r.Warn(NotSpecified, errors.New("third"))

	if r.Summary.Details != "first; second; third" {
		t.Errorf("unexpected details %q", r.Summary.Details)
	}
	if len(r.Summary.ErrorCodes) != 1 || r.Summary.ErrorCodes[0] != VerifyMetadata {
		t.Errorf("unexpected error codes %v", r.Summary.ErrorCodes)
	}
	if r.Summary.Status != StatusFail {
		t.Errorf("unexpected status %v", r.Summary.Status)
	}
}

func TestStatusWorse(t *testing.T) {
	all := []Status{"", StatusSuccess, StatusWarn, StatusFail}
	for i, a := range all {
		for j, b := range all {
			want := all[max(i, j)]
			if got := a.Worse(b); got != want {
				t.Errorf("%q.Worse(%q) = %q, want %q", a, b, got, want)
			}
		}
	}
}
