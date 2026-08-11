// Copyright (c) 2025 Fraunhofer AISEC
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

package est

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
)

func TestVerifyToken_Unlimited(t *testing.T) {
	dir := t.TempDir()

	token, err := CreateToken(dir, TokenOptions{})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	for range 3 {
		if err := VerifyToken(dir, token, ""); err != nil {
			t.Errorf("expected success on unlimited token, got: %v", err)
		}
	}
}

func TestVerifyToken_SingleUse(t *testing.T) {
	dir := t.TempDir()

	token, err := CreateToken(dir, TokenOptions{MaxUses: 1})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	if err := VerifyToken(dir, token, ""); err != nil {
		t.Fatalf("first redemption should succeed, got: %v", err)
	}

	err = VerifyToken(dir, token, "")
	if !errors.Is(err, ErrTokenConsumed) && !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("second redemption should fail with consumed/not-found, got: %v", err)
	}
}

func TestVerifyToken_MultiUse(t *testing.T) {
	dir := t.TempDir()

	token, err := CreateToken(dir, TokenOptions{MaxUses: 3})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	for i := range 3 {
		if err := VerifyToken(dir, token, ""); err != nil {
			t.Errorf("redemption %d should succeed, got: %v", i+1, err)
		}
	}

	err = VerifyToken(dir, token, "")
	if !errors.Is(err, ErrTokenConsumed) && !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("redemption after exhaustion should fail, got: %v", err)
	}
}

func TestVerifyToken_Subject(t *testing.T) {
	dir := t.TempDir()

	token, err := CreateToken(dir, TokenOptions{MaxUses: 2, Subject: "alice"})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	if err := VerifyToken(dir, token, "bob"); err == nil {
		t.Error("wrong subject should be rejected")
	}

	// Token must still be redeemable after a subject mismatch rejection
	if err := VerifyToken(dir, token, "alice"); err != nil {
		t.Errorf("correct subject should succeed, got: %v", err)
	}
}

func TestVerifyToken_NotFound(t *testing.T) {
	dir := t.TempDir()

	err := VerifyToken(dir, "ab.cdef0123456789ab", "")
	if !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("expected ErrTokenNotFound for non-existent token, got: %v", err)
	}
}

// TestVerifyToken_ConcurrentSingleUse fires N goroutines against a MaxUses=1 token simultaneously
// and asserts that exactly one succeeds
func TestVerifyToken_ConcurrentSingleUse(t *testing.T) {
	const N = 20

	dir := t.TempDir()

	token, err := CreateToken(dir, TokenOptions{MaxUses: 1})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	var (
		wg        sync.WaitGroup
		successes atomic.Int32
		start     = make(chan struct{})
	)

	for range N {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if VerifyToken(dir, token, "") == nil {
				successes.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Errorf("expected exactly 1 successful redemption, got %d", got)
	}
}

// TestVerifyToken_BackwardCompat verifies that an old-format token file without MaxUses and Uses
// fields is still accepted as unlimited
func TestVerifyToken_BackwardCompat(t *testing.T) {
	dir := t.TempDir()

	// Create a token without MaxUses, i.e., unlimited
	token, err := CreateToken(dir, TokenOptions{})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	for range 5 {
		if err := VerifyToken(dir, token, ""); err != nil {
			t.Errorf("unlimited token should verify repeatedly, got: %v", err)
		}
	}
}

func TestVerifyToken_MalformedToken(t *testing.T) {
	dir := t.TempDir()
	err := VerifyToken(dir, "nodotintoken", "")
	if err == nil {
		t.Error("malformed token should be rejected")
	}
}

func TestVerifyToken_NoTokenDir(t *testing.T) {
	err := VerifyToken("/nonexistent/path", "ab.0123456789abcdef", "")
	if !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("missing dir should return ErrTokenNotFound, got: %v", err)
	}
}

func TestCreateToken_Options(t *testing.T) {
	dir := t.TempDir()

	token, err := CreateToken(dir, TokenOptions{MaxUses: 5, Subject: "test-subject"})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	// A mismatched subject must fail but preserve the token
	if err := VerifyToken(dir, token, "other"); err == nil {
		t.Error("wrong subject should be rejected")
	}

	// The correct subject allows 5 uses
	for i := range 5 {
		if err := VerifyToken(dir, token, "test-subject"); err != nil {
			t.Errorf("use %d of 5 should succeed, got: %v", i+1, err)
		}
	}

	// The 6th use is exhausted
	err = VerifyToken(dir, token, "test-subject")
	if !errors.Is(err, ErrTokenConsumed) && !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("exhausted token should fail, got: %v", err)
	}

	// Remove temp dir entries
	_ = os.RemoveAll(dir)
}
