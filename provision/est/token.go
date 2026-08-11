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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrTokenConsumed is returned when a token exists but has been fully consumed
var ErrTokenConsumed = errors.New("token already consumed")

// ErrTokenNotFound is returned when no matching token can be found
var ErrTokenNotFound = errors.New("token not found")

type TokenData struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
	MaxUses   int       `json:"maxUses,omitempty"` // Maximum number of successful retrievals, 0 means unlimited
	Uses      int       `json:"uses,omitempty"`    // Number of successful retrievals so far
	Subject   string    `json:"subject,omitempty"` // If non-empty, restricts the token to callers presenting this subject
}

// TokenOptions configures a token created by CreateToken
type TokenOptions struct {
	MaxUses int    // Maximum number of successful redemptions, 0 means unlimited
	Subject string // If non-empty, restricts the token to callers presenting this subject
}

func CreateToken(dir string, opts TokenOptions) (string, error) {
	// Ensure directory exists
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create token directory %q: %w", dir, err)
	}
	log.Tracef("Using token directory: %v", dir)

	// Generate token
	token, err := generateTokenIDSecret()
	if err != nil {
		return "", err
	}

	td := TokenData{
		Token:     token,
		ExpiresAt: time.Now().Add(48 * time.Hour),
		MaxUses:   opts.MaxUses,
		Subject:   opts.Subject,
	}

	data, err := json.Marshal(td)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token data: %w", err)
	}

	// Filename is sha256(token) hex
	sum := sha256.Sum256([]byte(token))
	filename := hex.EncodeToString(sum[:])
	fullpath := filepath.Join(dir, filename)

	if err := os.WriteFile(fullpath, data, 0600); err != nil {
		return "", fmt.Errorf("failed to write token file %q: %w", fullpath, err)
	}

	log.Tracef("Added token to token store: %v (file %v)", dir, filename)
	return token, nil
}

// VerifyToken verifies presentedToken in dir and, for limited-use tokens, records the redemption.
// The subject is only compared against the token's subject if the latter is non-empty
func VerifyToken(dir string, presentedToken string, subject string) error {
	// Quick validation of presented token format (id.secret)
	parts := strings.SplitN(presentedToken, ".", 2)
	if len(parts) != 2 {
		return fmt.Errorf("malformed token (%v parts instead of 2)", len(parts))
	}
	idPart := parts[0]

	log.Tracef("Verifying token in directory: %v", dir)

	// If directory doesn't exist -> no tokens
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return ErrTokenNotFound
	}

	// Prune expired token files
	if err := pruneExpiredTokenFiles(dir); err != nil {
		log.Warnf("failed to prune expired tokens: %v", err)
	}

	// Compute filename for presented token
	sum := sha256.Sum256([]byte(presentedToken))
	filename := hex.EncodeToString(sum[:])
	fullpath := filepath.Join(dir, filename)
	claimedPath := fullpath + ".claimed"

	// Atomically take exclusive ownership of the token file by renaming it
	if err := os.Rename(fullpath, claimedPath); err != nil {
		if os.IsNotExist(err) {
			// Distinguish "being consumed right now" from "not here at all"
			if _, statErr := os.Stat(claimedPath); statErr == nil {
				return ErrTokenConsumed
			}
			return ErrTokenNotFound
		}
		return fmt.Errorf("failed to claim token file: %w", err)
	}

	data, err := os.ReadFile(claimedPath)
	if err != nil {
		_ = os.Rename(claimedPath, fullpath) // Restore
		return fmt.Errorf("failed to read token file: %w", err)
	}

	var td TokenData
	if err := json.Unmarshal(data, &td); err != nil {
		_ = os.Remove(claimedPath)
		return fmt.Errorf("failed to unmarshal token file: %w", err)
	}

	if time.Now().After(td.ExpiresAt) {
		log.Tracef("Removed token expired at %v", td.ExpiresAt.Format(time.RFC3339))
		_ = os.Remove(claimedPath)
		return fmt.Errorf("token %v expired", idPart)
	}

	if !strings.EqualFold(td.Token, presentedToken) {
		_ = os.Remove(claimedPath)
		return ErrTokenNotFound
	}

	if td.Subject != "" && td.Subject != subject {
		// Token is valid but not for this subject, restore it
		if err := os.Rename(claimedPath, fullpath); err != nil {
			log.Warnf("failed to restore token file after subject mismatch: %v", err)
		}
		return fmt.Errorf("token %v subject mismatch", idPart)
	}

	// Restore unlimited tokens unchanged
	if td.MaxUses == 0 {
		if err := os.Rename(claimedPath, fullpath); err != nil {
			return fmt.Errorf("failed to restore unlimited token: %w", err)
		}
		log.Debugf("Successfully verified token %v (unlimited)", idPart)
		return nil
	}

	// Record the redemption of limited-use tokens
	td.Uses++
	if td.Uses >= td.MaxUses {
		_ = os.Remove(claimedPath)
		log.Debugf("Successfully verified and consumed token %v (%v/%v uses)", idPart, td.Uses, td.MaxUses)
		return nil
	}

	// Uses remaining, write the updated state back atomically
	updated, err := json.Marshal(td)
	if err != nil {
		_ = os.Rename(claimedPath, fullpath) // Restore
		return fmt.Errorf("failed to marshal updated token: %w", err)
	}

	tmpPath := fullpath + ".tmp"
	if err := os.WriteFile(tmpPath, updated, 0600); err != nil {
		_ = os.Rename(claimedPath, fullpath)
		return fmt.Errorf("failed to write updated token: %w", err)
	}
	if err := os.Rename(tmpPath, fullpath); err != nil {
		_ = os.Remove(tmpPath)
		_ = os.Rename(claimedPath, fullpath)
		return fmt.Errorf("failed to restore updated token: %w", err)
	}
	_ = os.Remove(claimedPath)

	log.Debugf("Successfully verified token %v (%v/%v uses)", idPart, td.Uses, td.MaxUses)
	return nil
}

func pruneExpiredTokenFiles(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read token directory %q: %w", dir, err)
	}

	now := time.Now()
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Remove stale claimed/tmp files left by a crashed process
		if strings.HasSuffix(name, ".claimed") || strings.HasSuffix(name, ".tmp") {
			info, err := e.Info()
			if err != nil {
				continue
			}
			if now.Sub(info.ModTime()) > 1*time.Minute {
				fullpath := filepath.Join(dir, name)
				log.Warnf("Removing stale token work file %v", fullpath)
				_ = os.Remove(fullpath)
			}
			continue
		}

		fullpath := filepath.Join(dir, name)
		data, err := os.ReadFile(fullpath)
		if err != nil {
			log.Warnf("failed to read token file %v while pruning: %v", fullpath, err)
			continue
		}
		var td TokenData
		if err := json.Unmarshal(data, &td); err != nil {
			// malformed file: try to remove it
			log.Warnf("malformed token file %v while pruning: %v (removing)", fullpath, err)
			_ = os.Remove(fullpath)
			continue
		}
		if now.After(td.ExpiresAt) {
			if err := os.Remove(fullpath); err != nil && !os.IsNotExist(err) {
				log.Warnf("failed to remove expired token file %v: %v", fullpath, err)
			} else {
				log.Tracef("Removed token expired at %v (file %v)", td.ExpiresAt.Format(time.RFC3339), fullpath)
			}
		}
	}
	return nil
}

func generateTokenIDSecret() (string, error) {
	idBytes := make([]byte, 3)     // 6 hex characters
	secretBytes := make([]byte, 8) // 16 hex characters

	if _, err := rand.Read(idBytes); err != nil {
		return "", err
	}
	if _, err := rand.Read(secretBytes); err != nil {
		return "", err
	}

	id := hex.EncodeToString(idBytes)
	secret := hex.EncodeToString(secretBytes)
	return fmt.Sprintf("%s.%s", id, secret), nil
}
