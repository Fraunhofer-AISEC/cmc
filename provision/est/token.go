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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type TokenData struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func CreateAndCacheToken(dir string) (string, error) {
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

	expiresAt := time.Now().Add(48 * time.Hour)
	td := TokenData{
		Token:     token,
		ExpiresAt: expiresAt,
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

func VerifyToken(dir string, presentedToken string) error {
	// Quick validation of presented token format (id.secret)
	parts := strings.SplitN(presentedToken, ".", 2)
	if len(parts) != 2 {
		return fmt.Errorf("malformed token (%v parts instead of 2)", len(parts))
	}
	idPart := parts[0]

	log.Tracef("Verifying token in directory: %v", dir)

	// If directory doesn't exist -> no tokens
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return fmt.Errorf("token %v not found", idPart)
	}

	// Prune expired token files
	if err := pruneExpiredTokenFiles(dir); err != nil {
		log.Warnf("failed to prune expired tokens: %v", err)
	}

	// Compute filename for presented token
	sum := sha256.Sum256([]byte(presentedToken))
	filename := hex.EncodeToString(sum[:])
	fullpath := filepath.Join(dir, filename)

	data, err := os.ReadFile(fullpath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("token %v not found", idPart)
		}
		return fmt.Errorf("failed to read token file: %w", err)
	}

	var td TokenData
	if err := json.Unmarshal(data, &td); err != nil {
		return fmt.Errorf("failed to unmarshal token file: %w", err)
	}

	now := time.Now()
	if now.After(td.ExpiresAt) {
		// token expired: remove file and report
		if err := os.Remove(fullpath); err != nil && !os.IsNotExist(err) {
			// log but still return an error about expiration
			log.Warnf("failed to remove expired token file %v: %v", fullpath, err)
		} else {
			log.Tracef("Removed token expired at %v (current time %v)", td.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
		}
		return fmt.Errorf("token %v expired", idPart)
	}

	// Verify token content matches (case-insensitive like before)
	if !strings.EqualFold(td.Token, presentedToken) {
		return fmt.Errorf("token %v not found", idPart)
	}

	log.Debugf("Successfully verified token %v", idPart)
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
		fullpath := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(fullpath)
		if err != nil {
			log.Warnf("failed to read token file %v while pruning: %v", fullpath, err)
			continue
		}
		var td TokenData
		if err := json.Unmarshal(data, &td); err != nil {
			// malformed file: try to remove it
			log.Warnf("malformed token file %v while pruning: %v (removing)", fullpath, err)
			if err := os.Remove(fullpath); err != nil && !os.IsNotExist(err) {
				log.Warnf("failed to remove malformed token file %v: %v", fullpath, err)
			}
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
