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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type TokenData struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func CreateAndCacheToken(path string) (string, error) {

	var tokenData []TokenData

	// Read tokens from file system
	if _, err := os.Stat(path); os.IsNotExist(err) {
		file, err := os.Create(path)
		if err != nil {
			return "", fmt.Errorf("failed to create file: %w", err)
		}
		file.Close()
		log.Tracef("File created: %v", path)
	} else {

		log.Tracef("Reading token file: %v", path)
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("failed to read file: %w", err)
		}

		err = json.Unmarshal(data, &tokenData)
		if err != nil {
			return "", fmt.Errorf("failed to unmarshal: %w", err)
		}
	}

	token, err := generateTokenIDSecret()
	if err != nil {
		return "", err
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	td := TokenData{
		Token:     token,
		ExpiresAt: expiresAt,
	}

	// Append generated token
	tokenData = append(tokenData, td)

	data, err := json.Marshal(tokenData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal: %w", err)
	}

	// Store in token path
	err = os.WriteFile(path, data, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to write file: %w", err)
	}

	log.Tracef("Added token to token store: %v", path)

	return token, nil
}

func VerifyToken(path string, presentedToken string) error {

	var tokenData []TokenData

	log.Tracef("Reading token file: %v", path)
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	err = json.Unmarshal(data, &tokenData)
	if err != nil {
		return fmt.Errorf("failed to unmarshal: %w", err)
	}

	// Extract token ID from "id.secret" format
	parts := strings.SplitN(presentedToken, ".", 2)
	if len(parts) != 2 {
		return fmt.Errorf("malformed token (%v parts instead of 2)", len(parts))
	}

	// Find token
	success := false
	filteredTokenData := make([]TokenData, 0, len(tokenData))
	for _, td := range tokenData {
		now := time.Now()
		if now.After(td.ExpiresAt) {
			log.Tracef("Removed token expired at %v (current time %v)",
				td.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
		} else {
			filteredTokenData = append(filteredTokenData, td)
		}

		if strings.EqualFold(td.Token, presentedToken) {
			success = true
		}
	}
	tokenData = filteredTokenData

	// Store in token path
	data, err = json.Marshal(tokenData)
	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}
	err = os.WriteFile(path, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	if !success {
		return fmt.Errorf("token %v not found", parts[0])
	}

	log.Debugf("Successfully verified token %v", parts[0])

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
