// Copyright (c) 2021 Fraunhofer AISEC
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

package tpmdriver

import (
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestGetAkName(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"Test Get AK Qualified Name", false},
	}

	log.SetLevel(log.DebugLevel)

	if err := OpenTpm(); err != nil {
		t.Errorf("Preparation: OpenTpm error '%v'", err)
	}
	defer CloseTpm()

	if err := LoadTpmKeys("test_encrypted_ak.json", "test_encrypted_tls_key.json"); err != nil {
		t.Errorf("Preparation: LoadTpmKeys error '%v'", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := GetAkQualifiedName(); (err != nil) != tt.wantErr {
				t.Errorf("GetAkName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetTpmInfo(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"Test TPM Info", false},
	}

	log.SetLevel(log.DebugLevel)

	if err := OpenTpm(); err != nil {
		t.Errorf("Preparation: OpenTpm error = %v", err)
	}
	defer CloseTpm()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetTpmInfo()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetTpmInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
