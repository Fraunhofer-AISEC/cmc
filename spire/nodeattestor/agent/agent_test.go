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

package agent

import (
	"os"
	"path/filepath"
	"testing"

	na "github.com/Fraunhofer-AISEC/cmc/spire/nodeattestor"
)

func TestLoadOrCreateNodeId(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "node-id")

	id, err := loadOrCreateNodeId(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := na.ParseNodeId(id); err != nil {
		t.Fatalf("created invalid ID: %v", err)
	}

	again, err := loadOrCreateNodeId(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if again != id {
		t.Fatalf("ID not stable: %q != %q", again, id)
	}

	if err := os.WriteFile(path, []byte("garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateNodeId(path); err == nil {
		t.Fatal("expected error for invalid stored ID")
	}
}
