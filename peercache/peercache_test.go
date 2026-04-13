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

package peercache

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestGetReturnsCopy(t *testing.T) {
	cache, _ := Load("")
	_ = cache.Update("peer1", map[string][]byte{"k": []byte("v")})

	result := cache.Get("peer1")
	result["k"] = []byte("modified")

	// Original should be unchanged
	original := cache.Get("peer1")
	if !bytes.Equal(original["k"], []byte("v")) {
		t.Errorf("Get() did not return a copy — original was mutated to %q", original["k"])
	}
}

func TestGetKeysMissingPeer(t *testing.T) {
	cache, _ := Load("")
	got := cache.GetKeys("nonexistent")
	if len(got) != 0 {
		t.Errorf("GetKeys(nonexistent) = %v, want empty", got)
	}
}

func TestGetKeysExistingPeer(t *testing.T) {
	cache, _ := Load("")
	_ = cache.Update("peer1", map[string][]byte{
		"aaa": []byte("data1"),
		"bbb": []byte("data2"),
	})

	got := cache.GetKeys("peer1")
	sort.Strings(got)
	if len(got) != 2 || got[0] != "aaa" || got[1] != "bbb" {
		t.Errorf("GetKeys = %v, want [aaa bbb]", got)
	}
}

func TestUpdateVolatileOnly(t *testing.T) {
	cache, _ := Load("")

	err := cache.Update("peer1", map[string][]byte{
		"hash1": []byte("data1"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}

	got := cache.Get("peer1")
	if !bytes.Equal(got["hash1"], []byte("data1")) {
		t.Errorf("after Update, Get returned %q, want %q", got["hash1"], "data1")
	}
}

func TestUpdateReplacesOldData(t *testing.T) {
	cache, _ := Load("")

	_ = cache.Update("peer1", map[string][]byte{"old": []byte("old_data")})
	_ = cache.Update("peer1", map[string][]byte{"new": []byte("new_data")})

	got := cache.Get("peer1")
	if _, exists := got["old"]; exists {
		t.Error("old key should have been replaced")
	}
	if !bytes.Equal(got["new"], []byte("new_data")) {
		t.Errorf("new key = %q, want %q", got["new"], "new_data")
	}
}

func TestUpdateNilCache(t *testing.T) {
	var cache *Cache
	err := cache.Update("peer", map[string][]byte{"k": []byte("v")})
	if err == nil {
		t.Error("nil.Update() should return error")
	}
}

func TestUpdatePersistent(t *testing.T) {
	dir := t.TempDir()
	cache, _ := Load(dir)

	data := map[string][]byte{
		"hash_a": []byte("content_a"),
		"hash_b": []byte("content_b"),
	}
	err := cache.Update("peer1", data)
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}

	// Verify files were created
	contentA, err := os.ReadFile(filepath.Join(dir, "peer1", "hash_a"))
	if err != nil {
		t.Fatalf("failed to read persisted file: %v", err)
	}
	if !bytes.Equal(contentA, []byte("content_a")) {
		t.Errorf("persisted hash_a = %q, want %q", contentA, "content_a")
	}
}

func TestUpdateRemovesStaleFiles(t *testing.T) {
	dir := t.TempDir()
	cache, _ := Load(dir)

	// First update with two items
	_ = cache.Update("peer1", map[string][]byte{
		"keep":   []byte("data"),
		"remove": []byte("data"),
	})

	// Second update without "remove"
	_ = cache.Update("peer1", map[string][]byte{
		"keep": []byte("data"),
	})

	// Stale file should be removed
	if _, err := os.Stat(filepath.Join(dir, "peer1", "remove")); !os.IsNotExist(err) {
		t.Error("stale file 'remove' should have been deleted")
	}
	// Kept file should still exist
	if _, err := os.Stat(filepath.Join(dir, "peer1", "keep")); err != nil {
		t.Errorf("kept file should still exist: %v", err)
	}
}

func TestLoadUpdateRoundtrip(t *testing.T) {
	dir := t.TempDir()

	// Create cache and update
	cache1, _ := Load(dir)
	_ = cache1.Update("peer1", map[string][]byte{
		"hash1": []byte("metadata1"),
		"hash2": []byte("metadata2"),
	})

	// Reload from same directory
	cache2, err := Load(dir)
	if err != nil {
		t.Fatalf("Load roundtrip error: %v", err)
	}

	got := cache2.Get("peer1")
	if !bytes.Equal(got["hash1"], []byte("metadata1")) {
		t.Errorf("roundtrip hash1 = %q, want %q", got["hash1"], "metadata1")
	}
	if !bytes.Equal(got["hash2"], []byte("metadata2")) {
		t.Errorf("roundtrip hash2 = %q, want %q", got["hash2"], "metadata2")
	}
}
