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

package main

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

const resultFull = `{
	"version": "3.5.0",
	"type": "Validation Report",
	"summary": { "status": "success" },
	"prover": { "hostname": "prover-a" },
	"created": "2025-01-01T10:00:00Z",
	"measurements": [
		{ "type": "TPM Result", "summary": { "status": "success" } },
		{ "type": "SW Result", "summary": { "status": "success" } }
	],
	"metadata": {
		"imageDescriptionResult": {
			"name": "test-image",
			"location": "registry.example.com/test",
			"description": "Image Description"
		},
		"manifestResults": [
			{ "name": "de.test.rtm" },
			{ "name": "de.test.os", "details": { "kernel": "6.8.0", "os": "Ubuntu 24.04" } }
		]
	}
}`

// Newer result for the same prover, with a timestamp in a different timezone
// that is lexicographically smaller than the one of resultFull
const resultFullNewer = `{
	"version": "3.5.0",
	"type": "Validation Report",
	"summary": { "status": "warn" },
	"prover": { "hostname": "prover-a" },
	"created": "2025-01-01T09:30:00-02:00",
	"measurements": [
		{ "type": "TPM Result", "summary": { "status": "warn" } }
	],
	"metadata": {
		"imageDescriptionResult": { "name": "test-image" },
		"manifestResults": []
	}
}`

const resultMinimal = `{
	"version": "3.5.0",
	"type": "Validation Report",
	"summary": { "status": "fail" },
	"prover": { "hostname": "prover-b" },
	"created": "2025-01-01T11:00:00Z"
}`

func newTestDb(t *testing.T, results ...string) *Db {
	t.Helper()

	db, err := NewDb(filepath.Join(t.TempDir(), "test.db"), 20, 400, defaultCategory)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	t.Cleanup(db.Close)

	for _, r := range results {
		if err := db.InsertResult([]byte(r), defaultCategory); err != nil {
			t.Fatalf("failed to insert result: %v", err)
		}
	}

	return db
}

func Test_GetLatestResults(t *testing.T) {
	// Insertion order determines which result is the latest one
	db := newTestDb(t, resultFull, resultMinimal, resultFullNewer)

	results, err := db.GetLatestResults(defaultCategory)
	if err != nil {
		t.Fatalf("failed to get latest results: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results (one per prover), got %v", len(results))
	}

	// Results are ordered by prover name
	a, b := results[0], results[1]

	if a.Prover != "prover-a" || b.Prover != "prover-b" {
		t.Fatalf("expected results for prover-a and prover-b, got %v and %v",
			a.Prover, b.Prover)
	}

	// prover-a must be the last inserted result, not the one with the
	// lexicographically largest timestamp
	if a.Status != "warn" {
		t.Errorf("expected the latest result for prover-a (status warn), got %v", a.Status)
	}
	if a.Created != "2025-01-01T09:30:00-02:00" {
		t.Errorf("unexpected created timestamp for prover-a: %v", a.Created)
	}
	if a.Version != "3.5.0" {
		t.Errorf("expected version 3.5.0, got %v", a.Version)
	}
	if !reflect.DeepEqual(a.MeasurementTypes, []string{"TPM Result"}) {
		t.Errorf("unexpected measurement types: %v", a.MeasurementTypes)
	}
	if a.Image == nil || a.Image.Name != "test-image" {
		t.Errorf("unexpected image description: %v", a.Image)
	}
	if len(a.Details) != 0 {
		t.Errorf("expected no manifest details, got %v", a.Details)
	}

	// prover-b carries nothing but the header fields
	if b.Status != "fail" {
		t.Errorf("expected status fail for prover-b, got %v", b.Status)
	}
	if len(b.MeasurementTypes) != 0 {
		t.Errorf("expected no measurement types, got %v", b.MeasurementTypes)
	}
	if b.Image != nil {
		t.Errorf("expected no image description, got %v", b.Image)
	}
	if len(b.Details) != 0 {
		t.Errorf("expected no manifest details, got %v", b.Details)
	}
}

func Test_GetLatestResultsDetails(t *testing.T) {
	db := newTestDb(t, resultFull)

	results, err := db.GetLatestResults(defaultCategory)
	if err != nil {
		t.Fatalf("failed to get latest results: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %v", len(results))
	}
	r := results[0]

	if !reflect.DeepEqual(r.MeasurementTypes, []string{"TPM Result", "SW Result"}) {
		t.Errorf("unexpected measurement types: %v", r.MeasurementTypes)
	}

	if r.Image == nil {
		t.Fatal("expected an image description")
	}
	want := ImageDescription{
		Name:        "test-image",
		Location:    "registry.example.com/test",
		Description: "Image Description",
	}
	if *r.Image != want {
		t.Errorf("unexpected image description: %+v", *r.Image)
	}

	// Only manifests carrying details are included, and the key order of the
	// original result is retained
	if len(r.Details) != 1 {
		t.Fatalf("expected details of 1 manifest, got %v", len(r.Details))
	}
	if got := string(r.Details[0]); got != `{"kernel":"6.8.0","os":"Ubuntu 24.04"}` {
		t.Errorf("unexpected manifest details: %v", got)
	}
}

func Test_GetLatestResultsFields(t *testing.T) {
	db := newTestDb(t, resultFull)

	results, err := db.GetLatestResults(defaultCategory)
	if err != nil {
		t.Fatalf("failed to get latest results: %v", err)
	}

	data, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("failed to marshal results: %v", err)
	}

	var decoded []map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal results: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("expected 1 result, got %v", len(decoded))
	}

	got := make([]string, 0, len(decoded[0]))
	for k := range decoded[0] {
		got = append(got, k)
	}
	sort.Strings(got)

	want := []string{"category", "created", "details", "id", "image",
		"measurementTypes", "prover", "status", "version"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("expected fields %v, got %v", want, got)
	}
}

func Test_Categories(t *testing.T) {
	db := newTestDb(t)

	for _, c := range []string{"demo-a", "demo-b"} {
		if err := db.InsertResult([]byte(resultFull), c); err != nil {
			t.Fatalf("failed to insert result: %v", err)
		}
	}
	if err := db.InsertResult([]byte(resultMinimal), "demo-a"); err != nil {
		t.Fatalf("failed to insert result: %v", err)
	}

	tests := []struct {
		category string
		want     int
	}{
		{"demo-a", 2},
		{"demo-b", 1},
		{"demo-c", 0},
		{"", 3},
	}

	for _, test := range tests {
		results, err := db.GetLatestResults(test.category)
		if err != nil {
			t.Fatalf("failed to get latest results: %v", err)
		}
		if len(results) != test.want {
			t.Errorf("category %q: expected %v results, got %v",
				test.category, test.want, len(results))
		}
		for _, r := range results {
			if test.category != "" && r.Category != test.category {
				t.Errorf("expected category %q, got %q", test.category, r.Category)
			}
		}
	}

	names, err := db.GetDeviceNames("demo-b")
	if err != nil {
		t.Fatalf("failed to get device names: %v", err)
	}
	if !reflect.DeepEqual(names, []string{"prover-a"}) {
		t.Errorf("unexpected device names: %v", names)
	}
}

// The row limits must apply within a category, so that a busy deployment
// cannot evict the provers of another one
func Test_CategoryLimits(t *testing.T) {
	db, err := NewDb(filepath.Join(t.TempDir(), "test.db"), 2, 3, defaultCategory)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	t.Cleanup(db.Close)

	if err := db.InsertResult([]byte(resultMinimal), "quiet"); err != nil {
		t.Fatalf("failed to insert result: %v", err)
	}

	// Exceed both the per-prover and the total limit of the other category
	for i := 0; i < 10; i++ {
		if err := db.InsertResult([]byte(resultFull), "busy"); err != nil {
			t.Fatalf("failed to insert result: %v", err)
		}
	}

	quiet, err := db.GetLatestResults("quiet")
	if err != nil {
		t.Fatalf("failed to get latest results: %v", err)
	}
	if len(quiet) != 1 {
		t.Errorf("expected the quiet category to be untouched, got %v results", len(quiet))
	}

	busy, err := db.GetEnvelopesByProver("prover-a", "busy")
	if err != nil {
		t.Fatalf("failed to get envelopes: %v", err)
	}
	if len(busy) != 2 {
		t.Errorf("expected 2 rows after the per-prover limit, got %v", len(busy))
	}
}

// Databases created before categories existed must keep working
func Test_CategoryMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	_, err = legacy.Exec(`
CREATE TABLE results (
    serial INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL,
    prover TEXT,
    created TEXT,
    status TEXT,
    result TEXT
);
INSERT INTO results (id, prover, created, status, result)
VALUES ('abc', 'legacy-prover', '2025-01-01T10:00:00Z', 'success', json('{"version":"3.5.0"}'));`)
	if err != nil {
		t.Fatalf("failed to create legacy table: %v", err)
	}
	legacy.Close()

	db, err := NewDb(path, 20, 400, "demo")
	if err != nil {
		t.Fatalf("failed to open migrated database: %v", err)
	}
	t.Cleanup(db.Close)

	// Existing rows must land in the configured default category, otherwise
	// they are invisible to a client filtering by a configured category
	results, err := db.GetLatestResults("demo")
	if err != nil {
		t.Fatalf("failed to get latest results: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 migrated result, got %v", len(results))
	}
	if results[0].Prover != "legacy-prover" {
		t.Errorf("unexpected prover: %v", results[0].Prover)
	}
	if results[0].Category != "demo" {
		t.Errorf("expected category %q, got %q", "demo", results[0].Category)
	}

	// New results must end up alongside the migrated ones
	if err := db.InsertResult([]byte(resultFull), "demo"); err != nil {
		t.Fatalf("failed to insert result: %v", err)
	}
	results, err = db.GetLatestResults("demo")
	if err != nil {
		t.Fatalf("failed to get latest results: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results after inserting, got %v", len(results))
	}
}
