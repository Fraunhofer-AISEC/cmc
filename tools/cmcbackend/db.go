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

package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/publish"
)

const (
	tableResults       = "results"
	tableOcsfFindings  = "ocsf_findings"
	tableNetworkEvents = "network_events"

	defaultCategory = "default"
)

type Db struct {
	db *sql.DB
}

type ResultEnvelope struct {
	Type    string    `json:"type"`
	Id      string    `json:"id"`
	Prover  string    `json:"prover"`
	Created string    `json:"created"`
	Status  ar.Status `json:"status"`
	Result  any       `json:"result"`
}

// ResultOverview summarizes a result through values extracted from it
type ResultOverview struct {
	Id               string            `json:"id"`
	Category         string            `json:"category"`
	Prover           string            `json:"prover"`
	Created          string            `json:"created"`
	Status           ar.Status         `json:"status"`
	Version          string            `json:"version"`
	MeasurementTypes []string          `json:"measurementTypes,omitempty"`
	Image            *ImageDescription `json:"image,omitempty"`
	Details          []json.RawMessage `json:"details,omitempty"`
}

type ImageDescription struct {
	Name        string `json:"name,omitempty"`
	Location    string `json:"location,omitempty"`
	Description string `json:"description,omitempty"`
}

func NewDb(path string, maxRowsPerProver, maxRows int, defaultCategory string) (*Db, error) {

	log.Tracef("Opening database %v", path)

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite3 DB: %w", err)
	}

	log.Tracef("Openend database %v", path)

	if err = createTables(db); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	// Schema steps below run on every start, so that databases created by
	// earlier versions are migrated and configuration changes take effect
	for _, table := range []string{tableResults, tableOcsfFindings, tableNetworkEvents} {
		if err = addCategoryColumn(db, table, defaultCategory); err != nil {
			return nil, fmt.Errorf("failed to migrate table %v: %w", table, err)
		}
	}

	if err = createIndexes(db); err != nil {
		return nil, fmt.Errorf("failed to create indexes: %w", err)
	}

	if err = createTriggers(db, maxRowsPerProver, maxRows); err != nil {
		return nil, fmt.Errorf("failed to create triggers: %w", err)
	}

	return &Db{db: db}, nil
}

func (db *Db) Close() {
	db.db.Close()
}

// categoryFilter returns an SQL condition and its argument. An empty category
// matches all categories.
func categoryFilter(category string) (string, []any) {
	if category == "" {
		return "1=1", nil
	}
	return "category = ?", []any{category}
}

// Result methods

func (db *Db) InsertResult(data []byte, category string) error {

	if !json.Valid(data) {
		return fmt.Errorf("provided data is not valid JSON")
	}

	// Unmarshal the header to get prover and creation date
	header := new(ar.AttestationResult)
	err := json.Unmarshal(data, header)
	if err != nil {
		return fmt.Errorf("failed to unmarshal header")
	}

	if header.Prover.Hostname == "" {
		return errors.New("cannot insert into database: The result prover field is empty")
	}

	log.Tracef("Inserting prover '%v' into %v (category %v)",
		header.Prover.Hostname, tableResults, category)

	// Create ID through hashing
	digest := sha256.Sum256(data)
	id := hex.EncodeToString(digest[:])

	// Insert everything into the database
	insert := fmt.Sprintf(`INSERT INTO %v
		(id, category, prover, created, status, result)
		VALUES
		(?, ?, ?, ?, ?, json(?))`, tableResults)

	tx, err := db.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Commit()

	stmt, err := tx.Prepare(insert)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(id[:], category, header.Prover.Hostname, header.Created,
		header.Summary.Status, string(data))
	if err != nil {
		return fmt.Errorf("failed to execute statement: %w", err)
	}

	return nil
}

func (db *Db) GetAllStatistics(category string) ([]*ResultEnvelope, error) {

	log.Trace("Querying all result statistics")

	filter, args := categoryFilter(category)
	stmt := fmt.Sprintf("SELECT id, prover, created, status FROM %v WHERE %v;",
		tableResults, filter)

	rows, err := db.db.Query(stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to exec sqlite3 statement: %w", err)
	}
	defer rows.Close()

	results := make([]*ResultEnvelope, 0)
	for rows.Next() {

		var id string
		var prover string
		var created string
		var status ar.Status
		err = rows.Scan(&id, &prover, &created, &status)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		resultEnvelope := &ResultEnvelope{
			Type:    "Validation Report",
			Id:      id,
			Prover:  prover,
			Created: created,
			Status:  status,
		}

		results = append(results, resultEnvelope)
	}

	log.Tracef("Returning all result statistics with %v results", len(results))

	return results, nil
}

func (db *Db) GetAllResults(category string) ([]*ResultEnvelope, error) {

	log.Trace("Querying all results")

	filter, args := categoryFilter(category)
	stmt := fmt.Sprintf("SELECT id, prover, created, status, result FROM %v WHERE %v;",
		tableResults, filter)

	rows, err := db.db.Query(stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to exec sqlite3 statement: %w", err)
	}
	defer rows.Close()

	results := make([]*ResultEnvelope, 0)
	for rows.Next() {

		var id string
		var prover string
		var created string
		var status ar.Status
		var data string
		err = rows.Scan(&id, &prover, &created, &status, &data)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		result := new(any)
		err := json.Unmarshal([]byte(data), result)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal attestation result: %w", err)
		}

		resultEnvelope := &ResultEnvelope{
			Type:    "Validation Report",
			Id:      id,
			Prover:  prover,
			Created: created,
			Status:  status,
			Result:  *result,
		}

		results = append(results, resultEnvelope)
	}

	log.Tracef("Returning all results list with %v results", len(results))

	return results, nil
}

func (db *Db) GetEnvelopesByProver(name, category string) ([]*ResultEnvelope, error) {

	// Use the prover name from the JSON attestation result
	filter, args := categoryFilter(category)
	stmt := fmt.Sprintf(`SELECT id, prover, created, status FROM %s
		WHERE prover = ? AND %v
		ORDER BY serial DESC`,
		tableResults, filter)

	rows, err := db.db.Query(stmt, append([]any{name}, args...)...)
	if err != nil {
		return nil, fmt.Errorf("failed to exec sqlite3 statement: %w", err)
	}
	defer rows.Close()

	results := make([]*ResultEnvelope, 0)
	for rows.Next() {
		var id string
		var prover string
		var created string
		var status ar.Status
		err = rows.Scan(&id, &prover, &created, &status)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		resultEnvelope := &ResultEnvelope{
			Type:    "Validation Report",
			Id:      id,
			Prover:  prover,
			Created: created,
			Status:  status,
		}

		results = append(results, resultEnvelope)
	}

	return results, nil
}

func (db *Db) GetLatestResult(name, category string) ([]*ResultEnvelope, error) {

	log.Trace("Querying latest results")

	// Extract the prover name from the JSON attestation result
	filter, args := categoryFilter(category)
	stmt := fmt.Sprintf(`SELECT id, prover, created, status, result FROM %v
	WHERE prover=? AND %v
	ORDER BY serial DESC LIMIT 1`,
		tableResults, filter)

	rows, err := db.db.Query(stmt, append([]any{name}, args...)...)
	if err != nil {
		return nil, fmt.Errorf("failed to exec sqlite3 statement: %w", err)
	}
	defer rows.Close()

	results := make([]*ResultEnvelope, 0)
	for rows.Next() {
		var id string
		var prover string
		var created string
		var status ar.Status
		var data string
		err = rows.Scan(&id, &prover, &created, &status, &data)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		result := new(any)
		err := json.Unmarshal([]byte(data), result)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal attestation result: %w", err)
		}

		resultEnvelope := &ResultEnvelope{
			Type:    "Validation Report",
			Id:      id,
			Prover:  prover,
			Created: created,
			Status:  status,
			Result:  *result,
		}

		results = append(results, resultEnvelope)
	}

	log.Tracef("Returning latest results list with %v results", len(results))

	return results, nil
}

func (db *Db) GetLatestResults(category string) ([]*ResultOverview, error) {

	log.Trace("Querying latest result overviews")

	// Select the latest row per prover by serial: the created timestamps carry
	// the verifier's local timezone offset and do not compare correctly across zones
	filter, args := categoryFilter(category)
	stmt := fmt.Sprintf(`
SELECT
    r.id,
    r.category,
    r.prover,
    r.created,
    r.status,
    json_extract(r.result, '$.version'),
    (SELECT json_group_array(json_extract(m.value, '$.type'))
        FROM json_each(r.result, '$.measurements') m),
    json_extract(r.result, '$.metadata.imageDescriptionResult.name'),
    json_extract(r.result, '$.metadata.imageDescriptionResult.location'),
    json_extract(r.result, '$.metadata.imageDescriptionResult.description'),
    (SELECT json_group_array(json(json_extract(m.value, '$.details')))
        FROM json_each(r.result, '$.metadata.manifestResults') m
        WHERE json_extract(m.value, '$.details') IS NOT NULL)
FROM %[1]v r
JOIN (SELECT MAX(serial) AS serial FROM %[1]v WHERE %[2]v GROUP BY category, prover) latest
    ON r.serial = latest.serial
ORDER BY r.category, r.prover`, tableResults, filter)

	rows, err := db.db.Query(stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to exec sqlite3 statement: %w", err)
	}
	defer rows.Close()

	results := make([]*ResultOverview, 0)
	for rows.Next() {
		var id string
		var cat string
		var prover string
		var created string
		var status ar.Status
		var version, types, name, location, description, details sql.NullString
		err = rows.Scan(&id, &cat, &prover, &created, &status, &version, &types, &name,
			&location, &description, &details)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		overview := &ResultOverview{
			Id:       id,
			Category: cat,
			Prover:   prover,
			Created:  created,
			Status:   status,
			Version:  version.String,
		}

		if types.Valid {
			err = json.Unmarshal([]byte(types.String), &overview.MeasurementTypes)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal measurement types: %w", err)
			}
		}

		// Kept as raw JSON to retain the original key order
		if details.Valid {
			err = json.Unmarshal([]byte(details.String), &overview.Details)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal manifest details: %w", err)
			}
		}

		if name.String != "" || location.String != "" || description.String != "" {
			overview.Image = &ImageDescription{
				Name:        name.String,
				Location:    location.String,
				Description: description.String,
			}
		}

		results = append(results, overview)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate rows: %w", err)
	}

	log.Tracef("Returning %v latest result overviews", len(results))

	return results, nil
}

func (db *Db) GetResultById(id, category string) ([]*ResultEnvelope, error) {

	// Extract the prover name from the JSON attestation result
	filter, args := categoryFilter(category)
	stmt := fmt.Sprintf(`SELECT id, prover, created, status, result FROM %v
		WHERE id=? AND %v LIMIT 1`,
		tableResults, filter)

	rows, err := db.db.Query(stmt, append([]any{id}, args...)...)
	if err != nil {
		return nil, fmt.Errorf("failed to exec sqlite3 statement: %w", err)
	}
	defer rows.Close()

	results := make([]*ResultEnvelope, 0)
	for rows.Next() {
		var id string
		var prover string
		var created string
		var status ar.Status
		var data string
		err = rows.Scan(&id, &prover, &created, &status, &data)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		result := new(any)
		err := json.Unmarshal([]byte(data), result)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal attestation result: %w", err)
		}

		resultEnvelope := &ResultEnvelope{
			Type:    "Validation Report",
			Id:      id,
			Prover:  prover,
			Created: created,
			Status:  status,
			Result:  *result,
		}

		results = append(results, resultEnvelope)
	}

	return results, nil
}

func (db *Db) GetDeviceNames(category string) ([]string, error) {

	// Extract the prover name from the JSON attestation result
	filter, args := categoryFilter(category)
	stmt := fmt.Sprintf(`SELECT DISTINCT prover FROM %v WHERE %v`, tableResults, filter)

	rows, err := db.db.Query(stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to exec sqlite3 statement: %w", err)
	}
	defer rows.Close()

	var results []string
	for rows.Next() {
		var prover sql.NullString
		err = rows.Scan(&prover)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		if prover.Valid {
			results = append(results, prover.String)
		}
	}

	return results, nil
}

// OCSF methods

type ocsfFindingHeader struct {
	Time        string `json:"time"`
	FindingInfo *struct {
		UID string `json:"uid"`
	} `json:"finding_info"`
}

func (db *Db) InsertOcsfFinding(data []byte, category string) error {

	if !json.Valid(data) {
		return fmt.Errorf("provided data is not valid JSON")
	}

	header := new(ocsfFindingHeader)
	err := json.Unmarshal(data, header)
	if err != nil {
		return fmt.Errorf("failed to unmarshal OCSF finding header")
	}

	var findingUID string
	if header.FindingInfo != nil {
		findingUID = header.FindingInfo.UID
	}

	log.Tracef("Inserting OCSF finding '%v' into %v", findingUID, tableOcsfFindings)

	digest := sha256.Sum256(data)
	id := hex.EncodeToString(digest[:])

	insert := fmt.Sprintf(`INSERT INTO %v
		(id, category, time, finding_uid, finding)
		VALUES
		(?, ?, ?, ?, json(?))`, tableOcsfFindings)

	tx, err := db.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Commit()

	stmt, err := tx.Prepare(insert)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(id, category, header.Time, findingUID, string(data))
	if err != nil {
		return fmt.Errorf("failed to execute statement: %w", err)
	}

	return nil
}

func (db *Db) GetAllOcsfFindings(category string) ([]any, error) {

	log.Trace("Querying all OCSF findings")

	filter, args := categoryFilter(category)
	stmt := fmt.Sprintf("SELECT finding FROM %v WHERE %v ORDER BY serial DESC;",
		tableOcsfFindings, filter)

	rows, err := db.db.Query(stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to exec sqlite3 statement: %w", err)
	}
	defer rows.Close()

	results := make([]any, 0)
	for rows.Next() {
		var data string
		err = rows.Scan(&data)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		finding := new(any)
		err = json.Unmarshal([]byte(data), finding)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal OCSF finding: %w", err)
		}

		results = append(results, *finding)
	}

	log.Tracef("Returning %v OCSF findings", len(results))

	return results, nil
}

// Network event methods

func (db *Db) InsertNetworkEvent(data []byte, category string) error {

	if !json.Valid(data) {
		return fmt.Errorf("provided data is not valid JSON")
	}

	header := new(publish.NetworkEvent)
	err := json.Unmarshal(data, header)
	if err != nil {
		return fmt.Errorf("failed to unmarshal network event header")
	}

	log.Tracef("Inserting network event '%v -> %v' into %v",
		header.Verifier.Hostname, header.Prover.Hostname, tableNetworkEvents)

	digest := sha256.Sum256(data)
	id := hex.EncodeToString(digest[:])

	insert := fmt.Sprintf(`INSERT INTO %v
		(id, category, verifier, prover, status, time, event)
		VALUES
		(?, ?, ?, ?, ?, ?, json(?))`, tableNetworkEvents)

	tx, err := db.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Commit()

	stmt, err := tx.Prepare(insert)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(id, category, header.Verifier.Hostname, header.Prover.Hostname,
		header.Status, header.Time, string(data))
	if err != nil {
		return fmt.Errorf("failed to execute statement: %w", err)
	}

	return nil
}

func (db *Db) GetAllNetworkEvents(category string) ([]any, error) {

	log.Trace("Querying all network events")

	filter, args := categoryFilter(category)
	stmt := fmt.Sprintf("SELECT event FROM %v WHERE %v ORDER BY serial DESC;",
		tableNetworkEvents, filter)

	rows, err := db.db.Query(stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to exec sqlite3 statement: %w", err)
	}
	defer rows.Close()

	results := make([]any, 0)
	for rows.Next() {
		var data string
		err = rows.Scan(&data)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		event := new(any)
		err = json.Unmarshal([]byte(data), event)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal network event: %w", err)
		}

		results = append(results, *event)
	}

	log.Tracef("Returning %v network events", len(results))

	return results, nil
}

func (db *Db) GetNetworkGraph(category string) ([]any, error) {

	log.Trace("Querying network graph")

	filter, args := categoryFilter(category)
	stmt := fmt.Sprintf(`SELECT event FROM %[1]v
		WHERE serial IN (
			SELECT MAX(serial) FROM %[1]v
			WHERE %[2]v
			GROUP BY category, verifier, prover
		)
		ORDER BY serial DESC;`, tableNetworkEvents, filter)

	rows, err := db.db.Query(stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to exec sqlite3 statement: %w", err)
	}
	defer rows.Close()

	results := make([]any, 0)
	for rows.Next() {
		var data string
		err = rows.Scan(&data)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		event := new(any)
		err = json.Unmarshal([]byte(data), event)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal network event: %w", err)
		}

		results = append(results, *event)
	}

	log.Tracef("Returning network graph with %v edges", len(results))

	return results, nil
}

// Schema helpers

func createTables(db *sql.DB) error {

	stmts := []string{
		fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %v (
    serial INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL,
    category TEXT NOT NULL,
    prover TEXT,
    created TEXT,
    status TEXT,
    result TEXT
);`, tableResults),
		fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %v (
    serial INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL,
    category TEXT NOT NULL,
    time TEXT,
    finding_uid TEXT,
    finding TEXT
);`, tableOcsfFindings),
		fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %v (
    serial INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL,
    category TEXT NOT NULL,
    verifier TEXT,
    prover TEXT,
    status TEXT,
    time TEXT,
    event TEXT
);`, tableNetworkEvents),
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("failed to exec sqlite3 create statement: %w", err)
		}
	}

	return nil
}

// addCategoryColumn migrates tables created before categories were introduced.
// Existing rows are assigned the default category, so that they stay visible.
func addCategoryColumn(db *sql.DB, table, defaultCategory string) error {

	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%v);", table))
	if err != nil {
		return fmt.Errorf("failed to query table info: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return fmt.Errorf("failed to scan row: %w", err)
		}
		if name == "category" {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to iterate rows: %w", err)
	}

	log.Infof("Migrating table %v: adding category %v to existing rows", table, defaultCategory)

	stmt := fmt.Sprintf(`ALTER TABLE %v ADD COLUMN category TEXT NOT NULL DEFAULT '%v';`,
		table, defaultCategory)
	if _, err := db.Exec(stmt); err != nil {
		return fmt.Errorf("failed to add category column: %w", err)
	}

	return nil
}

func createIndexes(db *sql.DB) error {

	stmts := []string{
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_results_category_prover_serial
			ON %v (category, prover, serial);`, tableResults),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_ocsf_category_serial
			ON %v (category, serial);`, tableOcsfFindings),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_network_category_serial
			ON %v (category, serial);`, tableNetworkEvents),
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("failed to exec sqlite3 create index statement: %w", err)
		}
	}

	return nil
}

// createTriggers enforces the row limits within each category. They are
// recreated on every start so that changed limits take effect.
func createTriggers(db *sql.DB, maxRowsPerProver, maxRows int) error {

	stmts := []string{
		`DROP TRIGGER IF EXISTS limit_size;`,
		`DROP TRIGGER IF EXISTS limit_ocsf_size;`,
		`DROP TRIGGER IF EXISTS limit_network_size;`,
		fmt.Sprintf(`
CREATE TRIGGER limit_size AFTER INSERT ON %[1]v
BEGIN
    DELETE FROM %[1]v
    WHERE serial IN (
        SELECT serial
        FROM %[1]v
        WHERE category = NEW.category AND prover = NEW.prover
        ORDER BY serial DESC
        LIMIT -1 OFFSET %[2]v
    );
    DELETE FROM %[1]v
    WHERE serial IN (
        SELECT serial
        FROM %[1]v
        WHERE category = NEW.category
        ORDER BY serial DESC
        LIMIT -1 OFFSET %[3]v
    );
END;`, tableResults, maxRowsPerProver, maxRows),
		fmt.Sprintf(`
CREATE TRIGGER limit_ocsf_size AFTER INSERT ON %[1]v
BEGIN
    DELETE FROM %[1]v
    WHERE serial IN (
        SELECT serial
        FROM %[1]v
        WHERE category = NEW.category
        ORDER BY serial DESC
        LIMIT -1 OFFSET %[2]v
    );
END;`, tableOcsfFindings, maxRows),
		fmt.Sprintf(`
CREATE TRIGGER limit_network_size AFTER INSERT ON %[1]v
BEGIN
    DELETE FROM %[1]v
    WHERE serial IN (
        SELECT serial
        FROM %[1]v
        WHERE category = NEW.category
        ORDER BY serial DESC
        LIMIT -1 OFFSET %[2]v
    );
END;`, tableNetworkEvents, maxRows),
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("failed to exec sqlite3 trigger statement: %w", err)
		}
	}

	return nil
}
