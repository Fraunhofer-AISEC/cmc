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

func NewDb(path string, maxRowsPerProver, maxRows int) (*Db, error) {

	log.Tracef("Opening database %v", path)

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite3 DB: %w", err)
	}

	log.Tracef("Openend database %v", path)

	// Create results table
	ok, err := tableExists(db, tableResults)
	if err != nil {
		return nil, fmt.Errorf("failed to check tables: %w", err)
	}
	if !ok {
		if err = createResultsTable(db, maxRowsPerProver, maxRows); err != nil {
			return nil, fmt.Errorf("failed to create results table: %w", err)
		}
	}

	// Create OCSF findings table
	ok, err = tableExists(db, tableOcsfFindings)
	if err != nil {
		return nil, fmt.Errorf("failed to check tables: %w", err)
	}
	if !ok {
		if err = createOcsfTable(db, maxRows); err != nil {
			return nil, fmt.Errorf("failed to create OCSF table: %w", err)
		}
	}

	// Create network events table
	ok, err = tableExists(db, tableNetworkEvents)
	if err != nil {
		return nil, fmt.Errorf("failed to check tables: %w", err)
	}
	if !ok {
		if err = createNetworkTable(db, maxRows); err != nil {
			return nil, fmt.Errorf("failed to create network table: %w", err)
		}
	}

	return &Db{db: db}, nil
}

func (db *Db) Close() {
	db.db.Close()
}

// Result methods

func (db *Db) InsertResult(data []byte) error {

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

	log.Tracef("Inserting prover '%v' into %v", header.Prover.Hostname, tableResults)

	// Create ID through hashing
	digest := sha256.Sum256(data)
	id := hex.EncodeToString(digest[:])

	// Insert everything into the database
	insert := fmt.Sprintf(`INSERT INTO %v
		(id, prover, created, status, result)
		VALUES
		(?, ?, ?, ?, json(?))`, tableResults)

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

	_, err = stmt.Exec(id[:], header.Prover.Hostname, header.Created, header.Summary.Status, string(data))
	if err != nil {
		return fmt.Errorf("failed to execute statement: %w", err)
	}

	return nil
}

func (db *Db) GetAllStatistics() ([]*ResultEnvelope, error) {

	log.Trace("Querying all result statistics")

	stmt := fmt.Sprintf("SELECT id, prover, created, status FROM %v;", tableResults)

	rows, err := db.db.Query(stmt)
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

func (db *Db) GetAllResults() ([]*ResultEnvelope, error) {

	log.Trace("Querying all results")

	stmt := fmt.Sprintf("SELECT id, prover, created, status, result FROM %v;", tableResults)

	rows, err := db.db.Query(stmt)
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

func (db *Db) GetEnvelopesByProver(name string) ([]*ResultEnvelope, error) {

	// Use the prover name from the JSON attestation result
	stmt := fmt.Sprintf(`SELECT id, prover, created, status FROM %s
		WHERE prover = ?
		ORDER BY created DESC`,
		tableResults)

	rows, err := db.db.Query(stmt, name)
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

func (db *Db) GetLatestResult(name string) ([]*ResultEnvelope, error) {

	log.Trace("Querying latest results")

	// Extract the prover name from the JSON attestation result and sort by date
	stmt := fmt.Sprintf(`SELECT id, prover, created, status, result FROM %v
	WHERE prover=?
	ORDER BY created DESC LIMIT 1`,
		tableResults)

	rows, err := db.db.Query(stmt, name)
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

func (db *Db) GetLatestResults() ([]*ResultEnvelope, error) {

	// Extract the prover name from the JSON attestation result and sort by date
	stmt := fmt.Sprintf(`SELECT id, prover, MAX(created), status, result FROM %v
	GROUP BY prover`,
		tableResults)

	rows, err := db.db.Query(stmt)
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

func (db *Db) GetResultById(id string) ([]*ResultEnvelope, error) {

	// Extract the prover name from the JSON attestation result
	stmt := fmt.Sprintf(`SELECT id, prover, created, status, result FROM %v
		WHERE id=?`,
		tableResults)

	rows, err := db.db.Query(stmt, id)
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

func (db *Db) GetDeviceNames() ([]string, error) {

	// Extract the prover name from the JSON attestation result and sort by date
	stmt := fmt.Sprintf(`SELECT DISTINCT prover FROM %v`, tableResults)

	rows, err := db.db.Query(stmt)
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

func (db *Db) InsertOcsfFinding(data []byte) error {

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
		(id, time, finding_uid, finding)
		VALUES
		(?, ?, ?, json(?))`, tableOcsfFindings)

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

	_, err = stmt.Exec(id, header.Time, findingUID, string(data))
	if err != nil {
		return fmt.Errorf("failed to execute statement: %w", err)
	}

	return nil
}

// Network event methods

func (db *Db) InsertNetworkEvent(data []byte) error {

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
		(id, verifier, prover, status, time, event)
		VALUES
		(?, ?, ?, ?, ?, json(?))`, tableNetworkEvents)

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

	_, err = stmt.Exec(id, header.Verifier.Hostname, header.Prover.Hostname,
		header.Status, header.Time, string(data))
	if err != nil {
		return fmt.Errorf("failed to execute statement: %w", err)
	}

	return nil
}

func (db *Db) GetAllNetworkEvents() ([]any, error) {

	log.Trace("Querying all network events")

	stmt := fmt.Sprintf("SELECT event FROM %v ORDER BY serial DESC;", tableNetworkEvents)

	rows, err := db.db.Query(stmt)
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

func (db *Db) GetNetworkGraph() ([]any, error) {

	log.Trace("Querying network graph")

	stmt := fmt.Sprintf(`SELECT event FROM %v
		WHERE serial IN (
			SELECT MAX(serial) FROM %v
			GROUP BY verifier, prover
		)
		ORDER BY serial DESC;`, tableNetworkEvents, tableNetworkEvents)

	rows, err := db.db.Query(stmt)
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

// Table creation helpers

func tableExists(db *sql.DB, table string) (bool, error) {
	stmt := fmt.Sprintf("SELECT name FROM sqlite_master WHERE type='table' AND name='%v';",
		table)

	rows, err := db.Query(stmt)
	if err != nil {
		return false, fmt.Errorf("failed to exec sqlite3 statement: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		log.Tracef("Table %v exists", table)
		return true, nil
	}

	log.Tracef("Table %v does not exist", table)
	return false, nil
}

func createResultsTable(db *sql.DB, maxRowsPerProver int, maxTotalRows int) error {

	log.Tracef("Creating table %v", tableResults)

	sqlStmt := fmt.Sprintf(`
CREATE TABLE %v (
    serial INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL,
    prover TEXT,
    created TEXT,
    status TEXT,
    result TEXT
);`, tableResults)
	_, err := db.Exec(sqlStmt)
	if err != nil {
		return fmt.Errorf("failed to exec sqlite3 create statement: %w", err)
	}

	log.Tracef("Setting combined trigger for per-prover and total limits")

	// Combined trigger for per-prover and total limits
	sqlStmt = fmt.Sprintf(`
CREATE TRIGGER limit_size AFTER INSERT ON %v
BEGIN
    DELETE FROM %v
    WHERE serial IN (
        SELECT serial
        FROM %v
        WHERE prover = NEW.prover
        ORDER BY serial DESC
        LIMIT -1 OFFSET %v
    );
    DELETE FROM %v
    WHERE serial IN (
        SELECT serial
        FROM %v
        ORDER BY serial DESC
        LIMIT -1 OFFSET %v
    );
END;`, tableResults, tableResults, tableResults, maxRowsPerProver, tableResults, tableResults, maxTotalRows)

	_, err = db.Exec(sqlStmt)
	if err != nil {
		return fmt.Errorf("failed to exec sqlite3 combined trigger statement: %w", err)
	}

	log.Tracef("Created table %v with per-prover and total limits", tableResults)
	return nil
}

func createOcsfTable(db *sql.DB, maxTotalRows int) error {

	log.Tracef("Creating OCSF table %v", tableOcsfFindings)

	sqlStmt := fmt.Sprintf(`
CREATE TABLE %v (
    serial INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL,
    time TEXT,
    finding_uid TEXT,
    finding TEXT
);`, tableOcsfFindings)
	_, err := db.Exec(sqlStmt)
	if err != nil {
		return fmt.Errorf("failed to exec sqlite3 create statement: %w", err)
	}

	sqlStmt = fmt.Sprintf(`
CREATE TRIGGER limit_ocsf_size AFTER INSERT ON %v
BEGIN
    DELETE FROM %v
    WHERE serial IN (
        SELECT serial
        FROM %v
        ORDER BY serial DESC
        LIMIT -1 OFFSET %v
    );
END;`, tableOcsfFindings, tableOcsfFindings, tableOcsfFindings, maxTotalRows)

	_, err = db.Exec(sqlStmt)
	if err != nil {
		return fmt.Errorf("failed to exec sqlite3 trigger statement: %w", err)
	}

	log.Tracef("Created OCSF table %v with total limit %v", tableOcsfFindings, maxTotalRows)
	return nil
}

func createNetworkTable(db *sql.DB, maxTotalRows int) error {

	log.Tracef("Creating network table %v", tableNetworkEvents)

	sqlStmt := fmt.Sprintf(`
CREATE TABLE %v (
    serial INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL,
    verifier TEXT,
    prover TEXT,
    status TEXT,
    time TEXT,
    event TEXT
);`, tableNetworkEvents)
	_, err := db.Exec(sqlStmt)
	if err != nil {
		return fmt.Errorf("failed to exec sqlite3 create statement: %w", err)
	}

	sqlStmt = fmt.Sprintf(`
CREATE TRIGGER limit_network_size AFTER INSERT ON %v
BEGIN
    DELETE FROM %v
    WHERE serial IN (
        SELECT serial
        FROM %v
        ORDER BY serial DESC
        LIMIT -1 OFFSET %v
    );
END;`, tableNetworkEvents, tableNetworkEvents, tableNetworkEvents, maxTotalRows)

	_, err = db.Exec(sqlStmt)
	if err != nil {
		return fmt.Errorf("failed to exec sqlite3 trigger statement: %w", err)
	}

	log.Tracef("Created network table %v with total limit %v", tableNetworkEvents, maxTotalRows)
	return nil
}
