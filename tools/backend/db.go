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
)

type Db struct {
	db    *sql.DB
	table string
}

type Status string

const (
	StatusSuccess Status = "success"
	StatusFail    Status = "fail"
	StatusWarn    Status = "warn"
)

type ResultHeader struct {
	Status Status `json:"status"`
}

type VerificationResultHeader struct {
	Prover  string       `json:"prover,omitempty"`
	Created string       `json:"created,omitempty"`
	Summary ResultHeader `json:"summary"`
}

type ResultEnvelope struct {
	Type    string `json:"type"`
	Id      string `json:"id"`
	Prover  string `json:"prover"`
	Created string `json:"created"`
	Status  Status `json:"status"`
	Result  any    `json:"result"`
}

func NewDb(path string, table string, maxRowsPerProver, maxRows int) (*Db, error) {

	log.Tracef("Opening database %v", path)

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite3 DB: %w", err)
	}

	log.Tracef("Openend database %v", path)

	ok, err := tableExists(db, table)
	if err != nil {
		return nil, fmt.Errorf("failed to check tables: %w", err)
	}
	if !ok {
		createTable(db, table, maxRowsPerProver, maxRows)
	}

	return &Db{db: db, table: table}, nil
}

func (db *Db) Close() {
	db.db.Close()
}

func (db *Db) InsertResult(data []byte) error {

	if !json.Valid(data) {
		return fmt.Errorf("provided data is not valid JSON")
	}

	// Unmarshal the header to get prover and creation date
	header := new(VerificationResultHeader)
	err := json.Unmarshal(data, header)
	if err != nil {
		return fmt.Errorf("failed to unmarshal header")
	}

	if header.Prover == "" {
		return errors.New("cannot insert into database: The result prover field is empty")
	}

	log.Tracef("Inserting prover '%v' into %v", header.Prover, db.table)

	// Create ID through hashing
	digest := sha256.Sum256(data)
	id := hex.EncodeToString(digest[:])

	// Insert everything into the database
	insert := fmt.Sprintf(`INSERT INTO %v
		(id, prover, created, status, result)
		VALUES
		(?, ?, ?, ?, json(?))`, db.table)

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

	_, err = stmt.Exec(id[:], header.Prover, header.Created, header.Summary.Status, string(data))
	if err != nil {
		return fmt.Errorf("failed to execute statement: %w", err)
	}

	return nil
}

func (db *Db) GetAllStatistics() ([]*ResultEnvelope, error) {

	log.Trace("Querying all result statistics")

	stmt := fmt.Sprintf("SELECT id, prover, created, status FROM %v;", db.table)

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
		var status Status
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

	stmt := fmt.Sprintf("SELECT id, prover, created, status, result FROM %v;", db.table)

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
		var status Status
		var data string
		err = rows.Scan(&id, &prover, &created, &status, &data)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		result := new(any)
		err := json.Unmarshal([]byte(data), result)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal verification result: %w", err)
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

	// Extract the prover name from the JSON Verification Result
	stmt := fmt.Sprintf(`SELECT id, prover, created, status FROM %v
		WHERE prover='%s'
		ORDER BY created DESC`,
		db.table, name)

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
		var status Status
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

	// Extract the prover name from the JSON Verification Result and sort by date
	stmt := fmt.Sprintf(`SELECT id, prover, created, status, result FROM %v
	WHERE prover='%s'
	ORDER BY created DESC LIMIT 1`,
		db.table, name)

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
		var status Status
		var data string
		err = rows.Scan(&id, &prover, &created, &status, &data)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		result := new(any)
		err := json.Unmarshal([]byte(data), result)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal verification result: %w", err)
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

	// Extract the prover name from the JSON Verification Result and sort by date
	stmt := fmt.Sprintf(`SELECT id, prover, MAX(created), status, result FROM %v
	GROUP BY prover`,
		db.table)

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
		var status Status
		var data string
		err = rows.Scan(&id, &prover, &created, &status, &data)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		result := new(any)
		err := json.Unmarshal([]byte(data), result)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal verification result: %w", err)
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

	// Extract the prover name from the JSON Verification Result
	stmt := fmt.Sprintf(`SELECT id, prover, created, status, result FROM %v
		WHERE id='%s'`,
		db.table, id)

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
		var status Status
		var data string
		err = rows.Scan(&id, &prover, &created, &status, &data)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		result := new(any)
		err := json.Unmarshal([]byte(data), result)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal verification result: %w", err)
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

	// Extract the prover name from the JSON Verification Result and sort by date
	stmt := fmt.Sprintf(`SELECT DISTINCT prover FROM %v`, db.table)

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

func createTable(db *sql.DB, table string, maxRowsPerProver int, maxTotalRows int) error {

	log.Tracef("Creating table %v", table)

	sqlStmt := fmt.Sprintf(`
CREATE TABLE %v (
    serial INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL,
    prover TEXT,
    created TEXT,
    status TEXT,
    result TEXT
);`, table)
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
END;`, table, table, table, maxRowsPerProver, table, table, maxTotalRows)

	_, err = db.Exec(sqlStmt)
	if err != nil {
		return fmt.Errorf("failed to exec sqlite3 combined trigger statement: %w", err)
	}

	log.Tracef("Created table %v with per-prover and total limits", table)
	return nil
}
