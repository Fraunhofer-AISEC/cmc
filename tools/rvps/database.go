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
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
)

type Database struct {
	db *sql.DB
}

type DatabaseInfo struct {
	Id          string
	Type        string
	Name        string
	Version     string
	VersionTime int64
	Created     string
}
type DatabaseEntry struct {
	DatabaseInfo
	Raw []byte
}
type DatabaseHash struct {
	Algorithm string
	Hash      string
}

type DatabaseHashMatch struct {
	DatabaseHash
	DatabaseInfo
}

const (
	tableInfoQuery = "id, type, name, version, version_time, created"
	tableFullQuery = tableInfoQuery + ", raw"
)

func NewDatabase(path string) (*Database, error) {
	log.Infof("Loading database %v", path)

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("failed to load sqlite3 database: %w", err)
	}

	// check if the metadata table already exists or create it
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS metadata (
	id TEXT PRIMARY KEY,
	type TEXT NOT NULL,
	name TEXT NOT NULL,
	version TEXT NOT NULL,
	version_time INTEGER NOT NULL,
	created TEXT NOT NULL,
	raw BLOB NOT NULL
	)`); err != nil {
		return nil, fmt.Errorf("failed to create sqlite3 database table metadata: %w", err)
	}

	// check if the lookup index for the metadata table already exists or create it (to speed up common lookup patterns)
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS index_metadata_type_name_version ON metadata (type, name, version_time)"); err != nil {
		return nil, fmt.Errorf("failed to create sqlite3 database index index_metadata_type_name_version: %w", err)
	}

	return &Database{db: db}, nil
}

func (db *Database) Close() {
	db.db.Close()
}

func (db *Database) Enumerate(kind, name string) ([]DatabaseInfo, error) {
	// construct the filter statement for the query depending on the provided parameter
	filter, args := "", make([]any, 0, 2)
	if kind != "" || name != "" {
		filter = "WHERE"
		if kind != "" {
			filter += " type = ?"
			args = append(args, kind)
		}
		if name != "" {
			if kind != "" {
				filter += " AND"
			}
			filter += " name = ?"
			args = append(args, name)
		}
	}

	// perform the actual query for the given information
	rows, err := db.db.Query(fmt.Sprintf("SELECT %v FROM metadata %v ORDER BY type, name, version_time DESC",
		tableInfoQuery, filter), args...)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate sqlite3 database: %w", err)
	}
	defer rows.Close()

	// unpack all of the queried rows
	return rowsToEntries(rows, func(info *DatabaseInfo) error {
		return rows.Scan(&info.Id, &info.Type, &info.Name, &info.Version, &info.VersionTime, &info.Created)
	})
}

func (db *Database) FetchById(id string) (*DatabaseEntry, error) {
	return db.fetch(fmt.Sprintf("SELECT %v FROM metadata WHERE id = ? LIMIT 1", tableFullQuery), id)
}

func (db *Database) FetchByName(name, kind string) (*DatabaseEntry, error) {
	return db.fetch(fmt.Sprintf("SELECT %v FROM metadata WHERE name = ? AND type = ? ORDER BY version_time DESC LIMIT 1", tableFullQuery), name, kind)
}

func (db *Database) fetch(query string, args ...any) (*DatabaseEntry, error) {
	// perform the actual query for the given information
	rows, err := db.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from sqlite3 database: %w", err)
	}
	defer rows.Close()

	// unpack the found row (can at most be one)
	if entries, err := rowsToEntries(rows, func(entry *DatabaseEntry) error {
		return rows.Scan(&entry.Id, &entry.Type, &entry.Name, &entry.Version, &entry.VersionTime, &entry.Created, &entry.Raw)
	}); err != nil {
		return nil, err
	} else if len(entries) == 0 {
		return nil, nil
	} else {
		return &entries[0], nil
	}
}

func (db *Database) Insert(entry *DatabaseEntry, hashes []DatabaseHash, manifests []string) (bool, error) {
	// try to insert the entry into the table
	exec := fmt.Sprintf(`INSERT OR IGNORE INTO metadata (%v) VALUES (?, ?, ?, ?, ?, ?, ?)`, tableFullQuery)
	res, err := db.db.Exec(exec, entry.Id, entry.Type, entry.Name, entry.Version, entry.VersionTime, entry.Created, entry.Raw)
	if err != nil {
		return false, fmt.Errorf("failed to insert into sqlite3 database: %w", err)
	}

	// check if an actual insertion occurred, as the entry otherwise already existed, and no more updates are necessary
	count, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to check affected rows: %w", err)
	}
	if count == 0 {
		return false, nil
	}
	return true, nil
}

func rowsToEntries[T any](rows *sql.Rows, unpack func(*T) error) ([]T, error) {
	var entries []T

	// iterate over all entries in the sql selection and unpack them
	for rows.Next() {
		var entry T
		if err := unpack(&entry); err != nil {
			return nil, fmt.Errorf("failed to unpack row: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate rows: %w", err)
	}
	return entries, nil
}
