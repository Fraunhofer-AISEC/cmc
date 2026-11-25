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

package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Fraunhofer-AISEC/cmc/rvps/store"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
)

// SQLite implementation of store.Index interface based on sqlite3 database
type SQLite struct {
	db *sql.DB
}

// test interface compatibility
var _ store.Index = (*SQLite)(nil)

const (
	tableQuery  = "id, type, name, version, version_time, signer, format, created"
	selectQuery = "sequence, " + tableQuery

	// wait for concurrent writers instead of failing immediately, and do not let writers block readers
	openOptions = "?_busy_timeout=5000&_journal_mode=WAL"
)

func NewSQLiteIndex(path string) (*SQLite, error) {
	log.Infof("Loading sqlite3 index %v", path)

	db, err := sql.Open("sqlite3", path+openOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to load sqlite3 database: %w", err)
	}

	// serialize all access to database to prevent errors (sqlite3 only supports a single writer)
	db.SetMaxOpenConns(1)

	// check if the metadata table already exists or create it
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS metadata (
	sequence INTEGER PRIMARY KEY AUTOINCREMENT,
	id TEXT NOT NULL UNIQUE,
	type TEXT NOT NULL,
	name TEXT NOT NULL,
	version TEXT NOT NULL,
	version_time INTEGER NOT NULL,
	signer TEXT NOT NULL,
	format TEXT NOT NULL,
	created TEXT NOT NULL
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create sqlite3 database table metadata: %w", err)
	}

	// check if the lookup index for the metadata table already exists or create it (to speed up common lookup patterns)
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS index_metadata_type_name_version ON metadata (type, name, version_time)"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create sqlite3 database index index_metadata_type_name_version: %w", err)
	}

	return &SQLite{db: db}, nil
}

func (s *SQLite) Close() {
	s.db.Close()
}

func (s *SQLite) Insert(ctx context.Context, e store.EntryInfo) (bool, error) {
	// try to insert the entry into the table
	exec := fmt.Sprintf(`INSERT OR IGNORE INTO metadata (%v) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, tableQuery)
	res, err := s.db.ExecContext(ctx, exec, e.Id, e.Type, e.Name, e.Version, e.VersionTime, e.Signer, e.Format, e.Created)
	if err != nil {
		return false, fmt.Errorf("failed to insert into sqlite3 database: %w", err)
	}

	// check if an actual insertion occurred, as the entry otherwise already existed, and no more updates are necessary
	count, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to check affected rows: %w", err)
	}
	return count > 0, nil
}

func (s *SQLite) ByID(ctx context.Context, id string) (*store.EntryInfo, error) {
	return s.fetch(ctx, fmt.Sprintf("SELECT %v FROM metadata WHERE id = ? LIMIT 1", selectQuery), id)
}

func (s *SQLite) Latest(ctx context.Context, kind, name string, signer *string) (*store.EntryInfo, error) {
	filter, args := "", []any{kind, name}

	if signer != nil {
		filter = " AND signer = ?"
		args = append(args, signer)
	}

	return s.fetch(ctx, fmt.Sprintf("SELECT %v FROM metadata WHERE type = ? AND name = ?%v ORDER BY version_time DESC, sequence DESC LIMIT 1", selectQuery, filter), args...)
}

func (s *SQLite) List(ctx context.Context, f store.Filter, offset uint) ([]store.EntryInfo, error) {
	// construct the filter statement for the query depending on the provided parameter
	filter, args := "", make([]any, 0, 5)
	for _, c := range []struct{ column, value string }{{"type", f.Kind}, {"name", f.Name}, {"signer", f.Signer}} {
		if c.value != "" {
			if filter == "" {
				filter = "WHERE "
			} else {
				filter += " AND "
			}
			filter += c.column + " = ?"
			args = append(args, c.value)
		}
	}
	args = append(args, store.ListPageSize, int64(offset))

	// perform the actual query for the given information (sequence as final criteria to ensure a stable order across pages)
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf("SELECT %v FROM metadata %v ORDER BY type, name, version_time DESC, sequence DESC LIMIT ? OFFSET ?",
		selectQuery, filter), args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list sqlite3 database: %w", err)
	}
	defer rows.Close()

	// unpack all of the queried rows
	return rowsToEntries(rows)
}

func (s *SQLite) fetch(ctx context.Context, query string, args ...any) (*store.EntryInfo, error) {
	// perform the actual query for the given information
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from sqlite3 database: %w", err)
	}
	defer rows.Close()

	// unpack the found row (can at most be one)
	entries, err := rowsToEntries(rows)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}
	return &entries[0], nil
}

func rowsToEntries(rows *sql.Rows) ([]store.EntryInfo, error) {
	var entries []store.EntryInfo

	// iterate over all entries in the sql selection and unpack them
	for rows.Next() {
		var e store.EntryInfo
		if err := rows.Scan(&e.Sequence, &e.Id, &e.Type, &e.Name, &e.Version, &e.VersionTime, &e.Signer, &e.Format, &e.Created); err != nil {
			return nil, fmt.Errorf("failed to unpack row: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate rows: %w", err)
	}
	return entries, nil
}
