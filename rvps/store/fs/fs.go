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

package fs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/Fraunhofer-AISEC/cmc/rvps/store"
	log "github.com/sirupsen/logrus"
)

// FileSystem implementation of store.BlobStore interface based on a directory
// blobs are stored as <path>/<first two characters of id>/<id> to keep the directories small
type FileSystem struct {
	path string
}

// test interface compatibility
var _ store.BlobStore = (*FileSystem)(nil)

// ids become part of the file path and are therefore restricted to lowercase hex digests
var regexIdCheck = regexp.MustCompile(`^[0-9a-f]{2,}$`)

func NewFileSystemStore(path string) (*FileSystem, error) {
	log.Infof("Loading filesystem blob store %v", path)

	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create blob store directory: %w", err)
	}
	return &FileSystem{path: path}, nil
}

func (f *FileSystem) Close() {}

func (f *FileSystem) Put(ctx context.Context, id string, data []byte) error {
	path, err := f.blobPath(id)
	if err != nil {
		return err
	}

	// check if the blob already exists, in which case it can be ignored (blobs are immutable and addressed by their content)
	if exists, err := f.Has(ctx, id); err != nil || exists {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create blob directory: %w", err)
	}

	// write the blob to a temporary file and move it in place, to never expose partially written blobs
	tmp, err := os.CreateTemp(filepath.Dir(path), id+".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary blob file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write blob %v: %w", id, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to sync blob %v: %w", id, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close blob %v: %w", id, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("failed to store blob %v: %w", id, err)
	}
	return nil
}
func (f *FileSystem) Get(ctx context.Context, id string) ([]byte, error) {
	path, err := f.blobPath(id)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read blob %v: %w", id, err)
	}
	return data, nil
}

func (f *FileSystem) Has(ctx context.Context, id string) (bool, error) {
	path, err := f.blobPath(id)
	if err != nil {
		return false, err
	}

	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("failed to check blob %v: %w", id, err)
	}
	return true, nil
}

func (f *FileSystem) blobPath(id string) (string, error) {
	if !regexIdCheck.MatchString(id) {
		return "", fmt.Errorf("malformed blob id (%v)", id)
	}
	return filepath.Join(f.path, id[:2], id), nil
}
