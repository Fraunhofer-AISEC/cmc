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

package store

import "context"

// maximum number of entries returned at a single call to Index.List
const ListPageSize = 100

type EntryInfo struct {
	Sequence    int64
	Id          string
	Type        string
	Name        string
	Version     string
	VersionTime int64
	Signer      string
	Format      string
	Created     string
}

// fields are optional, an empty filter matches everything
type Filter struct {
	Name   string
	Kind   string
	Signer string
}

// blob store for reading and writing and fetching persistent binary blobs
// 'ctx' optional and only for environments, which require it
type BlobStore interface {
	Close()
	Put(ctx context.Context, id string, data []byte) error
	Get(ctx context.Context, id string) ([]byte, error)
	Has(ctx context.Context, id string) (bool, error)
}

// index interface to query for existing metadata information
// id's reference the blobs stored in a blob store
type Index interface {
	Close()
	Insert(ctx context.Context, e EntryInfo) (bool, error)
	ByID(ctx context.Context, id string) (*EntryInfo, error)
	Latest(ctx context.Context, kind, name string, signer *string) (*EntryInfo, error)
	List(ctx context.Context, f Filter, offset uint) ([]EntryInfo, error)
}
