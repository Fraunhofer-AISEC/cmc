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

package provision

import (
	"encoding/json"
	"os"
	"path"
	"sync"
	"time"
)

// cachedCollateral stores entries in the TDX collateral cache. It stores the raw
// HTTP body together with the URL-encoded PEM issuer chain that PCS returns in
// the response header. SourceUrls is only used for the root CA CRL
type cachedCollateral struct {
	FetchedAt   time.Time `json:"fetchedAt"`
	Body        []byte    `json:"body"`
	IssuerChain string    `json:"issuerChain,omitempty"`
	SourceUrls  []string  `json:"sourceUrls,omitempty"`
}

// tdxCache caches TDX collateral fetched from Intel PCS or PCCS
type tdxCache struct {
	mu     sync.Mutex
	folder string
	mem    map[string]*cachedCollateral
	ttl    time.Duration
}

// newTdxCache creates a new TDX collateral cache
func newTdxCache(folder string, ttl time.Duration) *tdxCache {
	return &tdxCache{
		folder: folder,
		mem:    make(map[string]*cachedCollateral),
		ttl:    ttl,
	}
}

// get returns the cached entry for key plus a freshness flag
func (c *tdxCache) get(key string) (entry *cachedCollateral, fresh bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.mem[key]; ok {
		return e, time.Since(e.FetchedAt) < c.ttl
	}
	if c.folder == "" {
		return nil, false
	}

	filePath := path.Join(c.folder, key+".json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("failed to read TDX cache file %v: %v", filePath, err)
		}
		return nil, false
	}
	e := &cachedCollateral{}
	if err := json.Unmarshal(data, e); err != nil {
		log.Warnf("failed to parse TDX cache file %v: %v", filePath, err)
		return nil, false
	}
	c.mem[key] = e
	return e, time.Since(e.FetchedAt) < c.ttl
}

// put stores the entry under key, in memory and (if configured) on disk.
func (c *tdxCache) put(key string, entry *cachedCollateral) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.mem[key] = entry

	if c.folder == "" {
		return
	}
	if _, err := os.Stat(c.folder); err != nil {
		if err := os.MkdirAll(c.folder, 0755); err != nil {
			log.Warnf("failed to create TDX cache folder %v: %v", c.folder, err)
			return
		}
	}
	data, err := json.Marshal(entry)
	if err != nil {
		log.Warnf("failed to encode TDX cache entry %v: %v", key, err)
		return
	}
	filePath := path.Join(c.folder, key+".json")
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		log.Warnf("failed to write TDX cache file %v: %v", filePath, err)
		return
	}
	log.Tracef("Cached TDX collateral at %v", filePath)
}
