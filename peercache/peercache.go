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
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sync"

	"github.com/sirupsen/logrus"

	"golang.org/x/exp/maps"
)

var (
	log = logrus.WithField("service", "peercache")
)

type Cache struct {
	path  string                       // Optional persistent storage path
	data  map[string]map[string][]byte // Peer ID -> metadata-hash -> metadata
	mutex sync.Mutex
}

// Load loads the peer cache from persistent storage
func Load(path string) (*Cache, error) {

	log.Debug("Loading cached peer metadata")

	cache := &Cache{
		path: path,
		data: map[string]map[string][]byte{},
	}

	// Return empty peer cache if peer cache folder is not configured
	if path == "" {
		log.Debugf("No peer cache configured. Do not load peer cache from storage")
		return cache, nil
	}

	// Iterate through file system and collect persistent peer cache
	dirs, err := os.ReadDir(path)
	if err != nil {
		log.Debugf("Peer cache folder does not (yet) exist. Do not read cache")
		return cache, nil
	}
	log.Debugf("Read peer cache folder %v", path)

	for _, d := range dirs {
		if d.IsDir() {
			subfolder := filepath.Join(path, d.Name())
			log.Tracef("Read peer %v cache", d.Name())

			// Content-addressable storage: directory name corresponds to peer ID
			cache.data[d.Name()] = map[string][]byte{}

			files, err := os.ReadDir(subfolder)
			if err != nil {
				return nil, fmt.Errorf("failed to read peer %v cache: %w", d.Name(), err)
			}

			for _, file := range files {
				if !file.IsDir() {
					filePath := filepath.Join(subfolder, file.Name())
					log.Tracef("Read cached metadata item %v", filePath)
					content, err := os.ReadFile(filePath)
					if err != nil {
						return nil, fmt.Errorf("failed to read peer cache file %v: %w", filePath, err)
					}

					// Content-addressable storage filename is hash of metadata content
					cache.data[d.Name()][file.Name()] = content
				}
			}
		}
	}

	return cache, nil
}

// Get returns the cached metadata for a given peer
func (cache *Cache) Get(peer string) map[string][]byte {

	if peer == "" {
		log.Debugf("No peer specified. Will not retrieve cached metadata")
		return nil
	}

	if cache == nil {
		log.Warnf("internal error: peer cache is nil")
		return nil
	}

	if _, exists := cache.data[peer]; !exists {
		log.Debugf("No metadata cached for peer %q", peer)
		return nil
	}

	return cache.data[peer]
}

// GetKeys returns the hashes, i.e., the IDs of the cached metadata items
func (cache *Cache) GetKeys(peer string) []string {

	if cache == nil {
		return []string{}
	}

	c, ok := cache.data[peer]
	if ok {
		return maps.Keys(c)
	} else {
		return []string{}
	}
}

// Update updates the volatile and persistent peer cache for peer peer
// through adding newly received metadata and removing cache misses
func (cache *Cache) Update(peer string, new map[string][]byte) error {

	if cache == nil {
		return fmt.Errorf("internal error: peer cache is nil")
	}

	log.Debugf("Updating volatile peer cache for peer %v", peer)

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	// Update volatile peer cache through overwriting the existing peer cache with the updated
	// peer cache
	cache.data[peer] = make(map[string][]byte, len(new))
	for k, v := range new {
		cache.data[peer][k] = v
	}

	// Finished if persistent peer cache is not configured
	if cache.path == "" {
		log.Debugf("No persistent peer cache configured. Do not store persistently")
		return nil
	}

	// Update the persistent peer cache
	data, ok := cache.data[peer]
	if !ok {
		log.Debugf("Cache for peer %v does not exist. Do not store", peer)
		return nil
	}
	log.Debugf("Updating persistent peer cache for peer %v", peer)

	// Ensure the peer cache directory exists
	peerDir := path.Join(cache.path, peer)
	if err := os.MkdirAll(peerDir, 0755); err != nil {
		return fmt.Errorf("failed to create peer cache %v: %w", peerDir, err)
	}

	// Track files on disk
	filesOnDisk, err := os.ReadDir(peerDir)
	if err != nil {
		return fmt.Errorf("failed to read peer cache directory %v: %w", peerDir, err)
	}
	existingFiles := make(map[string]struct{})
	for _, f := range filesOnDisk {
		if !f.Type().IsRegular() {
			continue
		}
		existingFiles[f.Name()] = struct{}{}
	}

	// Write new or updated files
	for hash, content := range data {
		fpath := path.Join(peerDir, hash)
		if _, exists := existingFiles[hash]; exists {
			// File already exists, no need to write
			delete(existingFiles, hash) // Remove as the remaining existing files will be deleted
			continue
		}
		log.Tracef("Caching metadata file %v", fpath)
		if err := os.WriteFile(fpath, content, 0644); err != nil {
			return fmt.Errorf("failed to cache %v: %w", fpath, err)
		}
	}

	// Remove files no longer present in cache
	for staleFile := range existingFiles {
		fpath := path.Join(peerDir, staleFile)
		log.Tracef("Removing stale cache file %v", fpath)
		if err := os.Remove(fpath); err != nil {
			log.Warnf("Failed to remove stale file %v: %v", fpath, err)
		}
	}

	return nil
}
