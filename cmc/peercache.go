// Copyright (c) 2021 Fraunhofer AISEC
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

package cmc

import (
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"sync"
)

var (
	peerCacheMutex sync.Mutex
)

func LoadCacheMetadata(path string) (map[string]map[string][]byte, error) {

	log.Trace("Loading cached peer metadata")

	peerCache := map[string]map[string][]byte{}

	// Return empty peer cache if peer cache folder is not configured
	if path == "" {
		log.Tracef("No peer cache configured. Do not load peer cache from storage")
		return peerCache, nil
	}

	// Iterate through file system and collect persistent peer cache
	dirs, err := os.ReadDir(path)
	if err != nil {
		log.Tracef("Peer cache folder does not (yet) exist. Do not read cache")
		return peerCache, nil
	}
	log.Tracef("Read peer cache folder %v", path)

	for _, d := range dirs {
		if d.IsDir() {
			subfolder := filepath.Join(path, d.Name())
			log.Tracef("Read peer %v cache", d.Name())
			peerCache[d.Name()] = map[string][]byte{}

			files, err := os.ReadDir(subfolder)
			if err != nil {
				return peerCache, fmt.Errorf("failed to read peer %v cache: %w", d.Name(), err)
			}

			for _, file := range files {
				if !file.IsDir() {
					filePath := filepath.Join(subfolder, file.Name())
					log.Tracef("Read cached metadata item %v", filePath)
					content, err := os.ReadFile(filePath)
					if err != nil {
						return peerCache, fmt.Errorf("failed to read peer cache file %v: %w", filePath, err)
					}
					peerCache[d.Name()][file.Name()] = content
				}
			}
		}
	}

	return peerCache, nil
}

// GetCached iterates the cache sent by the verifier and returns hits and misses
func GetCacheMisses(cached []string, metadata map[string][]byte) []string {

	misses := make([]string, 0)

	for _, c := range cached {
		_, exists := metadata[c]
		if !exists {
			misses = append(misses, c)
		}
	}
	return misses
}

func UpdateCacheMetadata(peer string, cmcCache map[string]map[string][]byte, reqCache map[string][]byte, misses []string) {

	// Remove cache misses
	if _, exists := cmcCache[peer]; exists {
		for _, miss := range misses {
			delete(cmcCache[peer], miss)
		}
	}

	// Add newly received metadata
	peerCacheMutex.Lock()
	if _, exists := cmcCache[peer]; !exists {
		cmcCache[peer] = map[string][]byte{}
	}
	maps.Copy(cmcCache[peer], reqCache)
	peerCacheMutex.Unlock()
}

func StoreCacheMetadata(peerCache, prover string, cached map[string][]byte, misses []string) error {

	log.Tracef("Updating peer cache for peer %v", prover)

	// Return if peer cache is not configured
	if peerCache == "" {
		log.Tracef("No peer cache configured. Do not store persistently")
		return nil
	}
	if prover == "" {
		log.Tracef("No prover configured. Do not store peer cache")
		return nil
	}

	peerCacheMutex.Lock()

	// Create cache folder if not existing
	if _, err := os.Stat(peerCache); err != nil {
		if err := os.MkdirAll(peerCache, 0755); err != nil {
			return fmt.Errorf("failed to create peer cache %v: %w", peerCache, err)
		}
	}

	// Create peer cache subfolder if not existing
	peerCacheProver := path.Join(peerCache, prover)
	if _, err := os.Stat(peerCacheProver); err != nil {
		if err := os.MkdirAll(peerCacheProver, 0755); err != nil {
			return fmt.Errorf("failed to create peer cache %v: %w", peerCacheProver, err)
		}
	}

	// Add newly received metadata if it does not yet exist
	for hash, data := range cached {
		f := path.Join(peerCacheProver, hash)
		if _, err := os.Stat(f); err == nil {
			continue
		}
		log.Tracef("Caching metadata file %v", f)
		err := os.WriteFile(f, data, 0644)
		if err != nil {
			return fmt.Errorf("failed to cache %v: %w", f, err)
		}
	}

	// Remove cache misses
	for _, miss := range misses {
		f := path.Join(peerCacheProver, miss)
		if _, err := os.Stat(f); err != nil {
			continue
		}
		log.Tracef("Removing cache miss file %v", f)
		err := os.Remove(f)
		if err != nil {
			log.Warnf("Failed to remove cache miss: %v", err)
			continue
		}
	}

	peerCacheMutex.Unlock()

	return nil
}
