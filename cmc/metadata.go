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

// Install github packages with "go get [url]"
import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	// local modules

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	est "github.com/Fraunhofer-AISEC/cmc/est/estclient"
	"github.com/fxamacker/cbor/v2"
)

func GetMetadata(paths []string, cache string) ([][]byte, ar.Serializer, error) {

	metadata := make([][]byte, 0)
	fails := 0

	// Iterate over all given paths, determine whether this is a file
	// system or remote location, and fetch metadata
	for _, p := range paths {
		log.Tracef("Retrieving metadata from %v", p)
		if strings.HasPrefix(p, "file://") {
			f := strings.TrimPrefix(p, "file://")
			data, err := loadMetadata(f)
			if err != nil {
				log.Warnf("failed to read %v: %v", f, err)
				fails++
				continue
			}
			metadata = append(metadata, data...)
		} else {
			data, err := est.FetchMetadata(p)
			if err != nil {
				log.Warnf("failed to fetch %v: %v", p, err)
				fails++
				continue
			}
			metadata = append(metadata, data...)
		}
	}
	log.Tracef("Successfully retrieved metadata from %v of %v locations (%v failed)",
		len(paths)-fails, len(paths), fails)

	// In case of errors, load cached metadata if cache is available
	if fails > 0 {
		if cache != "" {
			log.Tracef("Additionally loading cached metadata from %v", cache)
			data, err := loadMetadata(cache)
			if err != nil {
				log.Warnf("failed to read cache %v: %v", cache, err)
			} else {
				metadata = append(metadata, data...)
			}
		} else {
			log.Trace("No cache available. Do not load additional metadata")
		}
	}

	// Filter metadata: remove any duplicates through always choosing the
	// newest version of duplicate metadata
	metadata, s, err := filterMetadata(metadata)
	if err != nil {
		return nil, s, fmt.Errorf("failed to filter metadata: %v", err)
	}

	// Cache metadata if cache is available
	if cache != "" {
		if err := cacheMetadata(metadata, cache); err != nil {
			log.Warnf("Failed to cache metadata to %v", cache)
		}
	}

	log.Debugf("Loaded %v metadata objects", len(metadata))

	return metadata, s, nil
}

// loadMetadata loads the metadata (manifests and descriptions) from the file system
func loadMetadata(dir string) ([][]byte, error) {

	metadata := make([][]byte, 0)

	// Check if file or directory
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	// If it is a file, read it directly
	if !info.IsDir() {
		data, err := os.ReadFile(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to get file: %w", err)
		}
		metadata = append(metadata, data)
		return metadata, nil
	}

	// If it is a directory, get files and contents
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata folder: %v", err)
	}

	// Retrieve the metadata files
	log.Tracef("Parsing %v metadata files in %v", len(files), dir)
	for i := 0; i < len(files); i++ {
		file := path.Join(dir, files[i].Name())
		if fileInfo, err := os.Stat(file); err == nil {
			if fileInfo.IsDir() {
				log.Tracef("Skipping directory %v", file)
				continue
			}
		}
		log.Tracef("Reading file %v", file)
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %v: %v", file, err)
		}
		metadata = append(metadata, data)
	}
	return metadata, nil
}

// cacheMetadata stores the metadata locally into the specified file system folder
// It uses the file's sha256 hash as the filename
func cacheMetadata(data [][]byte, localPath string) error {
	if _, err := os.Stat(localPath); err != nil {
		if err := os.Mkdir(localPath, 0755); err != nil {
			return fmt.Errorf("failed to create directory for local data '%v': %v", localPath, err)
		}
	}
	for _, d := range data {
		digest := sha256.Sum256(d)
		filename := path.Join(localPath, hex.EncodeToString(digest[:]))
		log.Debug("Caching metadata object: ", filename)
		err := os.WriteFile(filename, d, 0644)
		if err != nil {
			return fmt.Errorf("failed to write file: %v", err)
		}
	}
	return nil
}

func filterMetadata(inlist [][]byte) ([][]byte, ar.Serializer, error) {
	log.Tracef("Filtering %v meta-data objects..", len(inlist))

	outlist := make([][]byte, 0)
	var s ar.Serializer
	foundJson := false
	foundCbor := false

	for _, elem := range inlist {

		// Get serialization format
		if json.Valid(elem) {
			log.Trace("Detected JSON serialization")
			s = ar.JsonSerializer{}
			foundJson = true
		} else if err := cbor.Valid(elem); err == nil {
			log.Trace("Detected CBOR serialization")
			s = ar.CborSerializer{}
			foundCbor = true
		} else {
			return nil, s, errors.New("failed to detect serialization (only JSON and CBOR are supported)")
		}

		// Extract plain payload (i.e. the manifest/description itself)
		data, err := s.GetPayload(elem)
		if err != nil {
			log.Warnf("Failed to parse metadata object: %v", err)
			continue
		}

		in := new(ar.MetaInfo)
		err = s.Unmarshal(data, in)
		if err != nil {
			log.Warnf("Failed to unmarshal data from metadata object: %v", err)
			continue
		}

		// Verify that metadata has a version in RFC3339 format
		_, err = time.Parse(time.RFC3339, in.Version)
		if err != nil {
			log.Warnf("metadata %v has incorrect version %v (must be RFC3339 format): %v",
				in.Name, in.Version, err)
			continue
		}

		// Iterate through already present metadata and filter
		done := false
		for i := 0; i < len(outlist); i++ {

			// Get info about item in outlist
			data, err := s.GetPayload(outlist[i])
			if err != nil {
				return nil, s, fmt.Errorf("failed to parse metadata object %v: %v", i, err)
			}
			out := new(ar.MetaInfo)
			err = s.Unmarshal(data, out)
			if err != nil {
				return nil, s, fmt.Errorf("internal error: failed to unmarshal result: %v", err)
			}

			// Result contains already metadata of this type
			if in.Type == out.Type {
				// Metadata which can be present multiple times must be checked by its
				// unique name
				if in.Type == "App Manifest" || in.Type == "App Description" {
					if in.Name == out.Name {
						// Metadata is already present, compare versions
						log.Tracef("Checking if %v: %v is newer then %v:%v", in.Name, in.Version, out.Name, out.Version)
						newer, err := isNewer(in.Version, out.Version)
						if err != nil {
							return nil, s, fmt.Errorf("failed to compare metadata versions: %v", err)
						}
						if newer {
							// Replace item with more recent item
							log.Tracef("Replacing %v: %v with %v:%v", out.Name, out.Version, in.Name, in.Version)
							outlist[i] = elem
						} else {
							log.Tracef("Discarding %v: %v", in.Name, in.Version)
						}
						done = true
						break
					}
				} else {
					// Metadata is already present, compare versions
					log.Tracef("Checking if %v: %v is newer then %v:%v", in.Name, in.Version, out.Name, out.Version)
					newer, err := isNewer(in.Version, out.Version)
					if err != nil {
						return nil, s, fmt.Errorf("failed to compare metadata versions: %v", err)
					}
					if newer {
						// Replace item with more recent item
						log.Tracef("Replacing %v: %v with %v:%v", out.Name, out.Version, in.Name, in.Version)
						outlist[i] = elem
					} else {
						log.Tracef("Discarding %v: %v", in.Name, in.Version)
					}
					done = true
					break
				}
			}
		}

		// If not already done, add new item
		if !done {
			log.Tracef("Adding: %v %v, Version: %v", in.Type, in.Name, in.Version)
			outlist = append(outlist, elem)
		}
	}

	if foundJson && foundCbor {
		return nil, s, fmt.Errorf("found both JSON and CBOR metadata. Mixed metadata is not supported")
	}

	log.Tracef("Returning filtered lists with %v elements", len(outlist))

	return outlist, s, nil
}

func isNewer(t, ref string) (bool, error) {

	checktime, err := time.Parse(time.RFC3339, t)
	if err != nil {
		return false, fmt.Errorf("failed to parse time to be checked %v: %v", t, err)
	}

	reftime, err := time.Parse(time.RFC3339, ref)
	if err != nil {
		return false, fmt.Errorf("failed to parse reference time %v: %v", ref, err)
	}

	return checktime.After(reftime), nil
}
