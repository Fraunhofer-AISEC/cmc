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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	log "github.com/sirupsen/logrus"
)

type MetadataInfo struct {
	Id      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Created string `json:"created"`
}

type MetadataFull struct {
	Info   MetadataInfo
	Format string
	Raw    []byte
	parsed *ar.Metadata
}

var (
	RegexHashCheck      = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	RegexNameCheck      = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	MetadataTypeAliases = map[string]string{
		"manifest": ar.TYPE_MANIFEST,
		"image":    ar.TYPE_IMAGE_DESCRIPTION,
		"company":  ar.TYPE_COMPANY_DESCRIPTION,
	}
)

func IsSupportedMetadataType(kind string) bool {
	// all standalone metadata types are supported
	return (kind == ar.TYPE_MANIFEST || kind == ar.TYPE_IMAGE_DESCRIPTION || kind == ar.TYPE_COMPANY_DESCRIPTION)
}

func ResolveMetadataType(kind string) (string, bool) {
	if IsSupportedMetadataType(kind) {
		return kind, true
	}
	if resolved, ok := MetadataTypeAliases[strings.ToLower(kind)]; ok {
		return resolved, true
	}
	return "", false
}

func ParseMetadata(raw []byte, cas []*x509.Certificate) (*MetadataFull, error) {
	// detect the serialization of the data
	serializer, err := ar.DetectSerialization(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to detect serialization: %w", err)
	}
	log.Tracef("Detected %v serialization", serializer.String())

	// check if ca's were provided and use them to verify the payload (otherwise just assume it to be valid)
	var payload []byte
	if len(cas) > 0 {
		if res, data, ok := serializer.Verify(raw, cas); !ok {
			// collect all relevant error information
			results, parts := []ar.Result{res.Summary}, make([]string, 0)
			for _, sig := range res.SignatureCheck {
				results = append(results, sig.CertChainCheck, sig.SignCheck)
			}

			// concat all error codes and details into an error description
			for _, r := range results {
				for _, code := range r.ErrorCodes {
					parts = append(parts, code.String())
				}
				if r.Details != "" {
					parts = append(parts, r.Details)
				}
			}
			if len(parts) == 0 {
				parts = append(parts, "unknown error")
			}
			return nil, fmt.Errorf("failed to verify signature: %v", strings.Join(parts, ", "))
		} else {
			payload = data
		}
	} else {
		payload, err = serializer.GetPayload(raw)
		if err != nil {
			return nil, fmt.Errorf("failed to extract payload: %w", err)
		}
	}

	// unpack the metadata structure using the corresponding serializer
	meta := &ar.Metadata{}
	if err := serializer.Unmarshal(payload, meta); err != nil {
		return nil, fmt.Errorf("failed to unpack metadata: %w", err)
	}

	// validate the integrity and consistency of the data
	if !IsSupportedMetadataType(meta.Type) {
		return nil, fmt.Errorf("unsupported metadata type (%v)", meta.Type)
	}
	if !RegexNameCheck.MatchString(meta.Name) {
		return nil, fmt.Errorf("%v has malformed name (%v)", meta.Type, meta.Name)
	}
	if _, err := time.Parse(time.RFC3339, meta.Version); err != nil {
		return nil, fmt.Errorf("%v %v has malformed version (%v): %w", meta.Type, meta.Name, meta.Version, err)
	}

	// compute the id over the data (and as sanity-check, validate the regex)
	digest := sha256.Sum256(raw)
	id := strings.ToLower(hex.EncodeToString(digest[:]))
	if !RegexHashCheck.MatchString(id) {
		return nil, fmt.Errorf("%v %v has malformed id (%v)", meta.Type, meta.Name, id)
	}

	// assemble the new parsed metadata structure (leave creation time empty, will be populated by caller)
	entry := &MetadataFull{
		Info: MetadataInfo{
			Id:      id,
			Type:    meta.Type,
			Name:    meta.Name,
			Version: meta.Version,
			Created: "",
		},
		Format: strings.ToLower(serializer.String()),
		Raw:    raw,
		parsed: meta,
	}
	log.Debugf("Parsed %v %v (id %v; version %v)", entry.Info.Type, entry.Info.Name, entry.Info.Id, entry.Info.Version)
	return entry, nil
}
func LoadMetadata(entry *DatabaseEntry) (*MetadataFull, error) {
	// parse and unpack the database metadata
	if entry == nil {
		return nil, nil
	}
	full, err := ParseMetadata(entry.Raw, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse stored metadata (id %v): %w", entry.Id, err)
	}

	// validate the consistency of the parsed data
	if full.Info.Id != entry.Id || full.Info.Type != entry.Type || full.Info.Name != entry.Name || full.Info.Version != entry.Version {
		return nil, fmt.Errorf("stored metadata (id %v) is inconsistent with its raw data (id %v | %v %v %v)",
			entry.Id, full.Info.Id, full.Info.Type, full.Info.Name, full.Info.Version)
	}
	full.Info.Created = entry.Created
	return full, nil
}
func LoadMetadataInfo(entry *DatabaseInfo) MetadataInfo {
	return MetadataInfo{
		Id:      entry.Id,
		Type:    entry.Type,
		Name:    entry.Name,
		Version: entry.Version,
		Created: entry.Created,
	}
}
func StoreMetadata(entry *MetadataFull) (*DatabaseEntry, error) {
	versionTime, err := time.Parse(time.RFC3339, entry.Info.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to parse version time: %w", err)
	}
	return &DatabaseEntry{
		DatabaseInfo: DatabaseInfo{
			Id:          entry.Info.Id,
			Type:        entry.Info.Type,
			Name:        entry.Info.Name,
			Version:     entry.Info.Version,
			VersionTime: versionTime.UnixNano(),
			Created:     entry.Info.Created,
		},
		Raw: entry.Raw,
	}, nil
}

func ReferenceHashes(entry *MetadataFull) []DatabaseHash {
	if entry.Info.Type != ar.TYPE_MANIFEST || entry.parsed.Sbom == nil {
		return nil
	}
	seen, hashes := make(map[DatabaseHash]bool), make([]DatabaseHash, 0)

	// collect all of the hashes over the components of this manifest
	for _, component := range entry.parsed.Sbom.Components {
		for _, h := range component.Hashes {
			if len(h.Content) == 0 {
				continue
			}
			hash := DatabaseHash{Algorithm: strings.ToLower(h.Alg), Hash: strings.ToLower(hex.EncodeToString(h.Content))}
			if !seen[hash] {
				seen[hash] = true
				hashes = append(hashes, hash)
			}
		}
	}
	return hashes
}
func ReferenceManifests(entry *MetadataFull) []string {
	if entry.Info.Type != ar.TYPE_IMAGE_DESCRIPTION {
		return nil
	}
	seen, names := make(map[string]bool), make([]string, 0, len(entry.parsed.Descriptions))

	// collect all of the manifests referenced
	for _, desc := range entry.parsed.Descriptions {
		if desc.Manifest != "" && !seen[desc.Manifest] {
			seen[desc.Manifest] = true
			names = append(names, desc.Manifest)
		}
	}
	return names
}

type MetadataNameIdentifier struct {
	Name string
	Type string
}

type MetadataResolver struct {
	processed map[string]bool
	loaded    []*MetadataFull
	Open      []MetadataNameIdentifier
	Entries   map[string]*MetadataFull
}

func NewMetadataResolver() *MetadataResolver {
	return &MetadataResolver{
		Entries:   make(map[string]*MetadataFull),
		processed: make(map[string]bool),
	}
}

func (s *MetadataResolver) Continue() bool {
	s.Open = s.Open[:0]

	// iterate over the loaded entries and update the resolver state accordingly
	for _, loaded := range s.loaded {
		// insert the loaded entry into the overall entries list (if its already inside, can be skipped)
		if _, ok := s.Entries[loaded.Info.Id]; ok {
			continue
		}
		s.Entries[loaded.Info.Id] = loaded

		// add the manifest itself to the list of loaded manifests
		if loaded.Info.Type == ar.TYPE_MANIFEST {
			s.processed[loaded.Info.Name] = true
		}

		// extract the list of all relevant manifests
		var linkedManifests []string
		switch loaded.Info.Type {
		case ar.TYPE_MANIFEST:
			linkedManifests = append(linkedManifests, loaded.parsed.BaseLayers...)
		case ar.TYPE_IMAGE_DESCRIPTION:
			for _, desc := range loaded.parsed.Descriptions {
				if desc.Manifest != "" {
					linkedManifests = append(linkedManifests, desc.Manifest)
				}
			}
		}

		// add all of the linked manifests to the open list and mark them as loaded/being loaded
		for _, name := range linkedManifests {
			if !s.processed[name] {
				s.Open = append(s.Open, MetadataNameIdentifier{Name: name, Type: ar.TYPE_MANIFEST})
				s.processed[name] = true
			}
		}
	}

	// clear the loaded list to indicate they have all been processed and check if the end has been reached
	s.loaded = s.loaded[:0]
	return (len(s.Open) > 0)
}
func (s *MetadataResolver) Flush() {
	// write all loaded entries immediately to the loaded list without resolving anything recursively
	for _, loaded := range s.loaded {
		s.Entries[loaded.Info.Id] = loaded
	}
	s.loaded = s.loaded[:0]
}
func (s *MetadataResolver) AddLoaded(name, kind string, entry *MetadataFull) bool {
	// check if an entry was loaded and add it to the list of seen manifests to prevent it from being requested later on again
	if entry != nil {
		if entry.Info.Type == ar.TYPE_MANIFEST {
			s.processed[entry.Info.Name] = true
		}
		s.loaded = append(s.loaded, entry)
		return true
	}

	// for failed loads, check if this was a manifest and mark it as 'already seen', even if the load itself failed (to prevent re-requesting it)
	if kind == ar.TYPE_MANIFEST {
		s.processed[name] = true
	}
	return false
}
