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

package server

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/rvps/store"
	log "github.com/sirupsen/logrus"
)

type MetadataBundle struct {
	Info   store.EntryInfo
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

func ParseMetadata(raw []byte, cas []*x509.Certificate) (*store.EntryInfo, error) {
	// compute the id over the data (the id of a metadata item is the digest of its entire signed blob)
	digest := sha256.Sum256(raw)
	id := hex.EncodeToString(digest[:])

	// verify the metadata matches the signature and unpack them
	meta, res := ar.ParseAndVerifyMetadataItem(id, raw, cas)
	if meta == nil || res.Summary.Status != ar.StatusSuccess {
		// collect all relevant error information
		results, parts := []ar.Result{res.Summary, res.ValidityCheck}, make([]string, 0)
		for _, sig := range res.SignatureCheck {
			results = append(results, sig.CertChainCheck, sig.SignCheck)
		}

		// concat all error codes and details into an error description
		add := func(part string) {
			if part != "" && !slices.Contains(parts, part) {
				parts = append(parts, part)
			}
		}
		for _, r := range results {
			for _, code := range r.ErrorCodes {
				add(code.String())
			}
			add(r.Details)
		}
		if meta != nil && meta.Validity == nil {
			add("missing validity information")
		}
		if len(parts) == 0 {
			parts = append(parts, "unknown error")
		}
		return nil, fmt.Errorf("failed to verify metadata: %v", strings.Join(parts, ", "))
	}

	// compute the signer identifier (the validated chains start with the
	// leaf certificate; all chains of a signature share the same leaf)
	var signer string
	if len(res.SignatureCheck) == 0 {
		return nil, fmt.Errorf("no signatures found for signer")
	} else if chains := res.SignatureCheck[0].Certs; len(chains) == 0 || len(chains[0]) == 0 {
		return nil, fmt.Errorf("no validated certificate chain found for signer")
	} else if block, _ := pem.Decode([]byte(chains[0][0].PublicKey)); block == nil {
		return nil, fmt.Errorf("failed to decode public key of signing certificate")
	} else {
		if len(res.SignatureCheck) > 1 {
			log.Warnf("Metadata has %v signatures, only the first one is tracked as signer", len(res.SignatureCheck))
		}
		digest := sha256.Sum256(block.Bytes)
		signer = hex.EncodeToString(digest[:])
	}

	// detect the serialization format of the blob (should not fail anymore, as the blob has already been verified)
	serializer, err := ar.DetectSerialization(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to detect serialization: %w", err)
	}

	// validate the integrity and consistency of the data
	var versionTime time.Time
	if !IsSupportedMetadataType(meta.Type) {
		return nil, fmt.Errorf("unsupported metadata type (%v)", meta.Type)
	}
	if !RegexNameCheck.MatchString(meta.Name) {
		return nil, fmt.Errorf("%v has malformed name (%v)", meta.Type, meta.Name)
	}
	if versionTime, err = time.Parse(time.RFC3339, meta.Version); err != nil {
		return nil, fmt.Errorf("%v %v has malformed version (%v): %w", meta.Type, meta.Name, meta.Version, err)
	}

	// assemble the new parsed metadata structure (leave creation time, and origin empty, will be populated by caller)
	entry := &store.EntryInfo{
		Id:          id,
		Type:        meta.Type,
		Name:        meta.Name,
		Version:     meta.Version,
		VersionTime: versionTime.UnixNano(),
		Signer:      signer,
		Format:      strings.ToLower(serializer.String()),
		Created:     "",
		Origin:      "",
	}
	log.Debugf("Parsed %v %v (id %v; version %v; signer %v)", entry.Type, entry.Name, entry.Id, entry.Version, entry.Signer)
	return entry, nil
}
func UnpackMetadata(entry *store.EntryInfo, raw []byte, parse bool) (*MetadataBundle, error) {
	// parse and unpack the stored metadata
	if entry == nil {
		return nil, nil
	}

	// check if the data dont need to be parsed
	if !parse {
		return &MetadataBundle{Info: *entry, Raw: raw}, nil
	}

	// detect the serialization of the data
	serializer, err := ar.DetectSerialization(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to detect serialization: %w", err)
	}
	log.Tracef("Detected %v serialization", serializer.String())

	// unpack the metadata structure using the corresponding serializer
	payload, err := serializer.GetPayload(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract payload: %w", err)
	}
	meta := &ar.Metadata{}
	if err := serializer.Unmarshal(payload, meta); err != nil {
		return nil, fmt.Errorf("failed to unpack metadata: %w", err)
	}

	// return the unpacked full information (no need to validate the state or
	// consistency against the parsed data as the data come from a trusted source)
	return &MetadataBundle{Info: *entry, Raw: raw, parsed: meta}, nil
}

type MetadataIdentifier struct {
	Name string
	Type string
}

type MetadataResolver struct {
	processed map[string]bool
	loaded    []*MetadataBundle
	Open      []MetadataIdentifier
	Entries   map[string]*MetadataBundle
}

func NewMetadataResolver() *MetadataResolver {
	return &MetadataResolver{
		Entries:   make(map[string]*MetadataBundle),
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
				s.Open = append(s.Open, MetadataIdentifier{Name: name, Type: ar.TYPE_MANIFEST})
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
func (s *MetadataResolver) AddLoaded(name, kind string, entry *MetadataBundle) bool {
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
