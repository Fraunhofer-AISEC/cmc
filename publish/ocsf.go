// Copyright (c) 2025 Fraunhofer AISEC
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

package publish

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/google/uuid"
)

// DetectionFindings represents a minimal OCSF Detection Finding [2004]
type DetectionFinding struct {
	ActionId      int          `json:"action_id"`
	ActivityID    int          `json:"activity_id"`
	CategoryUID   int          `json:"category_uid"`
	ClassUID      int          `json:"class_uid"`
	TypeUID       int          `json:"type_uid"`
	ConfidenceID  int          `json:"confidence_id,omitempty"`
	DispositionID int          `json:"disposition_id,omitempty"`
	StatusID      int          `json:"status_id,omitempty"`
	IsAlert       bool         `json:"is_alert"`
	SeverityID    int          `json:"severity_id"`
	Time          string       `json:"time"`
	Message       string       `json:"message,omitempty"`
	FindingInfo   *Finding     `json:"finding_info"`
	Evidences     []Evidence   `json:"evidences"`
	Metadata      Metadata     `json:"metadata"`
	RawData       []byte       `json:"raw_data,omitempty"`
	RawDataHash   *Fingerprint `json:"raw_data_hash,omitempty"`
	RawDataSize   int          `json:"raw_data_size,omitempty"`
}

// Fingerprint represents the OCSF Fingerprint object.
type Fingerprint struct {
	Algorithm   string `json:"algorithm,omitempty"`
	AlgorithmID int    `json:"algorithm_id"`
	Value       string `json:"value"`
}

// Finding represents the OCSF Finding Information object
type Finding struct {
	UID   string `json:"uid"`
	Title string `json:"title"`
	Desc  string `json:"desc"`
}

// Evidence represents the OCSF Evidence Artifact object
type Evidence struct {
	File File `json:"file"`
}

// File represents the OCSF File [24] object
type File struct {
	Hashes       []Fingerprint `json:"hashes"`
	Path         string        `json:"path,omitempty"`
	Size         int           `json:"size,omitempty"`
	AccessedTime string        `json:"accessed_time,omitempty"`
	CreatedTime  string        `json:"created_time,omitempty"`
	ModifiedTime string        `json:"modified_time,omitempty"`
	Attributes   uint32        `json:"attributes,omitempty"`
	Extension    string        `json:"ext,omitempty"`
	ParentFolder string        `json:"parent_folder,omitempty"`
	Accessor     *User         `json:"accessor,omitempty"`
	Creator      *User         `json:"creator,omitempty"`
	Modifier     *User         `json:"modifier,omitempty"`
}

// User represents the OCSF User object
type User struct {
	Name string `json:"name,omitempty"`
}

// Metadata represents the OCSF Metadata object
type Metadata struct {
	Version  string   `json:"version"`
	Product  Product  `json:"product"`
	Profiles []string `json:"profiles,omitempty"`
}

// Product represents the OCSF Product object
type Product struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	VendorName string `json:"vendor_name"`
}

func CreateDetectionFindings(result *ar.AttestationResult) []*DetectionFinding {
	findings := make([]*DetectionFinding, 0)
	for _, measurement := range result.Measurements {
		for _, digest := range measurement.Artifacts {
			if digest.Success || !digest.Launched {
				continue // nothing to do
			}
			finding := CreateDetectionFinding(digest, result.Created)
			findings = append(findings, finding)
		}
	}
	return findings
}

func CreateDetectionFinding(dr ar.DigestResult, t string) *DetectionFinding {

	message := "Unauthorized software launch detected"

	description := fmt.Sprintf("Measurement Index: %v", dr.Index)
	if dr.Description != "" {
		description += ", Description: " + dr.Description
	}
	if dr.EventData != nil && dr.EventData.StringContent != "" {
		description += ", Event Data: " + dr.EventData.StringContent
	}

	var alg string
	switch len(dr.Digest) {
	case 2 * 32:
		alg = "sha256"
	case 2 * 48:
		alg = "sha384"
	case 2 * 64:
		alg = "sha512"
	default:
		alg = "other"
	}
	algId, _ := AlgorithmNameToID(alg)

	f := File{
		Hashes: []Fingerprint{
			{
				Algorithm:   alg,
				AlgorithmID: algId,
				Value:       dr.Digest,
			},
		},
	}

	// Description often contains paths to binaries. If so, try to get raw data
	var raw []byte
	fileExists := false
	if info, err := os.Stat(dr.Description); err == nil {
		fileExists = true
		filePath := dr.Description
		raw, _ = os.ReadFile(filePath)

		f.Path = filePath
		f.ParentFolder = filepath.Ext(filePath)
		f.Extension = filepath.Ext(filePath)
		f.ModifiedTime = info.ModTime().Format(time.RFC3339)
		f.Attributes = uint32(info.Mode().Perm())
		f.Size = len(raw)
	}

	finding := &DetectionFinding{
		ActionId:      3,      // Observed
		ActivityID:    1,      // Create
		CategoryUID:   2,      // Detection Finding
		ClassUID:      2004,   // Detection Finding
		TypeUID:       200401, // Detection Finding
		ConfidenceID:  3,      // High
		DispositionID: 19,     // Alert
		StatusID:      1,      // New
		IsAlert:       true,   // Raise alert
		SeverityID:    4,      // High
		Time:          t,      // AR creation time
		Message:       message,
		FindingInfo: &Finding{
			UID:   uuid.New().String(),
			Title: fmt.Sprintf("Unauthorized software launch: %v", dr.SubType),
			Desc:  description,
		},
		Evidences: []Evidence{
			{
				File: f,
			},
		},
		RawData:     raw,
		RawDataSize: len(raw),
		Metadata: Metadata{
			Version: "1.8.0",
			Product: Product{
				Name:       "Attestation Framework",
				Version:    internal.GetVersion(),
				VendorName: "Vendor",
			},
			Profiles: []string{"security_control"},
		},
	}

	if fileExists {
		finding.RawData = raw
		finding.RawDataSize = len(raw)
	}

	return finding
}

var algoNameToOCSF = map[string]int{
	"md5":    1,
	"sha1":   2,
	"sha256": 3,
	"sha512": 4,
	"sha224": 8,
	"sha384": 9,
	"other":  99,
}

func AlgorithmNameToID(name string) (int, bool) {
	norm := strings.ToLower(strings.TrimSpace(name))
	id, ok := algoNameToOCSF[norm]
	return id, ok
}
