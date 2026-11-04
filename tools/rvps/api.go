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

const ApiVersion = "0.1.0"

type QueryNameEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type QueryRequest struct {
	Version string           `json:"version"`
	Ids     []string         `json:"ids,omitempty"`
	Names   []QueryNameEntry `json:"names,omitempty"`
	Resolve bool             `json:"resolve,omitempty"`
}

type QueryMetadataEntry struct {
	Data    []byte `json:"data"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Version string `json:"version"`
}

type QueryResponse struct {
	Version      string                        `json:"version"`
	Metadata     map[string]QueryMetadataEntry `json:"metadata"`
	UnknownIds   []string                      `json:"unknownIds,omitempty"`
	UnknownNames []QueryNameEntry              `json:"unknownNames,omitempty"`
}

type ResolveMeasurement struct {
	Algorithm string `json:"algorithm"`
	Hash      string `json:"hash"`
}

type ResolveRequest struct {
	Version      string               `json:"version"`
	Measurements []ResolveMeasurement `json:"measurements,omitempty"`
	Resolve      bool                 `json:"resolve,omitempty"`
}

type ResolveManifestEntry struct {
	Data    []byte `json:"data"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Version string `json:"version"`
}

type ResolveNameEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type ResolveMapping struct {
	ResolveMeasurement
	ManifestId string `json:"manifest"`
}

type ResolveResponse struct {
	Version             string                          `json:"version"`
	ImageDescriptions   []string                        `json:"imageDescriptions,omitempty"`
	Metadata            map[string]ResolveManifestEntry `json:"metadata"`
	Mapping             []ResolveMapping                `json:"mapping"`
	UnknownMeasurements []ResolveMeasurement            `json:"unknownMeasurements,omitempty"`
	UnknownNames        []ResolveNameEntry              `json:"unknownNames,omitempty"`
}
