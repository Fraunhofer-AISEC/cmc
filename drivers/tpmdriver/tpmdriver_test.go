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

package tpmdriver

import (
	"os"
	"path/filepath"
	"testing"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

func TestGetContainerArtifacts(t *testing.T) {

	ctrLog := `{"type":"PCR Eventlog","index":11,"events":[{"name":"ctr",` +
		`"hashes":[{"alg":"SHA-256",` +
		`"content":"df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"}]}]}`

	dir := t.TempDir()
	logfile := filepath.Join(dir, "container-measurements.json")
	if err := os.WriteFile(logfile, []byte(ctrLog), 0600); err != nil {
		t.Fatalf("failed to write container measurements: %v", err)
	}

	artifact, err := GetContainerArtifacts(logfile)
	if err != nil {
		t.Fatalf("GetContainerArtifacts() error = %v", err)
	}
	if artifact == nil {
		t.Fatal("GetContainerArtifacts() returned no artifact")
	}
	if artifact.Index != 11 {
		t.Errorf("GetContainerArtifacts() --GOT-- index = %v, --WANT-- 11", artifact.Index)
	}
	if len(artifact.Events) != 1 {
		t.Errorf("GetContainerArtifacts() --GOT-- %v events, --WANT-- 1", len(artifact.Events))
	}

	// Without container measurements, neither an artifact nor an error must be returned
	artifact, err = GetContainerArtifacts(filepath.Join(dir, "nonexistent.json"))
	if err != nil {
		t.Errorf("GetContainerArtifacts() error = %v, want nil", err)
	}
	if artifact != nil {
		t.Errorf("GetContainerArtifacts() --GOT-- %v, --WANT-- nil", artifact)
	}
}

func TestSetPcrSummaries(t *testing.T) {

	pcrs := map[int][]byte{1: {0x01}, 4: {0x04}}

	artifacts := []ar.Artifact{
		{Type: ar.TYPE_PCR_EVENTLOG, Index: 4},
		{Type: ar.TYPE_PCR_EVENTLOG, Index: 1},
	}

	if err := SetPcrSummaries(artifacts, pcrs); err != nil {
		t.Fatalf("SetPcrSummaries() error = %v", err)
	}
	if len(artifacts[0].Summary) != 1 || artifacts[0].Summary[0] != 0x04 {
		t.Errorf("SetPcrSummaries() --GOT-- PCR4 summary = %v, --WANT-- [4]", artifacts[0].Summary)
	}
	if len(artifacts[1].Summary) != 1 || artifacts[1].Summary[0] != 0x01 {
		t.Errorf("SetPcrSummaries() --GOT-- PCR1 summary = %v, --WANT-- [1]", artifacts[1].Summary)
	}

	// An artifact without a measured PCR value must be detected
	missing := []ar.Artifact{{Type: ar.TYPE_PCR_EVENTLOG, Index: 8}}
	if err := SetPcrSummaries(missing, pcrs); err == nil {
		t.Error("SetPcrSummaries() succeeded for artifact without measured PCR value")
	}
}

func TestSummaryArtifacts(t *testing.T) {

	artifacts := CreateSummaryArtifacts([]int{4, 1})

	if len(artifacts) != 2 {
		t.Fatalf("SummaryArtifacts() --GOT-- %v artifacts, --WANT-- 2", len(artifacts))
	}
	for i, want := range []int{1, 4} {
		if artifacts[i].Index != want {
			t.Errorf("SummaryArtifacts() --GOT-- index %v, --WANT-- %v", artifacts[i].Index, want)
		}
		if artifacts[i].Type != ar.TYPE_PCR_SUMMARY {
			t.Errorf("SummaryArtifacts() --GOT-- type %v, --WANT-- %v", artifacts[i].Type,
				ar.TYPE_PCR_SUMMARY)
		}
	}
}
