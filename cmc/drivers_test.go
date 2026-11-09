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

package cmc

import (
	"slices"
	"testing"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	drv "github.com/Fraunhofer-AISEC/cmc/drivers"
)

type fakeDriver struct{}

func (fakeDriver) Init(*drv.DriverConfig) error              { return nil }
func (fakeDriver) GetEvidence([]byte) ([]ar.Evidence, error) { return nil, nil }
func (fakeDriver) GetCollateral() ([]ar.Collateral, error)   { return nil, nil }
func (fakeDriver) Name() string                              { return "fake" }
func (fakeDriver) UpdateCerts() error                        { return nil }

type fakeDetector struct {
	fakeDriver
	present bool
}

func (d fakeDetector) Detect() bool { return d.present }

func TestResolveDrivers(t *testing.T) {
	orig := drivers
	t.Cleanup(func() { drivers = orig })

	for _, tt := range []struct {
		name    string
		drivers map[string]drv.Driver
		in      []string
		want    []string
		wantErr bool
	}{
		{
			name:    "explicit",
			drivers: map[string]drv.Driver{"tpm": fakeDetector{present: false}, "sw": fakeDriver{}},
			in:      []string{"tpm", "sw"},
			want:    []string{"tpm", "sw"},
		},
		{
			name: "auto selects present detectors in sorted order",
			drivers: map[string]drv.Driver{
				"tpm": fakeDetector{present: true},
				"snp": fakeDetector{present: true},
				"tdx": fakeDetector{present: false},
				"sw":  fakeDriver{},
			},
			in:   []string{"auto"},
			want: []string{"snp", "tpm"},
		},
		{
			name:    "auto with explicit driver",
			drivers: map[string]drv.Driver{"tpm": fakeDetector{present: true}, "sw": fakeDriver{}},
			in:      []string{"auto", "sw"},
			want:    []string{"tpm", "sw"},
		},
		{
			name:    "duplicates removed",
			drivers: map[string]drv.Driver{"tpm": fakeDetector{present: true}},
			in:      []string{"tpm", "auto", "TPM"},
			want:    []string{"tpm"},
		},
		{
			name:    "auto detects nothing",
			drivers: map[string]drv.Driver{"tpm": fakeDetector{present: false}, "sw": fakeDriver{}},
			in:      []string{"auto"},
			wantErr: true,
		},
		{
			name:    "unknown driver",
			drivers: map[string]drv.Driver{"sw": fakeDriver{}},
			in:      []string{"hal9000"},
			wantErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			drivers = tt.drivers
			got, err := resolveDrivers(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !slices.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
