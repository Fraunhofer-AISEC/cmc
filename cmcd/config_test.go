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
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"

	"github.com/Fraunhofer-AISEC/cmc/internal/config"
)

// TestMain hides the config file of the user running the tests, which would
// otherwise be loaded whenever a test does not pass --config.
func TestMain(m *testing.M) {
	os.Setenv("XDG_CONFIG_HOME", "/nonexistent")
	os.Exit(m.Run())
}

// run loads the configuration the way the cmcd binary does.
func run(t *testing.T, args ...string) (*Config, error) {
	t.Helper()

	var c *Config
	var loadErr error

	cmd := &cli.Command{
		Name:  "cmcd",
		Flags: config.AllFlags(binaryName, &Config{}),
		Action: func(_ context.Context, cmd *cli.Command) error {
			c, loadErr = config.New[Config](cmd, binaryName)
			return nil
		},
	}
	if err := cmd.Run(context.Background(), append([]string{"cmcd"}, args...)); err != nil {
		t.Fatalf("failed to run command: %v", err)
	}

	return c, loadErr
}

// TestExampleConfigs checks that every cmcd configuration shipped with the
// repository still loads and validates.
func TestExampleConfigs(t *testing.T) {

	files, err := filepath.Glob("../example-setup/*/cmcd*.toml")
	if err != nil {
		t.Fatalf("failed to list example configs: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("found no example configs, has the example setup moved?")
	}

	for _, file := range files {
		t.Run(filepath.Base(filepath.Dir(file))+"/"+filepath.Base(file), func(t *testing.T) {
			if _, err := run(t, "--config", file); err != nil {
				t.Errorf("%v does not validate: %v", file, err)
			}
		})
	}
}

// TestFlagNames pins the command line interface, which the setup and test
// scripts in bin/ depend on and which the move to sectioned config files was
// not supposed to change.
func TestFlagNames(t *testing.T) {

	want := []string{
		"allow-system-certs", "append-ebs", "cmc", "config", "ctr-log", "ctr-trust-anchor", "drivers",
		"enrollment", "exclude-pcrs", "hash-alg", "log-file", "log-level",
		"measurement-logs", "metadata", "omsp-format", "policy-engine", "policy-overwrite",
		"provision-auth", "provision-token", "root-cas", "snp-endorsement", "storage",
		"tdx-endorsement", "tpm-endorsement", "tpm-key-alg", "use-omsp", "vmpl",
	}

	var got []string
	for _, f := range config.AllFlags(binaryName, &Config{}) {
		got = append(got, f.Names()...)
	}
	slices.Sort(got)

	if !slices.Equal(got, want) {
		t.Errorf("flags changed:\n got %v\nwant %v", got, want)
	}
}

// TestNoRequiredOptions checks that neither metadata nor drivers are required,
// as a prover may only send evidence and empty drivers run a verifier only.
func TestNoRequiredOptions(t *testing.T) {
	if _, err := run(t); err != nil {
		t.Errorf("unexpected error for a configuration without any option: %v", err)
	}

	c, err := run(t, "--drivers", "")
	if err != nil {
		t.Fatalf("unexpected error for a verifier-only configuration: %v", err)
	}
	if len(c.Cmc.Attestation.Drivers) != 0 {
		t.Errorf("drivers = %v, want none", c.Cmc.Attestation.Drivers)
	}
}

func TestDefaultDrivers(t *testing.T) {
	c, err := run(t, "--metadata", "file://m")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Equal(c.Cmc.Attestation.Drivers, []string{"auto"}) {
		t.Errorf("drivers = %v, want [auto]", c.Cmc.Attestation.Drivers)
	}
}

func TestInvalidValues(t *testing.T) {
	base := []string{"--drivers", "sw", "--metadata", "file://m"}

	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"valid", nil, ""},
		{"api", []string{"--cmc", "carrier-pigeon://localhost"}, `API "carrier-pigeon" is not implemented`},
		{"driver", []string{"--drivers", "hal9000"}, `"hal9000" is not one of`},
		{"hashAlg", []string{"--hash-alg", "SHA256"}, `"SHA256" is not one of`},
		{"tpm endorsement", []string{"--tpm-endorsement", "est"}, "cmc.attestation.tpm.endorsement: est requires an address"},
		{"snp endorsement", []string{"--snp-endorsement", "est:https://localhost"}, `cmc.attestation.snp.endorsement: unknown mode "est"`},
		{"tdx endorsement", []string{"--tdx-endorsement", "host"}, `cmc.attestation.tdx.endorsement: unknown mode "host"`},
		{"tpm endorsement self", []string{"--drivers", "tpm", "--tpm-endorsement", "self"}, "cmc.attestation.tpm.endorsement: self requires the snp or tdx driver"},
		{"tpm endorsement self snp", []string{"--drivers", "tpm,snp", "--tpm-endorsement", "self"}, ""},
		{"tpm endorsement self auto", []string{"--drivers", "auto", "--tpm-endorsement", "self"}, ""},
		{"enrollment", []string{"--enrollment", "carrier-pigeon"}, "cmc.provisioning.enrollment: unknown mode"},
		{"container trust anchor", []string{"--ctr-trust-anchor", "tpm"}, `cmc.attestation.containers.trust_anchor: "tpm" requires the tpm driver in cmc.attestation.drivers`},
		{"container trust anchor auto", []string{"--drivers", "auto", "--ctr-trust-anchor", "tpm"}, ""},
		{"container trust anchor auto sw", []string{"--drivers", "auto", "--ctr-trust-anchor", "sw"}, `"sw" requires the sw driver`},
		{"auto with sw", []string{"--drivers", "auto,sw", "--ctr-trust-anchor", "sw"}, ""},
		{"container trust anchor enum", []string{"--ctr-trust-anchor", "snp"}, `"snp" is not one of`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := run(t, append(slices.Clone(base), tt.args...)...)
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.want != "" && err == nil:
				t.Errorf("expected an error containing %q", tt.want)
			case tt.want != "" && !strings.Contains(err.Error(), tt.want):
				t.Errorf("error %v does not contain %q", err, tt.want)
			}
		})
	}
}
