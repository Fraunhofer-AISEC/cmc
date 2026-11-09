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
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"

	"github.com/Fraunhofer-AISEC/cmc/internal/config"
)

// run loads the configuration the way the cmcd binary does.
func run(t *testing.T, args ...string) (*Config, error) {
	t.Helper()

	var c *Config
	var loadErr error

	cmd := &cli.Command{
		Name:  "cmcd",
		Flags: config.AllFlags(&Config{}),
		Action: func(_ context.Context, cmd *cli.Command) error {
			c, loadErr = config.New[Config](cmd)
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
		"allow-system-certs", "append-ebs", "cmc", "config", "ctr-driver", "ctr-log", "drivers",
		"endorsement", "enrollment", "exclude-pcrs", "hash-alg", "log-file", "log-level",
		"measurement-logs", "metadata", "omsp-format", "policy-engine", "policy-overwrite",
		"provision-auth", "provision-token", "root-cas", "storage", "tpm-key-alg", "use-omsp",
		"vmpl",
	}

	var got []string
	for _, f := range config.AllFlags(&Config{}) {
		got = append(got, f.Names()...)
	}
	slices.Sort(got)

	if !slices.Equal(got, want) {
		t.Errorf("flags changed:\n got %v\nwant %v", got, want)
	}
}

func TestRequiredOptions(t *testing.T) {
	_, err := run(t)
	if err == nil {
		t.Fatal("expected an error for a configuration without any option")
	}
	for _, want := range []string{"api.endpoint", "cmc.attestation.drivers",
		"cmc.metadata.locations", "trust.root_cas"} {
		if !strings.Contains(err.Error(), want+": required option is not set") {
			t.Errorf("error does not report %v as required:\n%v", want, err)
		}
	}
}

func TestInvalidValues(t *testing.T) {
	base := []string{
		"--drivers", "sw", "--metadata", "file://m", "--root-cas", "ca.pem",
		"--cmc", "socket://localhost:9955",
	}

	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"valid", nil, ""},
		{"api", []string{"--cmc", "carrier-pigeon://localhost"}, `API "carrier-pigeon" is not implemented`},
		{"driver", []string{"--drivers", "hal9000"}, `"hal9000" is not one of`},
		{"hashAlg", []string{"--hash-alg", "SHA256"}, `"SHA256" is not one of`},
		{"endorsement", []string{"--endorsement", "est"}, "cmc.provisioning.endorsement: est endorsement requires an address"},
		{"enrollment", []string{"--enrollment", "carrier-pigeon"}, "cmc.provisioning.enrollment: unknown mode"},
		{"container driver", []string{"--ctr-driver", "tpm"}, `cmc.attestation.containers.driver: "tpm" is not in cmc.attestation.drivers`},
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
