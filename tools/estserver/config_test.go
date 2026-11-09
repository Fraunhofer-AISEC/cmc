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

// run loads the configuration the way the estserver binary does.
func run(t *testing.T, args ...string) (*Config, error) {
	t.Helper()

	var c *Config
	var loadErr error

	cmd := &cli.Command{
		Name:  "estserver",
		Flags: config.AllFlags(&Config{}),
		Action: func(_ context.Context, cmd *cli.Command) error {
			c, loadErr = config.New[Config](cmd)
			return nil
		},
	}
	if err := cmd.Run(context.Background(), append([]string{"estserver"}, args...)); err != nil {
		t.Fatalf("failed to run command: %v", err)
	}

	return c, loadErr
}

// TestExampleConfigs checks that every EST server configuration shipped with
// the repository still loads and validates.
func TestExampleConfigs(t *testing.T) {

	files, err := filepath.Glob("../../example-setup/*/est-server*.toml")
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

func TestRequiredOptions(t *testing.T) {
	_, err := run(t)
	if err == nil {
		t.Fatal("expected an error for a configuration without any option")
	}
	for _, want := range []string{"est.ca_key", "est.ca_chain", "est.tls_key", "est.tls_ca_chain"} {
		if !strings.Contains(err.Error(), want+": required option is not set") {
			t.Errorf("error does not report %v as required:\n%v", want, err)
		}
	}
}

func TestIncompleteOmsp(t *testing.T) {
	c, err := run(t,
		"--est-ca-key", "k", "--est-ca-chain", "c", "--tls-key", "k", "--tls-ca-chain", "c",
		"--omsp-url", "https://localhost:9000/omsp")
	if err == nil {
		t.Fatalf("expected an error for an incomplete OMSP configuration, got %+v", c)
	}
	for _, want := range []string{"omsp.key", "omsp.folder", "omsp.ca_chain"} {
		if !strings.Contains(err.Error(), want+": incomplete OMSP configuration") {
			t.Errorf("error does not report %v as missing:\n%v", want, err)
		}
	}
}

func TestCertValidity(t *testing.T) {
	base := []string{
		"--est-ca-key", "k", "--est-ca-chain", "c", "--tls-key", "k", "--tls-ca-chain", "c",
	}

	for _, tt := range []struct {
		value string
		want  string
	}{
		{"4320h", ""},
		{"nonsense", "is not a duration"},
		{"-1h", "must be positive"},
		{"0s", "must be positive"},
	} {
		t.Run(tt.value, func(t *testing.T) {
			_, err := run(t, append(slices.Clone(base), "--cert-validity", tt.value)...)
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
