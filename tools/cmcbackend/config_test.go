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

// run loads the configuration the way the cmcbackend binary does.
func run(t *testing.T, args ...string) (*Config, error) {
	t.Helper()

	var c *Config
	var loadErr error

	cmd := &cli.Command{
		Name:  "cmcbackend",
		Flags: config.AllFlags(&Config{}),
		Action: func(_ context.Context, cmd *cli.Command) error {
			c, loadErr = config.New[Config](cmd)
			return nil
		},
	}
	if err := cmd.Run(context.Background(), append([]string{"cmcbackend"}, args...)); err != nil {
		t.Fatalf("failed to run command: %v", err)
	}

	return c, loadErr
}

// write stores a config file in a temporary directory and returns its path.
func write(t *testing.T, body string) string {
	t.Helper()

	file := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(file, []byte(body), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	return file
}

// TestExampleConfigs checks that every backend configuration shipped with the
// repository still loads and validates.
func TestExampleConfigs(t *testing.T) {

	files, err := filepath.Glob("../../example-setup/*/cmcbackend-conf*.json")
	if err != nil {
		t.Fatalf("failed to list example configs: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("found no example configs, has the example setup moved?")
	}

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			if _, err := run(t, "--config", file); err != nil {
				t.Errorf("%v does not validate: %v", file, err)
			}
		})
	}
}

// TestFlagNames pins the command line interface.
func TestFlagNames(t *testing.T) {

	want := []string{
		"addr", "config", "db", "debug", "log-file", "log-level", "max-rows",
		"max-rows-per-prover", "token",
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

func TestDefaults(t *testing.T) {

	c, err := run(t)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c.resolve()

	switch {
	case c.Http.Address != "localhost:8080":
		t.Errorf("http.address = %q", c.Http.Address)
	case c.Database.MaxRows != 400:
		t.Errorf("database.maxRows = %v", c.Database.MaxRows)
	case c.Database.MaxRowsPerProver != 20:
		t.Errorf("database.maxRowsPerProver = %v", c.Database.MaxRowsPerProver)
	}

	// Without a configured category, resolve invents a single default one
	if len(c.Categories.List) != 1 || c.Categories.Default != c.Categories.List[0].Id {
		t.Errorf("categories = %+v, default %q", c.Categories.List, c.Categories.Default)
	}
}

// TestCategories covers the record list, which is the one option that can
// only come from a config file.
func TestCategories(t *testing.T) {

	for _, tt := range []struct {
		name string
		body string
		want string
	}{
		{"valid", `{"categories":{"default":"a","list":[{"id":"a","label":"A"},{"id":"b"}]}}`, ""},
		{"not url safe", `{"categories":{"list":[{"id":"a/b"}]}}`, "must be URL-safe"},
		{"duplicate", `{"categories":{"list":[{"id":"a"},{"id":"a"}]}}`, "duplicate category"},
		{"unknown default", `{"categories":{"default":"c","list":[{"id":"a"}]}}`,
			"is not one of the configured categories"},
		{"not a list", `{"categories":{"list":{"id":"a"}}}`, "cannot use"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, err := run(t, "--config", write(t, tt.body))
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.want != "" && err == nil:
				t.Errorf("expected an error containing %q", tt.want)
			case tt.want != "" && !strings.Contains(err.Error(), tt.want):
				t.Errorf("error %v does not contain %q", err, tt.want)
			case tt.want != "":
				return
			}

			// A label defaults to the id it belongs to
			c.resolve()
			if c.Categories.List[1].Label != "b" {
				t.Errorf("label of b = %q, want b", c.Categories.List[1].Label)
			}
		})
	}
}

// TestPathsResolveAgainstConfigFile checks that the database ends up next to
// the config file rather than next to the working directory.
func TestPathsResolveAgainstConfigFile(t *testing.T) {

	file := write(t, `{"database":{"path":"db/monitoring.db"}}`)

	c, err := run(t, "--config", file)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if want := filepath.Join(filepath.Dir(file), "db/monitoring.db"); c.Database.Path != want {
		t.Errorf("database.path = %q, want %q", c.Database.Path, want)
	}
}
