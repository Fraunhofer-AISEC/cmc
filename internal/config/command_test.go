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

package config

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"
)

// configDir points the config directory to a fresh temporary directory, which
// does not exist yet, and returns it.
func configDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cfg")
	orig := baseDirs
	baseDirs = func() Dirs { return Dirs{Config: dir, Data: "/data", Run: "/run"} }
	t.Cleanup(func() { baseDirs = orig })
	return dir
}

// runConfig runs the config command of a binary named test with the
// configuration type T, and returns what it wrote to stdout.
func runConfig[T any](t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := &cli.Command{
		Name:      "test",
		Flags:     AllFlags("test", new(T)),
		Commands:  []*cli.Command{Command[T]("test", nil)},
		Writer:    &out,
		ErrWriter: &errOut,
	}
	err := cmd.Run(context.Background(), append([]string{"test"}, args...))
	return out.String(), err
}

// loadFile loads a configuration of type T from file only.
func loadFile[T any](t *testing.T, file string) *T {
	t.Helper()
	var c *T
	cmd := &cli.Command{
		Name:  "test",
		Flags: AllFlags("test", new(T)),
		Action: func(_ context.Context, cmd *cli.Command) (err error) {
			c, err = New[T](cmd, "test")
			return err
		},
	}
	if err := cmd.Run(context.Background(), []string{"test", "--config", file}); err != nil {
		t.Fatalf("failed to load %v: %v", file, err)
	}
	return c
}

func TestInit(t *testing.T) {
	dir := configDir(t)
	file := filepath.Join(dir, "test.toml")

	if _, err := runConfig[testConfig](t, "--name", "n", "--token", "secret", "config", "init"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fi, err := os.Stat(file)
	if err != nil {
		t.Fatalf("default file was not written: %v", err)
	}
	if fi.Mode().Perm() != 0644 {
		t.Errorf("mode = %v, want 0644", fi.Mode().Perm())
	}
	data, _ := os.ReadFile(file)
	if !strings.Contains(string(data), "token = 'secret'") {
		t.Errorf("secret not written in clear:\n%s", data)
	}

	// An existing file is kept without --force
	_, err = runConfig[testConfig](t, "--name", "other", "config", "init")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %v, want it to refuse overwriting", err)
	}
	if c := loadFile[testConfig](t, file); c.Server.Name != "n" {
		t.Errorf("server.name = %q, want the file unchanged", c.Server.Name)
	}

	// With --force, the file is replaced and gets mode 0644 again
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := runConfig[testConfig](t, "--name", "other", "config", "init", "--force"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c := loadFile[testConfig](t, file); c.Server.Name != "other" {
		t.Errorf("server.name = %q, want \"other\"", c.Server.Name)
	}
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0644 {
		t.Errorf("mode = %v, want 0644", fi.Mode().Perm())
	}
}

func TestInitValidates(t *testing.T) {
	dir := configDir(t)
	file := filepath.Join(dir, "test.toml")

	// server.name is missing
	_, err := runConfig[testConfig](t, "config", "init")
	if err == nil || !strings.Contains(err.Error(), "server.name") {
		t.Errorf("error = %v, want it to report server.name", err)
	}
	if _, err := os.Stat(file); err == nil {
		t.Error("an invalid configuration was written")
	}

	// --force writes a skeleton to complete by hand
	if _, err := runConfig[testConfig](t, "config", "init", "--force"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Errorf("file was not written with --force: %v", err)
	}
}

func TestInitAbsolutePaths(t *testing.T) {
	configDir(t)
	wd := t.TempDir()
	t.Chdir(wd)

	sub := filepath.Join(t.TempDir(), "sub")
	if err := os.Mkdir(sub, 0700); err != nil {
		t.Fatal(err)
	}
	write(t, sub, "in.toml", "[log]\nfile = \"from-file.log\"\n")

	out := filepath.Join(t.TempDir(), "out.toml")
	_, err := runConfig[testConfig](t, "--config", filepath.Join(sub, "in.toml"),
		"--name", "n", "--roots", "a.pem,/abs/b.pem", "--sources", "file://meta,https://host/x",
		"config", "init", "--output", out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	c := loadFile[testConfig](t, out)
	if want := filepath.Join(sub, "from-file.log"); c.Log.File != want {
		t.Errorf("log.file = %q, want %q", c.Log.File, want)
	}
	if want := []string{filepath.Join(wd, "a.pem"), "/abs/b.pem"}; !reflect.DeepEqual(c.Server.Roots, want) {
		t.Errorf("server.roots = %q, want %q", c.Server.Roots, want)
	}
	if want := []string{"file://" + filepath.Join(wd, "meta"), "https://host/x"}; !reflect.DeepEqual(c.Server.Sources, want) {
		t.Errorf("server.sources = %q, want %q", c.Server.Sources, want)
	}
}

func TestInitIgnoresDefaultFile(t *testing.T) {
	dir := configDir(t)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	write(t, dir, "test.toml", "[server]\nname = \"default\"\n")

	out, err := runConfig[testConfig](t, "--name", "flag", "config", "init", "--output", "-", "--minimal")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(out, "default") {
		t.Errorf("init read the default file:\n%v", out)
	}
}

type record struct {
	Id    string `toml:"id"`
	Label string `toml:"label"`
}

// roundTripConfig covers a top-level option, a record list and a subsection
// declared before an option of its parent section.
type roundTripConfig struct {
	Top    string `toml:"top" flag:"top" default:"t"`
	Server struct {
		Inner struct {
			Mode string `toml:"mode" flag:"mode" default:"a" enum:"a,b"`
		} `toml:"inner"`
		Name    string   `toml:"name"    flag:"name" usage:"server name"`
		Roots   []string `toml:"roots"   flag:"roots" default:"{data}/ca.pem" path:"true"`
		Report  string   `toml:"report"  flag:"report" default:"report" path:"true"`
		Records []record `toml:"records" flag:"-"`
	} `toml:"server"`
	Log logSection `toml:"log"`
}

func TestRoundTrip(t *testing.T) {
	configDir(t)
	dir := t.TempDir()
	in := write(t, dir, "in.toml", `
top = "x"

[server]
name = "n"

[server.inner]
mode = "b"

[[server.records]]
id = "a"
label = "A"

[[server.records]]
id = "b"
`)
	want := loadFile[roundTripConfig](t, in)

	for _, minimal := range []bool{false, true} {
		out := filepath.Join(dir, "out.toml")
		args := []string{"--config", in, "config", "init", "--force", "--output", out}
		if minimal {
			args = append(args, "--minimal")
		}
		if _, err := runConfig[roundTripConfig](t, args...); err != nil {
			t.Fatalf("minimal=%v: unexpected error: %v", minimal, err)
		}
		if got := loadFile[roundTripConfig](t, out); !reflect.DeepEqual(got, want) {
			data, _ := os.ReadFile(out)
			t.Errorf("minimal=%v: got %+v, want %+v, written:\n%s", minimal, got, want, data)
		}
	}
}

func TestPrint(t *testing.T) {
	configDir(t)

	full, err := runConfig[testConfig](t, "--name", "n", "--token", "secret", "config", "print")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"token = '" + Redaction + "'",
		"name = 'n'",
		// Defaults are commented out, with the usage and allowed values above
		"# Allowed: debug, info, warn\n# level = 'info'\n",
		"# address = 'localhost:1234'",
	} {
		if !strings.Contains(full, want) {
			t.Errorf("output does not contain %q:\n%v", want, full)
		}
	}
	if strings.Contains(full, "secret") {
		t.Errorf("secret leaked:\n%v", full)
	}

	minimal, err := runConfig[testConfig](t, "--name", "n", "--workers", "2", "config", "print", "--minimal")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "[server]\nname = 'n'\nworkers = 2\n"
	if minimal != want {
		t.Errorf("got:\n%v\nwant:\n%v", minimal, want)
	}
}

func TestValidateCommand(t *testing.T) {
	configDir(t)

	out, err := runConfig[testConfig](t, "--name", "n", "config", "validate")
	if err != nil || out != "configuration is valid\n" {
		t.Errorf("got %q, %v, want it to be valid", out, err)
	}
	if _, err := runConfig[testConfig](t, "config", "validate"); err == nil {
		t.Error("missing server.name was not reported")
	}
}
