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
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"
)

type logSection struct {
	Level string `toml:"level" flag:"log-level" default:"info" enum:"debug,info,warn"`
	File  string `toml:"file"  flag:"log-file"  path:"true"`
}

type serverSection struct {
	Address  string   `toml:"address"  flag:"addr"     default:"localhost:1234"`
	Name     string   `toml:"name"     flag:"name"`
	Roots    []string `toml:"roots"    flag:"roots"    path:"true"`
	Token    string   `toml:"token"    flag:"token"    secret:"true"`
	Workers  int      `toml:"workers"  flag:"workers"  default:"4"`
	Debug    bool     `toml:"debug"    flag:"debug"`
	Ports    []int    `toml:"ports"    flag:"ports"`
	Internal string   `toml:"internal" flag:"-"`
	Drivers  []string `toml:"drivers"  flag:"drivers"  enum:"@testdrivers"`
	Sources  []string `toml:"sources"  flag:"sources"  path:"uri"`
}

func (s *serverSection) Validate(r *Report) {
	if s.Name == "" {
		r.Missing("server.name", "name")
	}
}

type testConfig struct {
	Log    logSection    `toml:"log"`
	Server serverSection `toml:"server" category:"SERVER"`
}

func init() {
	RegisterEnum("testdrivers", func() []string { return []string{"tpm", "sw"} })
}

// TestMain fixes the standard directories, so that no test depends on the
// real user or environment.
func TestMain(m *testing.M) {
	baseDirs = func() Dirs { return Dirs{Config: "/cfg", Data: "/data", Run: "/run"} }
	os.Exit(m.Run())
}

// load runs Load the way a command would, with args as the command line.
func load(t *testing.T, c *testConfig, args []string) error {
	t.Helper()

	var loadErr error
	cmd := &cli.Command{
		Name:  "test",
		Flags: append([]cli.Flag{FileFlag("test")}, Flags("test", c)...),
		Action: func(_ context.Context, cmd *cli.Command) error {
			loadErr = Load(cmd, "test", c)
			return nil
		},
	}

	if err := cmd.Run(context.Background(), append([]string{"test"}, args...)); err != nil {
		t.Fatalf("failed to run command: %v", err)
	}

	return loadErr
}

// write puts contents into a new file under a temporary directory and returns
// its path.
func write(t *testing.T, dir, name, contents string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(contents), 0600); err != nil {
		t.Fatalf("failed to write %v: %v", p, err)
	}
	return p
}

func TestDefaults(t *testing.T) {
	c := &testConfig{}
	if err := load(t, c, []string{"--name", "n"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Log.Level != "info" {
		t.Errorf("log.level = %q, want \"info\"", c.Log.Level)
	}
	if c.Server.Address != "localhost:1234" {
		t.Errorf("server.address = %q, want \"localhost:1234\"", c.Server.Address)
	}
	if c.Server.Workers != 4 {
		t.Errorf("server.workers = %v, want 4", c.Server.Workers)
	}
}

func TestPrecedence(t *testing.T) {
	dir := t.TempDir()
	first := write(t, dir, "a.toml", `
[log]
level = "debug"

[server]
name = "from-a"
address = "a:1"
workers = 1
`)
	second := write(t, dir, "b.toml", `
[server]
address = "b:2"
`)

	c := &testConfig{}
	err := load(t, c, []string{"--config", first + "," + second, "--workers", "9"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The later file wins over the earlier one
	if c.Server.Address != "b:2" {
		t.Errorf("server.address = %q, want \"b:2\"", c.Server.Address)
	}
	// Keys the later file does not mention survive
	if c.Server.Name != "from-a" {
		t.Errorf("server.name = %q, want \"from-a\"", c.Server.Name)
	}
	// Sections merge field by field rather than being replaced
	if c.Log.Level != "debug" {
		t.Errorf("log.level = %q, want \"debug\"", c.Log.Level)
	}
	// Flags win over every file
	if c.Server.Workers != 9 {
		t.Errorf("server.workers = %v, want 9", c.Server.Workers)
	}
}

func TestTypes(t *testing.T) {
	dir := t.TempDir()
	file := write(t, dir, "c.toml", `
[server]
name = "n"
debug = true
ports = [1, 2, 3]
`)

	c := &testConfig{}
	if err := load(t, c, []string{"--config", file}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.Server.Debug {
		t.Error("server.debug = false, want true")
	}
	if !slices.Equal(c.Server.Ports, []int{1, 2, 3}) {
		t.Errorf("server.ports = %v, want [1 2 3]", c.Server.Ports)
	}

	// Lists are comma-separated on the command line
	c = &testConfig{}
	err := load(t, c, []string{"--name", "n", "--ports", "7,8", "--roots", "x.pem, y.pem"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Equal(c.Server.Ports, []int{7, 8}) {
		t.Errorf("server.ports = %v, want [7 8]", c.Server.Ports)
	}
	if !slices.Equal(c.Server.Roots, []string{"x.pem", "y.pem"}) {
		t.Errorf("server.roots = %v, want [x.pem y.pem]", c.Server.Roots)
	}
}

func TestPathsResolveAgainstConfigFile(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(dir, "absolute.pem")
	file := write(t, dir, "c.toml", `
[log]
file = "logs/est.log"

[server]
name = "n"
roots = ["pki/ca.pem", "`+abs+`"]
`)

	c := &testConfig{}
	// A path given on the command line stays relative to the working
	// directory, only config file paths are rewritten
	if err := load(t, c, []string{"--config", file, "--token", "t"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if want := filepath.Join(dir, "logs/est.log"); c.Log.File != want {
		t.Errorf("log.file = %q, want %q", c.Log.File, want)
	}
	want := []string{filepath.Join(dir, "pki/ca.pem"), abs}
	if !slices.Equal(c.Server.Roots, want) {
		t.Errorf("server.roots = %v, want %v", c.Server.Roots, want)
	}

	c = &testConfig{}
	if err := load(t, c, []string{"--config", file, "--roots", "rel/ca.pem"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Equal(c.Server.Roots, []string{"rel/ca.pem"}) {
		t.Errorf("server.roots = %v, want [rel/ca.pem]", c.Server.Roots)
	}
}

// TestUriPathsResolveAgainstConfigFile checks that a path:"uri" option only
// rewrites what actually is a local path, so that a metadata location can be
// given as a file:// URI next to an https:// one.
func TestUriPathsResolveAgainstConfigFile(t *testing.T) {
	dir := t.TempDir()
	file := write(t, dir, "c.toml", `
[server]
name = "n"
sources = [
	"file://metadata-signed",
	"file:///etc/cmc/metadata",
	"https://example.org/metadata",
	"plain/path",
]
`)

	c := &testConfig{}
	if err := load(t, c, []string{"--config", file}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{
		"file://" + filepath.Join(dir, "metadata-signed"),
		"file:///etc/cmc/metadata",
		"https://example.org/metadata",
		filepath.Join(dir, "plain/path"),
	}
	if !slices.Equal(c.Server.Sources, want) {
		t.Errorf("server.sources =\n %v\nwant\n %v", c.Server.Sources, want)
	}
}

func TestMissing(t *testing.T) {
	c := &testConfig{}
	err := load(t, c, nil)
	if err == nil {
		t.Fatal("expected an error for a missing required option")
	}
	if !strings.Contains(err.Error(), "server.name: required option is not set (--name)") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEnum(t *testing.T) {
	dir := t.TempDir()
	file := write(t, dir, "c.toml", `
[log]
level = "verbose"

[server]
name = "n"
drivers = ["tpm", "snp"]
`)

	c := &testConfig{}
	err := load(t, c, []string{"--config", file})
	if err == nil {
		t.Fatal("expected an error for values outside the enum")
	}
	for _, want := range []string{
		`log.level: "verbose" is not one of [debug info warn]`,
		`server.drivers[1]: "snp" is not one of [tpm sw]`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %v does not contain %q", err, want)
		}
	}
}

func TestUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	file := write(t, dir, "c.toml", `
stray = true

[server]
name = "n"
nope = 1
`)

	c := &testConfig{}
	err := load(t, c, []string{"--config", file})
	if err == nil {
		t.Fatal("expected an error for unknown keys")
	}
	for _, want := range []string{
		`server.nope: unknown option "server.nope"`,
		`stray: unknown option "stray"`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %v does not contain %q", err, want)
		}
	}
}

func TestErrorsAreCollected(t *testing.T) {
	c := &testConfig{}
	err := load(t, c, []string{"--log-level", "verbose", "--drivers", "nope"})
	if err == nil {
		t.Fatal("expected an error")
	}
	// Missing option, bad enum and bad enum element, all at once
	if n := strings.Count(err.Error(), "\n  "); n != 3 {
		t.Errorf("got %v problems, want 3:\n%v", n, err)
	}
}

type validated struct {
	A string `toml:"a" flag:"a"`
	B string `toml:"b" flag:"b"`
}

func (v *validated) Validate(r *Report) {
	if (v.A == "") != (v.B == "") {
		r.Errorf("", "a and b must be set together")
	}
	if v.A == "bad" {
		r.Errorf("a", "conflicts with %v", r.Path("b"))
	}
}

type validatedConfig struct {
	Outer struct {
		Sec validated `toml:"sec"`
	} `toml:"outer"`
}

func TestValidator(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want string
	}{
		// Paths reported by a section are prefixed with the section's path
		{[]string{"--a", "x"}, "outer.sec: a and b must be set together"},
		{[]string{"--a", "bad", "--b", "y"}, "outer.sec.a: conflicts with outer.sec.b"},
	} {
		c := &validatedConfig{}
		cmd := &cli.Command{
			Name:  "test",
			Flags: append([]cli.Flag{FileFlag("test")}, Flags("test", c)...),
			Action: func(_ context.Context, cmd *cli.Command) error {
				err := Load(cmd, "test", c)
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Errorf("error %v does not contain %q", err, tt.want)
				}
				return nil
			},
		}
		if err := cmd.Run(context.Background(), append([]string{"test"}, tt.args...)); err != nil {
			t.Fatalf("failed to run command: %v", err)
		}
	}
}

func TestRedacted(t *testing.T) {
	c := &testConfig{}
	c.Server.Name = "n"
	c.Server.Token = "super-secret"
	c.Server.Address = "localhost:1"

	s, err := Redacted(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(s, "super-secret") {
		t.Errorf("secret leaked into the printed configuration:\n%v", s)
	}
	if !strings.Contains(s, `token = '`+Redaction+`'`) {
		t.Errorf("secret not redacted:\n%v", s)
	}
	if !strings.Contains(s, `address = 'localhost:1'`) {
		t.Errorf("non-secret option missing:\n%v", s)
	}
	// The configuration itself must be untouched
	if c.Server.Token != "super-secret" {
		t.Errorf("server.token = %q, want it unmodified", c.Server.Token)
	}
}

func TestFlags(t *testing.T) {
	c := &testConfig{}
	flags := Flags("test", c)

	byName := map[string]cli.Flag{}
	for _, f := range flags {
		byName[f.Names()[0]] = f
	}

	if _, ok := byName["internal"]; ok {
		t.Error("flag:\"-\" option got a command line flag")
	}
	if len(byName) != 11 {
		t.Errorf("got %v flags, want 11: %v", len(byName), slices.Sorted(names(byName)))
	}

	if _, ok := byName["debug"].(*cli.BoolFlag); !ok {
		t.Errorf("--debug is %T, want *cli.BoolFlag", byName["debug"])
	}
	if _, ok := byName["workers"].(*cli.IntFlag); !ok {
		t.Errorf("--workers is %T, want *cli.IntFlag", byName["workers"])
	}
	// Lists stay comma-separated string flags
	if _, ok := byName["roots"].(*cli.StringFlag); !ok {
		t.Errorf("--roots is %T, want *cli.StringFlag", byName["roots"])
	}

	if got := byName["addr"].(*cli.StringFlag).Category; got != "SERVER" {
		t.Errorf("--addr category = %q, want \"SERVER\"", got)
	}
	if got := byName["log-level"].(*cli.StringFlag).Category; got != "LOG" {
		t.Errorf("--log-level category = %q, want \"LOG\"", got)
	}
	if got := byName["addr"].(*cli.StringFlag).DefaultText; got != "localhost:1234" {
		t.Errorf("--addr default text = %q, want \"localhost:1234\"", got)
	}
	if got := byName["log-level"].(*cli.StringFlag).Usage; !strings.Contains(got, "[debug info warn]") {
		t.Errorf("--log-level usage = %q, want the allowed values", got)
	}
}

func names(m map[string]cli.Flag) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func TestFlagsPerSection(t *testing.T) {
	c := &testConfig{}
	flags := Flags("test", c, &c.Log)

	var names []string
	for _, f := range flags {
		names = append(names, f.Names()[0])
	}
	slices.Sort(names)

	if !slices.Equal(names, []string{"log-file", "log-level"}) {
		t.Errorf("got %v, want [log-file log-level]", names)
	}
}

func TestMalformedStructsPanic(t *testing.T) {
	tests := []struct {
		name string
		cfg  any
	}{
		{"missing flag tag", &struct {
			S struct {
				A string `toml:"a"`
			} `toml:"s"`
		}{}},
		{"missing toml tag", &struct {
			S struct {
				A string `flag:"a"`
			} `toml:"s"`
		}{}},
		{"duplicate flag", &struct {
			S struct {
				A string `toml:"a" flag:"x"`
				B string `toml:"b" flag:"x"`
			} `toml:"s"`
		}{}},
		{"unsupported type", &struct {
			S struct {
				A float64 `toml:"a" flag:"a"`
			} `toml:"s"`
		}{}},
		{"enum on int", &struct {
			S struct {
				A int `toml:"a" flag:"a" enum:"1,2"`
			} `toml:"s"`
		}{}},
		{"unknown path mode", &struct {
			S struct {
				A string `toml:"a" flag:"a" path:"yes"`
			} `toml:"s"`
		}{}},
		{"unknown placeholder", &struct {
			S struct {
				A string `toml:"a" flag:"a" default:"{home}/a"`
			} `toml:"s"`
		}{}},
		{"not a pointer", testConfig{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("expected a panic")
				}
			}()
			Flags("test", tt.cfg)
		})
	}
}

func TestUnknownEnumRegistry(t *testing.T) {
	c := &struct {
		S struct {
			A string `toml:"a" flag:"a" enum:"@nosuchregistry"`
		} `toml:"s"`
	}{}
	c.S.A = "x"

	var err error
	cmd := &cli.Command{
		Name:  "test",
		Flags: append([]cli.Flag{FileFlag("test")}, Flags("test", c)...),
		Action: func(_ context.Context, cmd *cli.Command) error {
			err = Load(cmd, "test", c)
			return nil
		},
	}
	if runErr := cmd.Run(context.Background(), []string{"test", "--a", "x"}); runErr != nil {
		t.Fatalf("failed to run command: %v", runErr)
	}
	if err == nil || !strings.Contains(err.Error(), `unknown enum registry "nosuchregistry"`) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWrongTypeInFile(t *testing.T) {
	dir := t.TempDir()
	file := write(t, dir, "c.toml", `
[server]
name = "n"
workers = "many"
`)

	c := &testConfig{}
	err := load(t, c, []string{"--config", file})
	if err == nil {
		t.Fatal("expected an error for a wrongly typed value")
	}
	if want := "server.workers: expected int (" + file + ":4:11)"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %v does not contain %q", err, want)
	}
}

func TestWrongTypeInRecord(t *testing.T) {
	type record struct {
		Id string `toml:"id"`
	}
	c := &struct {
		S struct {
			List []record `toml:"list" flag:"-"`
		} `toml:"s"`
	}{}

	dir := t.TempDir()
	file := write(t, dir, "c.toml", `
[[s.list]]
id = "a"

[[s.list]]
id = 2
`)

	var err error
	cmd := &cli.Command{
		Name:  "test",
		Flags: []cli.Flag{FileFlag("test")},
		Action: func(_ context.Context, cmd *cli.Command) error {
			err = Load(cmd, "test", c)
			return nil
		},
	}
	if runErr := cmd.Run(context.Background(), []string{"test", "--config", file}); runErr != nil {
		t.Fatalf("failed to run command: %v", runErr)
	}
	if want := "s.list.id: expected string (" + file + ":6:6)"; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("error %v does not contain %q", err, want)
	}
}

func TestSyntaxError(t *testing.T) {
	dir := t.TempDir()
	file := write(t, dir, "c.toml", `
[server
name = "n"
`)

	c := &testConfig{}
	err := load(t, c, []string{"--config", file})
	if err == nil {
		t.Fatal("expected an error for malformed TOML")
	}
	if want := "failed to parse config file " + file + ":2:8:"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %v does not contain %q", err, want)
	}
}

func TestSectionExpectedToBeTable(t *testing.T) {
	dir := t.TempDir()
	file := write(t, dir, "c.toml", `
log = "debug"

[server]
name = "n"
`)

	c := &testConfig{}
	err := load(t, c, []string{"--config", file})
	if err == nil {
		t.Fatal("expected an error for a section given as a scalar")
	}
	// Reported once by the survey, not again by the decoder
	if n := strings.Count(err.Error(), "\n  "); n != 1 || !strings.Contains(err.Error(), "log: expected a table") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestEveryLeafIsReachable guards the invariant the package relies on: a leaf
// is addressable through its section, so per-section flag sets work.
func TestEveryLeafIsReachable(t *testing.T) {
	c := &testConfig{}
	s := newSchema(c)

	for _, f := range s.fields {
		if !f.value.CanSet() {
			t.Errorf("%v is not settable", f.path)
		}
		if f.value.Type().Kind() == reflect.Invalid {
			t.Errorf("%v has an invalid type", f.path)
		}
	}
	if len(s.fields) != 12 {
		t.Errorf("got %v options, want 12", len(s.fields))
	}
}

func TestDirs(t *testing.T) {
	tests := []struct {
		name string
		root bool
		env  map[string]string
		want Dirs
	}{
		{"root ignores XDG", true, map[string]string{"XDG_CONFIG_HOME": "/x/config"},
			Dirs{Config: "/etc/cmc", Data: "/var/lib/cmc", Run: "/run/cmc", root: true}},
		{"user without XDG", false, nil,
			Dirs{Config: "/home/u/.config/cmc", Data: "/home/u/.local/share/cmc",
				Run: "/home/u/.local/share/cmc/run"}},
		{"user with XDG", false,
			map[string]string{"XDG_CONFIG_HOME": "/x/config", "XDG_DATA_HOME": "/x/data",
				"XDG_RUNTIME_DIR": "/x/run"},
			Dirs{Config: "/x/config/cmc", Data: "/x/data/cmc", Run: "/x/run/cmc"}},
		{"run falls back to XDG data", false, map[string]string{"XDG_DATA_HOME": "/x/data"},
			Dirs{Config: "/home/u/.config/cmc", Data: "/x/data/cmc", Run: "/x/data/cmc/run"}},
		{"relative XDG is ignored", false,
			map[string]string{"XDG_CONFIG_HOME": "x/config", "XDG_RUNTIME_DIR": "x/run"},
			Dirs{Config: "/home/u/.config/cmc", Data: "/home/u/.local/share/cmc",
				Run: "/home/u/.local/share/cmc/run"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dirsFrom(tt.root, func(k string) string { return tt.env[k] }, "/home/u")
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

type placeholderConfig struct {
	Shared struct {
		Ca string `toml:"ca" flag:"ca" default:"{data}/ca.pem" path:"true"`
	} `toml:"shared"`
	Own struct {
		Socket string   `toml:"socket" flag:"socket" default:"socket://{run}/cmc.sock"`
		Files  []string `toml:"files"  flag:"files"  default:"{config}/a,{data}/b"`
	} `toml:"own"`
}

func TestPlaceholderDefaults(t *testing.T) {

	// A shared section gets the data folder of the binary it runs in
	for _, name := range []string{"a", "b"} {
		c := &placeholderConfig{}
		cmd := &cli.Command{
			Name:  name,
			Flags: AllFlags(name, c),
			Action: func(_ context.Context, cmd *cli.Command) error {
				return Load(cmd, name, c)
			},
		}
		if err := cmd.Run(context.Background(), []string{name}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if want := "/data/" + name + "/ca.pem"; c.Shared.Ca != want {
			t.Errorf("shared.ca = %q, want %q", c.Shared.Ca, want)
		}
		if want := "socket:///run/cmc.sock"; c.Own.Socket != want {
			t.Errorf("own.socket = %q, want %q", c.Own.Socket, want)
		}
		if want := []string{"/cfg/a", "/data/" + name + "/b"}; !slices.Equal(c.Own.Files, want) {
			t.Errorf("own.files = %q, want %q", c.Own.Files, want)
		}

		for _, f := range Flags(name, c, &c.Shared) {
			if got, want := f.(*cli.StringFlag).DefaultText, "/data/"+name+"/ca.pem"; got != want {
				t.Errorf("--ca default text = %q, want %q", got, want)
			}
		}
	}
}

func TestCreateDirs(t *testing.T) {
	tmp := t.TempDir()
	d := Dirs{Data: filepath.Join(tmp, "data", "bin"), Run: filepath.Join(tmp, "run")}

	if err := d.Create(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, dir := range []string{d.Data, d.Run} {
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("%v was not created: %v", dir, err)
		}
		if fi.Mode().Perm() != 0700 {
			t.Errorf("%v has mode %v, want 0700", dir, fi.Mode().Perm())
		}
	}
}

func TestDiscovery(t *testing.T) {

	dir := t.TempDir()
	orig := baseDirs
	baseDirs = func() Dirs { return Dirs{Config: dir, Data: "/data", Run: "/run"} }
	t.Cleanup(func() { baseDirs = orig })

	other := write(t, t.TempDir(), "other.toml", "[server]\nname = \"other\"\n")

	// The default file is missing
	c := &testConfig{}
	if err := load(t, c, []string{"--name", "flag"}); err != nil {
		t.Fatalf("missing default file: unexpected error: %v", err)
	}

	write(t, dir, "test.toml", "[server]\nname = \"default\"\nroots = [\"ca.pem\"]\n")

	tests := []struct {
		name  string
		args  []string
		want  string
		roots []string
	}{
		{"default file without --config", nil, "default", []string{filepath.Join(dir, "ca.pem")}},
		{"default file ignored with --config", []string{"--config", other}, "other", nil},
		{"empty --config disables the default file", []string{"--config=", "--name", "flag"}, "flag", nil},
		{"flags override the default file", []string{"--name", "flag"}, "flag", []string{filepath.Join(dir, "ca.pem")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &testConfig{}
			if err := load(t, c, tt.args); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.Server.Name != tt.want {
				t.Errorf("server.name = %q, want %q", c.Server.Name, tt.want)
			}
			if !slices.Equal(c.Server.Roots, tt.roots) {
				t.Errorf("server.roots = %q, want %q", c.Server.Roots, tt.roots)
			}
		})
	}

	if got, want := FileFlag("test").(*cli.StringFlag).DefaultText, filepath.Join(dir, "test.toml")+", if it exists"; got != want {
		t.Errorf("--config default text = %q, want %q", got, want)
	}
}
