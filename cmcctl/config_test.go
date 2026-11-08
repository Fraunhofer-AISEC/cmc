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

// run loads the configuration the way a cmcctl subcommand does, with every
// section registered.
func run(t *testing.T, args ...string) (*Config, error) {
	t.Helper()

	var c *Config
	var loadErr error

	cmd := &cli.Command{
		Name:  "cmcctl",
		Flags: append(globalFlags(true), flags(allSections...)...),
		Action: func(_ context.Context, cmd *cli.Command) error {
			c, loadErr = config.New[Config](cmd)
			return nil
		},
	}
	if err := cmd.Run(context.Background(), append([]string{"cmcctl"}, args...)); err != nil {
		t.Fatalf("failed to run command: %v", err)
	}

	return c, loadErr
}

// TestExampleConfigs checks that every cmcctl configuration shipped with the
// repository still loads and validates.
func TestExampleConfigs(t *testing.T) {

	files, err := filepath.Glob("../example-setup/*/cmcctl-conf*.json")
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
		"addr", "allow-system-certs", "append-ebs", "attest", "attestation-only-trust",
		"ca-store-path", "cmc", "config", "count", "ctr-driver", "ctr-log", "data", "drivers",
		"dry-run", "endorsement", "enrollment", "exclude-pcrs", "hash-alg", "header", "key-config",
		"key-id", "key-type", "kubeadm-path", "log-file", "log-level", "measurement-logs",
		"metadata", "method", "mtls", "nonce", "omsp-format", "policies", "policy-engine",
		"policy-overwrite", "provision-auth", "provision-token", "publish-cert", "publish-key",
		"publish-network", "publish-ocsf", "publish-results", "publish-token", "report", "result",
		"provision-token-out", "root-cas", "serialization", "storage", "tls-cn", "tls-dns-names", "tls-ip-addresses",
		"tpm-key-alg", "token-max-uses", "token-store", "token-subject", "use-omsp", "vmpl",
	}
	slices.Sort(want)

	var got []string
	for _, f := range append(globalFlags(true), flags(allSections...)...) {
		got = append(got, f.Names()...)
	}
	slices.Sort(got)

	if !slices.Equal(got, want) {
		t.Errorf("flags changed:\n got %v\nwant %v", got, want)
	}
}

// TestSubcommandFlags checks that a subcommand only registers the sections it
// needs, so that --help stays specific to what the subcommand does.
func TestSubcommandFlags(t *testing.T) {

	names := func(fs []cli.Flag) []string {
		var out []string
		for _, f := range fs {
			out = append(out, f.Names()...)
		}
		return out
	}

	generate := names(flags(withFiles))
	if slices.Contains(generate, "mtls") {
		t.Error("generate must not register the atls section")
	}
	if slices.Contains(generate, "publish-results") {
		t.Error("generate must not register the publish section")
	}
	if !slices.Contains(generate, "report") {
		t.Error("generate must register the files section")
	}
	// The global flags are inherited from the root command. Repeating them
	// on a subcommand would shadow them and make them unusable before the
	// subcommand name
	for _, global := range []string{"config", "root-cas", "drivers", "log-level"} {
		if slices.Contains(generate, global) {
			t.Errorf("subcommand must not redeclare the global flag --%v", global)
		}
	}
}

// TestLibapiFlagsAreListedOnlyWhenTheyApply checks that the options of the
// embedded CMC stay out of --help unless a CMC actually runs in this
// process, while remaining accepted either way.
func TestLibapiFlagsAreListedOnlyWhenTheyApply(t *testing.T) {

	visible := func(libapi bool) []string {
		var out []string
		for _, f := range globalFlags(libapi) {
			if v, ok := f.(cli.VisibleFlag); ok && !v.IsVisible() {
				continue
			}
			out = append(out, f.Names()...)
		}
		return out
	}

	if names := visible(false); slices.Contains(names, "drivers") {
		t.Error("--drivers is listed although no embedded CMC runs")
	}
	if names := visible(true); !slices.Contains(names, "drivers") {
		t.Error("--drivers is not listed although an embedded CMC runs")
	}
	// Whether they are listed must not change whether they work
	for _, libapi := range []bool{false, true} {
		var c *Config
		cmd := &cli.Command{
			Name:  "cmcctl",
			Flags: globalFlags(libapi),
			Action: func(_ context.Context, cmd *cli.Command) error {
				var err error
				c, err = config.New[Config](cmd)
				return err
			},
		}
		args := []string{"cmcctl", "--drivers", "sw", "--cmc", "socket://localhost:9955"}
		if err := cmd.Run(context.Background(), args); err != nil {
			t.Fatalf("libapi=%v: %v", libapi, err)
		}
		if !slices.Equal(c.Cmc.Attestation.Drivers, []string{"sw"}) {
			t.Errorf("libapi=%v: drivers = %v, want [sw]", libapi, c.Cmc.Attestation.Drivers)
		}
	}
}

// TestLibapiSelected checks the pre-parse of the command line that decides
// whether the embedded CMC options are listed.
func TestLibapiSelected(t *testing.T) {

	file := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(file, []byte(`{"api":{"endpoint":"libapi"}}`), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	for _, tt := range []struct {
		name string
		args []string
		want bool
	}{
		{"no api given", []string{"cmcctl", "dial"}, false},
		{"socket", []string{"cmcctl", "--cmc", "socket://localhost:9955", "dial"}, false},
		{"separate argument", []string{"cmcctl", "--cmc", "libapi", "dial"}, true},
		{"equals form", []string{"cmcctl", "--cmc=libapi", "dial"}, true},
		{"single dash", []string{"cmcctl", "-cmc", "libapi", "dial"}, true},
		{"after the subcommand", []string{"cmcctl", "dial", "--cmc", "libapi"}, true},
		{"from a config file", []string{"cmcctl", "--config", file, "dial"}, true},
		{"flag overrides the file", []string{"cmcctl", "--config", file, "--cmc", "grpc://h:1"}, false},
		{"unreadable config file", []string{"cmcctl", "--config", "/nonexistent", "dial"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := libapiSelected(tt.args); got != tt.want {
				t.Errorf("libapiSelected(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

// TestGlobalFlagsWorkBeforeAndAfterTheSubcommand guards the fact that a
// subcommand must not redeclare a global flag: urfave applies the root's
// flags to subcommands persistently, but a local flag of the same name
// shadows the inherited one, so the value given before the subcommand name
// would be silently ignored.
func TestGlobalFlagsWorkBeforeAndAfterTheSubcommand(t *testing.T) {

	load := func(args ...string) *Config {
		t.Helper()

		var c *Config
		action := func(_ context.Context, cmd *cli.Command) error {
			var err error
			c, err = config.New[Config](cmd)
			return err
		}
		cmd := &cli.Command{
			Name:  "cmcctl",
			Flags: globalFlags(true),
			Commands: []*cli.Command{{
				Name:   "dial",
				Flags:  flags(withAtls, withIdentity, withFiles, withPublish),
				Action: action,
			}},
		}
		if err := cmd.Run(context.Background(), append([]string{"cmcctl"}, args...)); err != nil {
			t.Fatalf("failed to run command: %v", err)
		}
		return c
	}

	before := load("--root-cas", "ca.pem", "dial")
	after := load("dial", "--root-cas", "ca.pem")

	for _, c := range []*Config{before, after} {
		if !slices.Equal(c.Trust.RootCas, []string{"ca.pem"}) {
			t.Errorf("trust.rootCas = %v, want [ca.pem]", c.Trust.RootCas)
		}
	}
}

// TestLibapiRequiresMetadataAndDrivers checks that the options only the
// embedded CMC needs are required exactly when cmcctl runs one.
func TestLibapiRequiresMetadataAndDrivers(t *testing.T) {

	if _, err := run(t, "--cmc", "socket://localhost:9955"); err != nil {
		t.Errorf("a client without an embedded CMC needs no drivers: %v", err)
	}

	_, err := run(t, "--cmc", "libapi")
	if err == nil {
		t.Fatal("expected an error for an embedded CMC without drivers or metadata")
	}
	for _, want := range []string{"cmc.attestation.drivers", "cmc.metadata.locations"} {
		if !strings.Contains(err.Error(), want+": required option is not set") {
			t.Errorf("error does not report %v as required:\n%v", want, err)
		}
	}
}

func TestInvalidValues(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"valid", nil, ""},
		{"api", []string{"--cmc", "carrier-pigeon://localhost"}, `API "carrier-pigeon" is not implemented`},
		{"serialization", []string{"--serialization", "yaml"}, `"yaml" is not one of`},
		{"attest", []string{"--attest", "sometimes"}, `"sometimes" is not one of`},
		{"keyConfig", []string{"--key-config", "EC512"}, `"EC512" is not one of`},
		{"attestation only trust", []string{"--attestation-only-trust", "--attest", "none"},
			"requires the peer to be attested"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := run(t, tt.args...)
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
