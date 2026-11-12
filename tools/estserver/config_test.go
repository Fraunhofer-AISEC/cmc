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
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/internal/config"
	"github.com/Fraunhofer-AISEC/cmc/provision/est"
)

// TestMain hides the config file of the user running the tests, which would
// otherwise be loaded whenever a test does not pass --config.
func TestMain(m *testing.M) {
	os.Setenv("XDG_CONFIG_HOME", "/nonexistent")
	os.Exit(m.Run())
}

// run loads the configuration the way the estserver binary does.
func run(t *testing.T, args ...string) (*Config, error) {
	t.Helper()

	var c *Config
	var loadErr error

	cmd := &cli.Command{
		Name:  "estserver",
		Flags: config.AllFlags(binaryName, &Config{}),
		Action: func(_ context.Context, cmd *cli.Command) error {
			c, loadErr = config.New[Config](cmd, binaryName)
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

// TestDefaults checks that the estserver needs no option to be configured, as
// every key and certificate has a default location.
func TestDefaults(t *testing.T) {
	c, err := run(t)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d, _ := time.ParseDuration(c.Est.CertValidity); d != internal.DefaultCertValidity {
		t.Errorf("est.cert_validity = %v, want %v", d, internal.DefaultCertValidity)
	}
}

func TestIncompleteOmsp(t *testing.T) {
	c, err := run(t, "--omsp-url", "https://localhost:9000/omsp")
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
			_, err := run(t, "--cert-validity", tt.value)
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

func TestAuthDefaults(t *testing.T) {
	c, err := run(t)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := c.resolveAuth(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]internal.AuthMethod{
		est.EnrollEndpoint:            internal.AuthToken,
		est.TpmActivateEnrollEndpoint: internal.AuthToken,
		est.TpmCertifyEnrollEndpoint:  internal.AuthAttestation,
		est.AttestEnrollEndpoint:      internal.AuthAttestation,
	}
	if !maps.Equal(c.auth, want) {
		t.Errorf("auth = %v, want %v", c.auth, want)
	}
}

func TestAuth(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"multiple methods", []string{"--auth-attestenroll", "token,certificate,attestation"}, ""},
		{"none", []string{"--auth-simpleenroll", "none"}, ""},
		{"none combined", []string{"--auth-simpleenroll", "none,token"},
			"est.auth.simpleenroll: none cannot be combined"},
		{"attestation not applicable", []string{"--auth-simpleenroll", "attestation"},
			"est.auth.simpleenroll"},
		{"attestation not applicable to activation", []string{"--auth-tpmactivateenroll", "attestation"},
			"est.auth.tpmactivateenroll"},
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

func TestAuthDisabledEndpoint(t *testing.T) {
	c, err := run(t, "--auth-simpleenroll", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := c.resolveAuth(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := c.auth[est.EnrollEndpoint]; ok {
		t.Errorf("%v enabled with empty methods", est.EnrollEndpoint)
	}
}
