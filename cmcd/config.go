// Copyright (c) 2021 - 2026 Fraunhofer AISEC
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
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/internal/config"
	"github.com/Fraunhofer-AISEC/cmc/internal/config/sections"
)

// apiConfig configures the API the cmcd serves.
type apiConfig struct {
	Endpoint string `toml:"endpoint" flag:"cmc" default:"socket://{run}/cmc.sock" usage:"CMC API and address in the form <api>://<address>, e.g. socket:///run/cmc/cmc.sock, socket://127.0.0.1:9955 or grpc://127.0.0.1:9955"`
}

// Config is the cmcd configuration. Everything the CMC itself reads sits in
// the cmc section, which is transparent here, so that its subsections keep
// their own help categories.
type Config struct {
	Log   sections.Log   `toml:"log"`
	Api   apiConfig      `toml:"api"`
	Trust sections.Trust `toml:"trust"`
	Cmc   cmc.Config     `toml:"cmc" category:"-"`
}

// Validate checks the rules that span more than one option. The sections of
// the embedded CMC check their own rules, which config.Load picks up wherever
// the section is used.
func (c *Config) Validate(r *config.Report) {

	// The set of APIs depends on the build tags, so it cannot be an enum tag
	name, _, err := internal.ParseApiEndpoint(c.Api.Endpoint)
	switch {
	case err != nil:
		r.Errorf("api.endpoint", "%v", err)
	case servers[name] == nil:
		r.Errorf("api.endpoint", "API %q is not implemented, available: %v",
			name, strings.Join(availableApis(), ", "))
	}
}
