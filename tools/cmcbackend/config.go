// Copyright (c) 2025 - 2026 Fraunhofer AISEC
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
	"fmt"

	"github.com/Fraunhofer-AISEC/cmc/internal/config"
	"github.com/Fraunhofer-AISEC/cmc/internal/config/sections"
)

// Category separates independent deployments within the same database. The
// row limits apply to each category individually.
type Category struct {
	Id    string `json:"id"    toml:"id"`
	Label string `json:"label" toml:"label"`
}

// httpConfig configures the HTTP server the results are published to.
type httpConfig struct {
	Address string `toml:"address" flag:"addr"  default:"localhost:8080" usage:"HTTP listen address"`
	Token   string `toml:"token"   flag:"token" path:"true" usage:"file with the HTTP authorization token clients have to present"`
	Debug   bool   `toml:"debug"   flag:"debug" usage:"activate GIN debug mode"`
}

// databaseConfig configures the SQLite database and how much it may hold.
// Both limits apply to each category individually, so a busy deployment
// cannot evict the provers of another one.
type databaseConfig struct {
	Path             string `toml:"path"                flag:"db" default:"{data}/monitoring.db" path:"true" usage:"SQLite3 database path"`
	MaxRows          int    `toml:"max_rows"            flag:"max-rows" default:"400" usage:"maximum number of results stored per category"`
	MaxRowsPerProver int    `toml:"max_rows_per_prover" flag:"max-rows-per-prover" default:"20" usage:"maximum number of results stored per prover and category"`
}

// categoriesConfig declares the independent deployments served from the same
// database. Both options are file-only, as a list of records has no sensible
// command line syntax and the default has to name one of its entries.
type categoriesConfig struct {
	Default string     `toml:"default" flag:"-"`
	List    []Category `toml:"list"    flag:"-"`
}

type Config struct {
	Log        sections.Log     `toml:"log"`
	Http       httpConfig       `toml:"http" category:"HTTP"`
	Database   databaseConfig   `toml:"database"`
	Categories categoriesConfig `toml:"categories"`
}

// Validate checks the rules that span more than one option. It is called by
// config.Load after the checks derived from the struct tags.
func (c *Config) Validate(r *config.Report) {

	seen := make(map[string]bool, len(c.Categories.List))
	for i, cat := range c.Categories.List {
		switch {
		case !categoryCheck.MatchString(cat.Id):
			r.Errorf(fmt.Sprintf("categories.list[%v].id", i),
				"%q must be URL-safe (A-Z a-z 0-9 . _ ~ -)", cat.Id)
		case seen[cat.Id]:
			r.Errorf(fmt.Sprintf("categories.list[%v].id", i), "duplicate category %q", cat.Id)
		}
		seen[cat.Id] = true
	}

	// An empty list is filled with a single default category by resolve, so
	// only a default naming a category that was configured can be wrong
	if c.Categories.Default != "" && len(seen) > 0 && !seen[c.Categories.Default] {
		r.Errorf("categories.default", "%q is not one of the configured categories %v",
			c.Categories.Default, categoryIds(c.Categories.List))
	}
}

func categoryIds(cats []Category) []string {
	ids := make([]string, 0, len(cats))
	for _, c := range cats {
		ids = append(ids, c.Id)
	}
	return ids
}

// resolve fills in the values that are derived from the validated
// configuration rather than configured directly.
func (c *Config) resolve() {

	if len(c.Categories.List) == 0 {
		c.Categories.List = []Category{{Id: defaultCategory, Label: "Default"}}
	}
	for i, cat := range c.Categories.List {
		if cat.Label == "" {
			c.Categories.List[i].Label = cat.Id
		}
	}
	if c.Categories.Default == "" {
		c.Categories.Default = c.Categories.List[0].Id
	}
}
