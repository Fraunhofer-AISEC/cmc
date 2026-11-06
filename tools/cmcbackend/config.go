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
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"github.com/Fraunhofer-AISEC/cmc/internal/config"
	"github.com/Fraunhofer-AISEC/cmc/internal/config/sections"
)

// Category separates independent deployments within the same database. The
// row limits apply to each category individually.
type Category struct {
	Id    string `json:"id"`
	Label string `json:"label"`
}

// httpConfig configures the HTTP server the results are published to.
type httpConfig struct {
	Address string `json:"address" flag:"addr"  default:"localhost:8080" usage:"HTTP listen address"`
	Token   string `json:"token"   flag:"token" path:"true" usage:"file with the HTTP authorization token clients have to present"`
	Debug   bool   `json:"debug"   flag:"debug" usage:"activate GIN debug mode"`
}

// databaseConfig configures the SQLite database and how much it may hold.
// Both limits apply to each category individually, so a busy deployment
// cannot evict the provers of another one.
type databaseConfig struct {
	Path             string `json:"path"             flag:"db" default:"monitoring.db" path:"true" usage:"SQLite3 database path"`
	MaxRows          int    `json:"maxRows"          flag:"max-rows" default:"400" usage:"maximum number of results stored per category"`
	MaxRowsPerProver int    `json:"maxRowsPerProver" flag:"max-rows-per-prover" default:"20" usage:"maximum number of results stored per prover and category"`
}

// categoriesConfig declares the independent deployments served from the same
// database. Both options are file-only, as a list of records has no sensible
// command line syntax and the default has to name one of its entries.
type categoriesConfig struct {
	Default string     `json:"default" flag:"-"`
	List    []Category `json:"list"    flag:"-"`
}

type Config struct {
	Log        sections.Log     `json:"log"`
	Http       httpConfig       `json:"http" category:"HTTP"`
	Database   databaseConfig   `json:"database"`
	Categories categoriesConfig `json:"categories"`
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

// flags returns the command line flags of the backend. A fresh set is built
// per call, as a flag carries the state of the command it is parsed for and
// must not be shared between commands.
func flags() []cli.Flag {
	return append([]cli.Flag{config.FileFlag()}, config.Flags(&Config{})...)
}

// getConfig loads and validates the configuration without touching anything
// outside the config files, so that it can also serve "cmcbackend config".
func getConfig(cmd *cli.Command) (*Config, error) {
	c := &Config{}
	if err := config.Load(cmd, c); err != nil {
		return nil, err
	}
	return c, nil
}

// setupLogging applies the log section to the global logger.
func setupLogging(c *Config) error {

	if c.Log.File != "" {
		file, err := os.OpenFile(c.Log.File, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		log.SetOutput(file)
	}

	// The level is restricted to the logrus levels by the enum tag
	l, err := log.ParseLevel(strings.ToLower(c.Log.Level))
	if err != nil {
		return fmt.Errorf("failed to parse log level: %w", err)
	}
	log.SetLevel(l)

	return nil
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

func printConfig(c *Config) {

	wd, err := os.Getwd()
	if err != nil {
		log.Warnf("Failed to get working directory: %v", err)
	}
	log.Infof("Running cmcbackend from working directory %v", wd)

	s, err := config.Redacted(c)
	if err != nil {
		log.Warnf("Failed to render configuration: %v", err)
		return
	}

	// One record per line, as the logger escapes an embedded newline
	log.Debug("Using the following configuration:")
	for line := range strings.SplitSeq(s, "\n") {
		log.Debugf("\t%v", line)
	}
}
