// Copyright (c) 2025 Fraunhofer AISEC
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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
	"golang.org/x/exp/maps"
)

type config struct {
	Addr             string `json:"addr"`
	Db               string `json:"db"`
	LogLevel         string `json:"log"`
	MaxRows          int    `json:"maxRows"`
	MaxRowsPerProver int    `json:"maxRowsPerProver"`
	Token            string `json:"token"`
	Debug            bool   `json:"debug"`
}

const (
	configFlag           = "config"
	addrFlag             = "addr"
	dbFlag               = "db"
	logFlag              = "log"
	maxRowsFlag          = "maxrows"
	maxRowsPerProverFlag = "maxrowsperprover"
	tokenFlag            = "token"
	debugFlag            = "debug"
)

var (
	logLevels = map[string]log.Level{
		"panic": log.PanicLevel,
		"fatal": log.FatalLevel,
		"error": log.ErrorLevel,
		"warn":  log.WarnLevel,
		"info":  log.InfoLevel,
		"debug": log.DebugLevel,
		"trace": log.TraceLevel,
	}
)

var flags = []cli.Flag{
	&cli.StringFlag{
		Name:  configFlag,
		Usage: "configuration file",
	},
	&cli.StringFlag{
		Name:  addrFlag,
		Usage: "HTTP listen address (default: localhost:8080)",
	},
	&cli.StringFlag{
		Name:  dbFlag,
		Usage: "SQLite3 database path (default: monitoring.db)",
	},
	&cli.StringFlag{
		Name:  logFlag,
		Usage: fmt.Sprintf("logging level: %v", strings.Join(maps.Keys(logLevels), ",")),
	},
	&cli.IntFlag{
		Name:  maxRowsFlag,
		Usage: "maximum number of results which can be stored in the database (default: 400)",
	},
	&cli.IntFlag{
		Name:  maxRowsPerProverFlag,
		Usage: "maximum number of results per prover which can be stored in the database (default: 20)",
	},
	&cli.StringFlag{
		Name:  tokenFlag,
		Usage: "optional HTTP authorization token",
	},
	&cli.BoolFlag{
		Name:  debugFlag,
		Usage: "activate GIN debug mode",
	},
}

func getConfig(cmd *cli.Command) (*config, error) {
	var err error

	// Create default configuration
	c := &config{
		Addr:             "localhost:8080",
		Db:               "monitoring.db",
		LogLevel:         "trace",
		MaxRows:          400,
		MaxRowsPerProver: 20,
		Debug:            false,
	}

	// Obtain custom configuration from file if specified
	if cmd.IsSet(configFlag) {
		configFile := cmd.String(configFlag)
		log.Infof("Loading config from file %v", configFile)
		data, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read cmcd config file %v: %v", configFile, err)
		}
		if err := json.Unmarshal(data, c); err != nil {
			return nil, fmt.Errorf("failed to parse cmcd config: %v", err)
		}
	}

	// Overwrite config file configuration with given command line arguments
	if cmd.IsSet(addrFlag) {
		c.Addr = cmd.String(addrFlag)
	}
	if cmd.IsSet(dbFlag) {
		c.Db = cmd.String(dbFlag)
	}
	if cmd.IsSet(logFlag) {
		c.LogLevel = cmd.String(logFlag)
	}
	if cmd.IsSet(maxRowsFlag) {
		c.MaxRows = cmd.Int(maxRowsFlag)
	}
	if cmd.IsSet(maxRowsPerProverFlag) {
		c.MaxRowsPerProver = cmd.Int(maxRowsPerProverFlag)
	}
	if cmd.IsSet(tokenFlag) {
		c.Token = cmd.String(tokenFlag)
	}
	if cmd.IsSet(debugFlag) {
		c.Debug = cmd.Bool(debugFlag)
	}

	// Configure the logger
	l, ok := logLevels[strings.ToLower(c.LogLevel)]
	if !ok {
		return nil, fmt.Errorf("log level %v does not exist", c.LogLevel)
	}
	log.SetLevel(l)

	// Convert file path to absolute path
	c.Db, err = filepath.Abs(c.Db)
	if err != nil {
		return nil, fmt.Errorf("failed to get path for database: %w", err)
	}
	if c.Token != "" {
		c.Token, err = filepath.Abs(c.Token)
		if err != nil {
			return nil, fmt.Errorf("failed to get path for authorization token: %w", err)
		}
	}

	printConfig(c)

	return c, nil
}

func printConfig(c *config) {
	wd, err := os.Getwd()
	if err != nil {
		log.Warnf("Failed to get working directory: %v", err)
	}
	log.Debugf("Running cmc-backend from working directory %v", wd)

	log.Debugf("Using the following configuration:")
	log.Debugf("\tListen address            : %v", c.Addr)
	log.Debugf("\tSQLite database           : %v", c.Db)
	log.Debugf("\tLogging level             : %v", c.LogLevel)
	log.Debugf("\tMaximum Entries           : %v", c.MaxRows)
	log.Debugf("\tMaximum Entries per Prover: %v", c.MaxRowsPerProver)
	log.Debugf("\tToken                     : %v", c.Token)
	log.Debugf("\tGIN Debug                 : %v", c.Debug)
}

func getVersion() string {
	version := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		if strings.EqualFold(info.Main.Version, "(devel)") {
			commit := "unknown"
			created := "unknown"
			for _, elem := range info.Settings {
				if strings.EqualFold(elem.Key, "vcs.revision") {
					commit = elem.Value
				}
				if strings.EqualFold(elem.Key, "vcs.time") {
					created = elem.Value
				}
			}
			version = fmt.Sprintf("%v, commit %v, created %v", info.Main.Version, commit, created)
		} else {
			version = info.Main.Version
		}
	}
	return version
}
