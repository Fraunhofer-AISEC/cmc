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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
	"golang.org/x/exp/maps"
)

type config struct {
	DbPath      string
	Address     string
	LogLevel    string
	MetadataCAs []*x509.Certificate
}

const (
	flagDbPath     = "db"
	flagAddress    = "addr"
	flagMetadataCA = "ca"
	flagLogLevel   = "log"
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

	flags = []cli.Flag{
		&cli.StringFlag{
			Name:     flagDbPath,
			Usage:    "SQLite3 database path, contents are considered trusted",
			Required: true,
		},
		&cli.StringFlag{
			Name:     flagAddress,
			Usage:    "HTTP listen address",
			Required: true,
		},
		&cli.StringSliceFlag{
			Name:  flagMetadataCA,
			Usage: "trusted metadata root CA certificates (PEM or DER), none means pushed metadata is stored unverified",
		},
		&cli.StringFlag{
			Name:  flagLogLevel,
			Usage: fmt.Sprintf("logging level: %v", strings.Join(maps.Keys(logLevels), ",")),
			Value: "info",
		},
	}
)

func fetchConfig(cmd *cli.Command) (*config, error) {
	cfg := &config{}

	// configure the logging class (first to ensure it applies to upcoming logs)
	level, ok := logLevels[strings.ToLower(cmd.String(flagLogLevel))]
	if !ok {
		return nil, fmt.Errorf("log level [%v] does not exist", cmd.String(flagLogLevel))
	}
	log.SetLevel(level)

	// parse and validate the db path and listen address (presence enforced by cli)
	if path, err := filepath.Abs(cmd.String(flagDbPath)); err != nil {
		return nil, fmt.Errorf("failed to resolve database path: %w", err)
	} else {
		cfg.DbPath = path
	}
	cfg.Address = cmd.String(flagAddress)

	// parse and validate the root cas
	if args := cmd.StringSlice(flagMetadataCA); len(args) > 0 {
		cfg.MetadataCAs = make([]*x509.Certificate, 0, len(args))

		for _, path := range args {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("failed to read ca (%v): %w", path, err)
			}

			// try to decode and parse the actual certificate
			block, _ := pem.Decode(data)
			if block != nil {
				data = block.Bytes
			}
			cert, err := x509.ParseCertificate(data)
			if err != nil {
				return nil, fmt.Errorf("failed to parse x509 certificate (%v): %w", path, err)
			}
			cfg.MetadataCAs = append(cfg.MetadataCAs, cert)

			log.Infof("Metadata CA certificate (%v) loaded", path)
		}
	} else {
		log.Info("Running without metadata signature verification")
	}
	return cfg, nil
}
