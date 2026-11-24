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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
	"golang.org/x/exp/maps"
)

type config struct {
	DbPath      string
	BlobPath    string
	Address     string
	LogLevel    string
	MetadataCAs []*x509.Certificate
	tlsKey      crypto.PrivateKey
	tlsCaChain  []*x509.Certificate
}

const (
	flagDbPath     = "db"
	flagBlobPath   = "blobs"
	flagAddress    = "addr"
	flagMetadataCA = "ca"
	flagLogLevel   = "log"
	flagTLSKey     = "tls-key"
	flagTLSCaChain = "tls-ca-chain"
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
			Usage:    "SQLite3 index database path, contents are considered trusted",
			Required: true,
		},
		&cli.StringFlag{
			Name:     flagBlobPath,
			Usage:    "directory of the metadata blob store, contents are considered trusted",
			Required: true,
		},
		&cli.StringFlag{
			Name:     flagAddress,
			Usage:    "HTTP listen address",
			Required: true,
		},
		&cli.StringSliceFlag{
			Name:     flagMetadataCA,
			Usage:    "trusted metadata root CA certificates (PEM or DER), none means pushed metadata is stored unverified",
			Required: true,
		},
		&cli.StringFlag{
			Name:  flagLogLevel,
			Usage: fmt.Sprintf("logging level: %v", strings.Join(maps.Keys(logLevels), ",")),
			Value: "info",
		},
		&cli.StringFlag{
			Name:  flagTLSKey,
			Usage: "TLS key for RVPS HTTPS server (no key and chain implies plain HTTP)",
		},
		&cli.StringFlag{
			Name:  flagTLSCaChain,
			Usage: "comma-separated paths to TLS certificate chain for RVPS HTTPS server (no key and chain implies plain HTTP)",
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

	// parse and validate the db path, blob path and listen address (presence enforced by cli)
	if path, err := filepath.Abs(cmd.String(flagDbPath)); err != nil {
		return nil, fmt.Errorf("failed to resolve database path: %w", err)
	} else {
		cfg.DbPath = path
	}
	if path, err := filepath.Abs(cmd.String(flagBlobPath)); err != nil {
		return nil, fmt.Errorf("failed to resolve blob store path: %w", err)
	} else {
		cfg.BlobPath = path
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

	// parse the tls parameter
	if cmd.IsSet(flagTLSKey) || cmd.IsSet(flagTLSCaChain) {
		var err error
		cfg.tlsKey, err = internal.LoadPrivateKey(cmd.String(flagTLSKey))
		if err != nil {
			return nil, fmt.Errorf("failed to load private key: %w", err)
		}

		cfg.tlsCaChain, err = internal.ReadCerts(strings.Split(cmd.String(flagTLSCaChain), ","))
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate chain: %w", err)
		}
	}
	return cfg, nil
}
