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

// Package sections holds the configuration sections that more than one binary
// uses, so that an option shared by cmcd, cmcctl and the estserver is declared
// exactly once. Sections that only one binary has stay with that binary.
package sections

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

// Log configures the global logger.
type Log struct {
	Level string `json:"level" flag:"log-level" default:"info" enum:"panic,fatal,error,warn,info,debug,trace" usage:"logging level"`
	File  string `json:"file"  flag:"log-file"  path:"true" usage:"file to log to instead of stdout/stderr"`
}

// Setup applies the log section to the global logger.
func (l *Log) Setup() error {

	if l.File != "" {
		file, err := os.OpenFile(l.File, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		logrus.SetOutput(file)
	}

	// The level is restricted to the logrus levels by the enum tag
	level, err := logrus.ParseLevel(l.Level)
	if err != nil {
		return fmt.Errorf("failed to parse log level: %w", err)
	}
	logrus.SetLevel(level)

	return nil
}

// Trust configures the root CAs used to authenticate metadata, attestation
// reports and TLS peers.
type Trust struct {
	RootCas          []string `json:"rootCas"          flag:"root-cas"           path:"true" usage:"comma-separated paths to trusted root CA PEM files"`
	AllowSystemCerts bool     `json:"allowSystemCerts" flag:"allow-system-certs" usage:"allow using the system cert pool as trusted root CAs"`
}
