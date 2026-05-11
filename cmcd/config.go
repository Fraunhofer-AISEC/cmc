// Copyright (c) 2021 Fraunhofer AISEC
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
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/internal/cmcflags"
)

type Config struct {
	LogLevel string `json:"logLevel,omitempty"`
	LogFile  string `json:"logFile,omitempty"`
	cmc.Config
}

const (
	configFlag   = "config"
	logLevelFlag = "log-level"
	logFileFlag  = "log-file"
)

var (
	logLevels = map[string]logrus.Level{
		"panic": logrus.PanicLevel,
		"fatal": logrus.FatalLevel,
		"error": logrus.ErrorLevel,
		"warn":  logrus.WarnLevel,
		"info":  logrus.InfoLevel,
		"debug": logrus.DebugLevel,
		"trace": logrus.TraceLevel,
	}
)

var Flags = append([]cli.Flag{
	&cli.StringFlag{
		Name:  configFlag,
		Usage: "JSON configuration file(s), comma-separated",
	},
	&cli.StringFlag{
		Name:  logLevelFlag,
		Usage: fmt.Sprintf("logging level: %v", strings.Join(logLevelKeys(), ",")),
	},
	&cli.StringFlag{
		Name:  logFileFlag,
		Usage: "file to log to instead of stdout/stderr",
	},
}, cmcflags.Flags...)

func logLevelKeys() []string {
	keys := make([]string, 0, len(logLevels))
	for k := range logLevels {
		keys = append(keys, k)
	}
	return keys
}

func GetConfig(cmd *cli.Command) (*Config, error) {

	c := &Config{}

	if cmd.IsSet(configFlag) {
		files := strings.Split(cmd.String(configFlag), ",")
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				return nil, fmt.Errorf("failed to read cmcd config file %v: %v", f, err)
			}
			err = json.Unmarshal(data, c)
			if err != nil {
				return nil, fmt.Errorf("failed to parse cmcd config: %v", err)
			}
		}
	}

	err := cmcflags.Override(cmd, &c.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to read cmc config: %w", err)
	}

	if cmd.IsSet(logLevelFlag) {
		c.LogLevel = cmd.String(logLevelFlag)
	}
	if cmd.IsSet(logFileFlag) {
		c.LogFile = cmd.String(logFileFlag)
	}

	// Configure the logger
	if c.LogFile != "" {
		lf, err := filepath.Abs(c.LogFile)
		if err != nil {
			return nil, fmt.Errorf("failed to get logfile path: %w", err)
		}
		file, err := os.OpenFile(lf, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
		}
		logrus.SetOutput(file)
	}
	if c.LogLevel != "" {
		l, ok := logLevels[strings.ToLower(c.LogLevel)]
		if !ok {
			log.Warnf("LogLevel %v does not exist. Default to info level", c.LogLevel)
			l = logrus.InfoLevel
		}
		logrus.SetLevel(l)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	c.Print()

	return c, nil
}

func (c *Config) Print() {
	wd, err := os.Getwd()
	if err != nil {
		log.Warnf("Failed to get working directory: %v", err)
	}
	log.Infof("Running cmc from working directory %v", wd)

	c.Config.Print()

	log.Debugf("\tLog Level                     : %v", c.LogLevel)
}
