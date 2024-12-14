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
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

type Config struct {
	LogLevel string `json:"logLevel,omitempty"`
	cmc.Config
}

const (
	configFlag   = "config"
	LogLevelFlag = "loglevel"
)

var (
	configFile = flag.String(configFlag, "", "configuration file")
	logLevel   = flag.String(LogLevelFlag, "",
		fmt.Sprintf("Possible logging: %v", strings.Join(maps.Keys(logLevels), ",")))
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

func GetConfig() (*Config, error) {

	flag.Parse()

	// Initialize cmcd configuration
	c := &Config{}

	// Fill cmcd values from json configuration file
	if internal.FlagPassed(configFlag) {
		files := strings.Split(*configFile, ",")
		for _, f := range files {
			log.Infof("Loading config from file %v", f)
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

	// Overwrite cmc configuration with values passed via command line
	err := cmc.GetConfig(&c.Config)
	if err != nil {
		log.Fatalf("Failed to read cmc config: %v", err)
	}

	if internal.FlagPassed(LogLevelFlag) {
		c.LogLevel = *logLevel
	}

	// Configure the logger
	l, ok := logLevels[strings.ToLower(c.LogLevel)]
	if !ok {
		log.Warnf("LogLevel %v does not exist. Default to info level", c.LogLevel)
		l = logrus.InfoLevel
	}
	log.Infof("Configuring logger for log level %v", c.LogLevel)
	logrus.SetLevel(l)

	// Output the configuration
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

	log.Debugf("\tLog Level                : %v", c.LogLevel)
}
