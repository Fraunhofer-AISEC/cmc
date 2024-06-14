// Copyright (c) 2024 Fraunhofer AISEC
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
	"flag"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

// Install github packages with "go get [url]"

type config struct {
	config   string
	rootfs   string
	args     string
	logLevel logrus.Level
}

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

func getConfig() (*config, error) {

	configPath := flag.String("config", "", "OCI runtime bundle config path")
	rootfsPath := flag.String("rootfs", "", "OCI runtime bundle rootfs path")
	args := flag.String("args", "", "OCI runtime bundle additional args")
	logLevel := flag.String("log-level", "info",
		fmt.Sprintf("Possible logging: %v", strings.Join(maps.Keys(logLevels), ",")))
	flag.Parse()

	if *configPath == "" {
		flag.Usage()
		log.Fatal("OCI runtime bundle config path not provided")
	}
	if *rootfsPath == "" {
		flag.Usage()
		log.Fatal("OCI runtime bundle rootfs path not provided")
	}

	l, ok := logLevels[strings.ToLower(*logLevel)]
	if !ok {
		flag.Usage()
		log.Fatalf("LogLevel %v does not exist", *logLevel)
	}

	c := &config{
		config:   *configPath,
		rootfs:   *rootfsPath,
		args:     *args,
		logLevel: l,
	}

	return c, nil
}
