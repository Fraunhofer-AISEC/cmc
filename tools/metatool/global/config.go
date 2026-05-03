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

package global

import (
	"fmt"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

type Config struct {
	LogLevel string
}

const (
	LogLevelFlag = "log-level"
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

	log = logrus.WithField("service", "metatool")
)

var Flags = []cli.Flag{
	&cli.StringFlag{
		Name:  LogLevelFlag,
		Usage: fmt.Sprintf("set log level. Possible: %v", strings.Join(maps.Keys(logLevels), ",")),
	},
}

func GetConfig(cmd *cli.Command) (*Config, error) {
	c := &Config{}

	if cmd.IsSet(LogLevelFlag) {
		c.LogLevel = cmd.String(LogLevelFlag)
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

	return c, nil
}
