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

// Package logging redirects the logrus output of the CMC packages to the hclog logger of the
// SPIRE plugin, so that log levels and fields are preserved in the SPIRE logs
package logging

import (
	"io"
	"maps"
	"slices"

	"github.com/hashicorp/go-hclog"
	"github.com/sirupsen/logrus"
)

// RedirectLogrus forwards all logrus entries to logger. The logrus level follows the hclog
// level, so that suppressed entries are not formatted
func RedirectLogrus(logger hclog.Logger) {
	logrus.SetOutput(io.Discard)
	logrus.SetLevel(logrusLevel(logger.GetLevel()))
	logrus.StandardLogger().ReplaceHooks(logrus.LevelHooks{})
	logrus.AddHook(&hook{logger: logger})
}

type hook struct {
	logger hclog.Logger
}

func (h *hook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *hook) Fire(entry *logrus.Entry) error {
	args := make([]any, 0, 2*len(entry.Data))
	for _, k := range slices.Sorted(maps.Keys(entry.Data)) {
		args = append(args, k, entry.Data[k])
	}
	h.logger.Log(hclogLevel(entry.Level), entry.Message, args...)
	return nil
}

func hclogLevel(l logrus.Level) hclog.Level {
	switch l {
	case logrus.TraceLevel:
		return hclog.Trace
	case logrus.DebugLevel:
		return hclog.Debug
	case logrus.InfoLevel:
		return hclog.Info
	case logrus.WarnLevel:
		return hclog.Warn
	default:
		return hclog.Error
	}
}

func logrusLevel(l hclog.Level) logrus.Level {
	switch l {
	case hclog.Trace:
		return logrus.TraceLevel
	case hclog.Debug:
		return logrus.DebugLevel
	case hclog.Info, hclog.NoLevel:
		return logrus.InfoLevel
	case hclog.Warn:
		return logrus.WarnLevel
	default:
		return logrus.ErrorLevel
	}
}
