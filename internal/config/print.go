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

package config

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/sirupsen/logrus"
)

// LogEffective logs the working directory of the binary name at info level
// and the effective configuration root, secrets redacted, at debug level.
func LogEffective(name string, root any) {

	l := logrus.WithField("service", name)

	wd, err := os.Getwd()
	if err != nil {
		l.Warnf("Failed to get working directory: %v", err)
	}
	l.Infof("Running %v from working directory %v", name, wd)

	s, err := Redacted(root)
	if err != nil {
		l.Warnf("Failed to render configuration: %v", err)
		return
	}

	// One record per line, as the logger escapes an embedded newline
	l.Debug("Using the following configuration:")
	for line := range strings.SplitSeq(s, "\n") {
		l.Debugf("\t%v", line)
	}
}

// Redaction is what the value of a secret option is replaced with.
const Redaction = "***"

// Redacted renders the effective configuration as TOML, in the layout a
// config file uses, with every option tagged secret replaced by
// Redaction. The configuration itself is not modified.
func Redacted(root any) (string, error) {

	s := newSchema(root)

	// Work on a copy, so that redacting does not destroy the live values.
	// Slices are shared with the original, but secrets are replaced as a
	// whole rather than element-wise, so the original stays intact
	cp := reflect.New(s.root.Type())
	cp.Elem().Set(s.root)

	for _, f := range newSchemaFor(cp.Elem()).fields {
		if !f.secret {
			continue
		}
		switch f.kind {
		case kindString:
			if f.value.String() != "" {
				f.value.SetString(Redaction)
			}
		case kindStringSlice:
			if n := f.value.Len(); n > 0 {
				out := reflect.MakeSlice(f.value.Type(), n, n)
				for i := range n {
					out.Index(i).SetString(Redaction)
				}
				f.value.Set(out)
			}
		}
	}

	var b bytes.Buffer
	enc := toml.NewEncoder(&b).SetIndentTables(true)
	if err := enc.Encode(cp.Interface()); err != nil {
		return "", fmt.Errorf("failed to marshal configuration: %w", err)
	}

	return strings.TrimSuffix(b.String(), "\n"), nil
}
