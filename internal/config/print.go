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
	"encoding/json"
	"fmt"
	"reflect"
)

// Redaction is what the value of a secret option is replaced with.
const Redaction = "***"

// Redacted renders the effective configuration as indented JSON, in the
// layout a config file uses, with every option tagged secret replaced by
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

	b, err := json.MarshalIndent(cp.Interface(), "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal configuration: %w", err)
	}

	return string(b), nil
}
