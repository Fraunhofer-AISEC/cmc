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
	"fmt"
	"reflect"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Redaction is what the value of a secret option is replaced with.
const Redaction = "***"

// commentWidth is the line width usage comments are wrapped at.
const commentWidth = 100

// writeOpts selects how render lays out a configuration.
type writeOpts struct {
	// annotate precedes every option with its usage and allowed values, and
	// writes the options at their default commented out
	annotate bool
	// minimal leaves out the options at their default, and the sections
	// without any other option
	minimal bool
	// redact replaces the value of every secret option with Redaction
	redact bool
}

// render writes the configuration as TOML in the layout of a config file.
// The defaults the options are compared against are expanded with d.
func (s *schema) render(d Dirs, o writeOpts) (string, error) {

	var defaults *schema
	if o.annotate || o.minimal {
		defaults = s.defaults(d)
	}
	isDefault := func(f *field) bool {
		return defaults != nil && equalValues(f.value, defaults.byPath[f.path].value)
	}

	// Group the options by section in the order of first appearance. Record
	// lists go last, as every key after a [[list]] header belongs to the record.
	// Top-level options come first, as they cannot follow a table header
	order := []string{""}
	bySection := map[string][]*field{}
	for _, f := range s.fields {
		sec := sectionOf(f.path)
		if _, ok := bySection[sec]; !ok && sec != "" {
			order = append(order, sec)
		}
		bySection[sec] = append(bySection[sec], f)
	}

	var b strings.Builder
	if o.annotate && !o.minimal {
		b.WriteString("# Options commented out are at their default value.\n")
	}

	for _, sec := range order {

		var plain, records []*field
		for _, f := range bySection[sec] {
			if o.minimal && isDefault(f) {
				continue
			}
			if f.kind == kindStructSlice {
				records = append(records, f)
			} else {
				plain = append(plain, f)
			}
		}
		if len(plain) == 0 && len(records) == 0 {
			continue
		}

		if sec != "" {
			if b.Len() > 0 {
				b.WriteString("\n")
			}
			fmt.Fprintf(&b, "[%v]\n", sec)
		}

		for i, f := range plain {
			if o.annotate {
				if i > 0 && f.comment() != "" {
					b.WriteString("\n")
				}
				writeComment(&b, f)
			}
			val, err := f.format(o.redact)
			if err != nil {
				return "", fmt.Errorf("%v: %w", f.path, err)
			}
			if o.annotate && isDefault(f) {
				b.WriteString("# ")
			}
			fmt.Fprintf(&b, "%v = %v\n", keyOf(f.path), val)
		}

		for _, f := range records {
			if err := writeRecords(&b, f, o, isDefault(f)); err != nil {
				return "", fmt.Errorf("%v: %w", f.path, err)
			}
		}
	}

	return strings.TrimSuffix(b.String(), "\n"), nil
}

// defaults returns a schema of the same type holding the defaults expanded
// with d.
func (s *schema) defaults(d Dirs) *schema {
	def := newSchemaFor(reflect.New(s.root.Type()).Elem())
	def.applyDefaults(d)
	return def
}

// writeRecords writes a record list as one [[path]] table per record. An
// empty list is written commented out, as an empty array.
func writeRecords(b *strings.Builder, f *field, o writeOpts, isDefault bool) error {

	b.WriteString("\n")
	if o.annotate {
		writeComment(b, f)
	}

	if f.value.Len() == 0 {
		if o.annotate && isDefault {
			b.WriteString("# ")
		}
		fmt.Fprintf(b, "%v = []\n", keyOf(f.path))
		return nil
	}

	for i := range f.value.Len() {
		data, err := toml.Marshal(f.value.Index(i).Interface())
		if err != nil {
			return err
		}
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(b, "[[%v]]\n", f.path)
		b.Write(data)
	}
	return nil
}

// writeComment writes the usage and the allowed values of an option as a
// comment.
func writeComment(b *strings.Builder, f *field) {
	for para := range strings.SplitSeq(f.comment(), "\n") {
		line := "#"
		for word := range strings.FieldsSeq(para) {
			if len(line)+1+len(word) > commentWidth && line != "#" {
				b.WriteString(line + "\n")
				line = "#"
			}
			line += " " + word
		}
		if line != "#" {
			b.WriteString(line + "\n")
		}
	}
}

// comment returns the usage and the allowed values of an option.
func (f *field) comment() string {
	allowed, err := f.allowed()
	if err != nil || len(allowed) == 0 {
		return f.usage
	}
	if f.usage == "" {
		return "Allowed: " + strings.Join(allowed, ", ")
	}
	return f.usage + ". Allowed: " + strings.Join(allowed, ", ")
}

// format renders the value of a plain option as a TOML value.
func (f *field) format(redact bool) (string, error) {

	v := f.value.Interface()
	switch {
	case f.value.Kind() == reflect.Slice && f.value.Len() == 0:
		return "[]", nil
	case redact && f.secret && f.kind == kindString && f.value.String() != "":
		v = Redaction
	case redact && f.secret && f.kind == kindStringSlice:
		r := make([]string, f.value.Len())
		for i := range r {
			r[i] = Redaction
		}
		v = r
	}

	data, err := toml.Marshal(map[string]any{"v": v})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(strings.TrimPrefix(string(data), "v = ")), nil
}

// equalValues reports whether two option values are equal, treating a nil
// and an empty list alike.
func equalValues(a, b reflect.Value) bool {
	if a.Kind() == reflect.Slice && a.Len() == 0 && b.Len() == 0 {
		return true
	}
	return reflect.DeepEqual(a.Interface(), b.Interface())
}

func sectionOf(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[:i]
	}
	return ""
}

func keyOf(path string) string {
	return path[strings.LastIndex(path, ".")+1:]
}

// redacted renders the configuration root as TOML, with every option tagged
// secret replaced by Redaction. The configuration itself is not modified.
func redacted(root any) (string, error) {
	return newSchema(root).render(Dirs{}, writeOpts{redact: true})
}
