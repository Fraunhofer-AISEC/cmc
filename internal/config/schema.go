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
	"strconv"
	"strings"
	"sync"
)

// kind is the supported leaf type of a configuration option.
type kind uint8

const (
	kindInvalid kind = iota
	kindString
	kindBool
	kindInt
	kindStringSlice
	kindIntSlice
	kindStructSlice
)

func kindOf(t reflect.Type) kind {
	switch t.Kind() {
	case reflect.String:
		return kindString
	case reflect.Bool:
		return kindBool
	case reflect.Int:
		return kindInt
	case reflect.Slice:
		switch t.Elem().Kind() {
		case reflect.String:
			return kindStringSlice
		case reflect.Int:
			return kindIntSlice
		case reflect.Struct:
			return kindStructSlice
		}
	}
	return kindInvalid
}

func (k kind) String() string {
	switch k {
	case kindString:
		return "string"
	case kindBool:
		return "bool"
	case kindInt:
		return "int"
	case kindStringSlice:
		return "string list"
	case kindIntSlice:
		return "int list"
	case kindStructSlice:
		return "record list"
	}
	return "invalid"
}

// field is a single configuration leaf, together with the tags declared on it
// and the value it lives in.
type field struct {
	path     string
	category string
	flag     string
	usage    string
	def      string
	hasDef   bool
	enum     []string
	enumRef  string
	isPath   bool
	isUri    bool
	secret   bool
	kind     kind
	value    reflect.Value
}

// validator is a Validator together with the path of the section it
// validates, which is empty for the root.
type validator struct {
	path string
	v    Validator
}

// schema is the flattened view of a configuration struct.
type schema struct {
	root       reflect.Value
	fields     []*field
	byPath     map[string]*field
	byFlag     map[string]*field
	sections   map[string]bool
	validators []validator
}

func newSchema(root any) *schema {
	v := reflect.ValueOf(root)
	if v.Kind() != reflect.Pointer || v.IsNil() || v.Elem().Kind() != reflect.Struct {
		panicf("root must be a non-nil pointer to a struct, got %T", root)
	}
	return newSchemaFor(v.Elem())
}

func newSchemaFor(root reflect.Value) *schema {
	s := &schema{
		root:     root,
		byPath:   map[string]*field{},
		byFlag:   map[string]*field{},
		sections: map[string]bool{},
	}
	s.walk(root, "", "")
	return s
}

func (s *schema) walk(v reflect.Value, path, category string) {

	if v.CanAddr() {
		if val, ok := v.Addr().Interface().(Validator); ok {
			s.validators = append(s.validators, validator{path, val})
		}
	}

	t := v.Type()
	for i := range t.NumField() {
		sf := t.Field(i)
		if !sf.IsExported() {
			continue
		}

		name, _, _ := strings.Cut(sf.Tag.Get("toml"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			panicf("%v.%v: missing toml tag", t, sf.Name)
		}

		p := name
		if path != "" {
			p = path + "." + name
		}

		if k := kindOf(sf.Type); k != kindInvalid {
			s.leaf(sf, v.Field(i), p, category, k)
			continue
		}

		if sf.Type.Kind() != reflect.Struct {
			panicf("%v: unsupported type %v", p, sf.Type)
		}

		// Only the top level introduces a category, so that a nested
		// subsection stays grouped with its parent section. A section
		// tagged category:"-" is transparent: it groups nothing itself,
		// so each of its subsections introduces its own category again
		c := category
		switch tag := sf.Tag.Get("category"); {
		case tag == "-":
			c = ""
		case c != "":
		case tag != "":
			c = tag
		default:
			c = strings.ToUpper(name)
		}
		s.sections[p] = true
		s.walk(v.Field(i), p, c)
	}
}

func (s *schema) leaf(sf reflect.StructField, v reflect.Value, path, category string, k kind) {

	f := &field{
		path:     path,
		category: category,
		kind:     k,
		value:    v,
		usage:    sf.Tag.Get("usage"),
		secret:   sf.Tag.Get("secret") == "true",
	}

	switch p := sf.Tag.Get("path"); p {
	case "":
	case "true":
		f.isPath = true
	case "uri":
		f.isPath, f.isUri = true, true
	default:
		panicf("%v: unknown path mode %q, expected true or uri", path, p)
	}

	f.flag = sf.Tag.Get("flag")
	if f.flag == "" {
		panicf("%v: missing flag tag (use flag:\"-\" for a file-only option)", path)
	}
	if f.flag == "-" {
		f.flag = ""
	}
	// A record list has no sensible command line syntax, so it can only be
	// written in a config file
	if k == kindStructSlice && f.flag != "" {
		panicf("%v: a record list cannot be set on the command line, use flag:\"-\"", path)
	}

	f.def, f.hasDef = sf.Tag.Lookup("default")
	if strings.Contains((Dirs{}).expand(f.def), "{") {
		panicf("%v: unknown placeholder in default %q, expected {config}, {data} or {run}", path, f.def)
	}

	if e := sf.Tag.Get("enum"); e != "" {
		if after, ok := strings.CutPrefix(e, "@"); ok {
			f.enumRef = after
		} else {
			f.enum = SplitList(e)
		}
	}

	switch {
	case f.hasDef && k == kindStructSlice:
		panicf("%v: default is not supported on %v", path, k)
	case (f.enumRef != "" || len(f.enum) > 0) && k != kindString && k != kindStringSlice:
		panicf("%v: enum is not supported on %v", path, k)
	case f.isPath && k != kindString && k != kindStringSlice:
		panicf("%v: path is not supported on %v", path, k)
	}

	if dup, ok := s.byPath[path]; ok {
		panicf("%v: duplicate option (also declared as %v)", path, dup.path)
	}
	if f.flag != "" {
		if dup, ok := s.byFlag[f.flag]; ok {
			panicf("--%v: duplicate flag (declared by %v and %v)", f.flag, dup.path, path)
		}
		s.byFlag[f.flag] = f
	}

	s.byPath[path] = f
	s.fields = append(s.fields, f)
}

// applyDefaults writes the default tags into the struct, with the
// placeholders expanded to the directories d.
func (s *schema) applyDefaults(d Dirs) {
	for _, f := range s.fields {
		if !f.hasDef {
			continue
		}
		if err := f.assign(d.expand(f.def)); err != nil {
			panicf("%v: invalid default %q: %v", f.path, f.def, err)
		}
	}
}

// assign parses raw according to the field's type and stores it.
func (f *field) assign(raw string) error {
	switch f.kind {
	case kindString:
		f.value.SetString(raw)

	case kindBool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("%q is not a boolean", raw)
		}
		f.value.SetBool(b)

	case kindInt:
		n, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("%q is not an integer", raw)
		}
		f.value.SetInt(int64(n))

	case kindStringSlice:
		parts := SplitList(raw)
		out := reflect.MakeSlice(f.value.Type(), len(parts), len(parts))
		for i, p := range parts {
			out.Index(i).SetString(p)
		}
		f.value.Set(out)

	case kindIntSlice:
		parts := SplitList(raw)
		out := reflect.MakeSlice(f.value.Type(), len(parts), len(parts))
		for i, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil {
				return fmt.Errorf("%q is not an integer", p)
			}
			out.Index(i).SetInt(int64(n))
		}
		f.value.Set(out)

	default:
		return fmt.Errorf("unsupported type")
	}
	return nil
}

// SplitList splits a comma-separated command line or tag value. Empty input
// yields no elements rather than one empty element.
func SplitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

var (
	registryMu sync.RWMutex
	registries = map[string]func() []string{}
)

// RegisterEnum registers the allowed values for an enum:"@name" tag. The
// values are resolved when the configuration is validated or a flag's help
// text is rendered, so they may depend on build tags.
func RegisterEnum(name string, values func() []string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registries[name] = values
}

// allowed returns the values this option is restricted to, or nil if it is
// not restricted.
func (f *field) allowed() ([]string, error) {
	if f.enumRef == "" {
		return f.enum, nil
	}
	registryMu.RLock()
	fn, ok := registries[f.enumRef]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown enum registry %q", f.enumRef)
	}
	return fn(), nil
}
