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
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// applyFile merges one config file into the configuration. Options the file
// does not mention keep the value they had, so sections merge field by field
// while scalars and lists are replaced.
func (s *schema) applyFile(file string, r *Report) {

	data, err := os.ReadFile(file)
	if err != nil {
		r.Errorf("", "failed to read config file %v: %v", file, err)
		return
	}

	// Survey the keys the file sets first. This yields every unknown key at
	// once and with its own message, which the decoder cannot do
	var tree map[string]any
	if err := toml.Unmarshal(data, &tree); err != nil {
		s.decodeError(err, file, r)
		return
	}

	var present []string
	s.survey(tree, "", file, &present, r)
	if len(present) == 0 {
		return
	}

	// Decode into a fresh struct of the same type, so that the keys the file
	// does not mention stay untouched in the real configuration
	tmp := reflect.New(s.root.Type())
	if err := toml.Unmarshal(data, tmp.Interface()); err != nil {
		s.decodeError(err, file, r)
		return
	}
	decoded := newSchemaFor(tmp.Elem())

	dir := filepath.Dir(file)
	for _, path := range present {
		src, dst := decoded.byPath[path], s.byPath[path]
		if src.isPath {
			resolvePaths(src.value, dir, src.isUri)
		}
		dst.value.Set(src.value)
	}
}

// decodeError reports an error of the TOML decoder with its position in the
// file. A value of the wrong type is reported for the option it belongs to.
func (s *schema) decodeError(err error, file string, r *Report) {

	var de *toml.DecodeError
	if !errors.As(err, &de) {
		r.Errorf("", "failed to parse config file %v: %v", file, err)
		return
	}

	row, col := de.Position()
	msg := strings.TrimPrefix(de.Error(), "toml: ")
	path := strings.Join(de.Key(), ".")

	if strings.HasPrefix(msg, "cannot decode") {
		// survey has already reported a section that is not a table
		if s.sections[path] {
			return
		}
		if want := s.typeOf(de.Key()); want != kindInvalid {
			r.Errorf(path, "expected %v (%v:%v:%v)", want, file, row, col)
			return
		}
	}

	r.Errorf("", "failed to parse config file %v:%v:%v: %v", file, row, col, msg)
}

// typeOf returns the kind of the option or record field at key, or
// kindInvalid if key does not name one.
func (s *schema) typeOf(key []string) kind {

	for i := len(key); i > 0; i-- {
		f, ok := s.byPath[strings.Join(key[:i], ".")]
		if !ok {
			continue
		}
		if i == len(key) {
			return f.kind
		}
		// A field inside a record of a record list
		if f.kind != kindStructSlice || i != len(key)-1 {
			return kindInvalid
		}
		t := f.value.Type().Elem()
		for j := range t.NumField() {
			if name, _, _ := strings.Cut(t.Field(j).Tag.Get("toml"), ","); name == key[i] {
				return kindOf(t.Field(j).Type)
			}
		}
		return kindInvalid
	}
	return kindInvalid
}

// survey walks the decoded TOML and collects the paths of the options the
// file sets, reporting every key that is not one.
func (s *schema) survey(node map[string]any, prefix, file string, present *[]string, r *Report) {

	keys := make([]string, 0, len(node))
	for k := range node {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	for _, k := range keys {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}

		if f, ok := s.byPath[path]; ok {
			// The decoder accepts a single table for a record list
			if _, isList := node[k].([]any); f.kind == kindStructSlice && !isList {
				r.Errorf(path, "expected %v (%v)", f.kind, file)
				continue
			}
			*present = append(*present, path)
			continue
		}

		if s.sections[path] {
			sub, ok := node[k].(map[string]any)
			if !ok {
				r.Errorf(path, "expected a table (%v)", file)
				continue
			}
			s.survey(sub, path, file, present, r)
			continue
		}

		r.Errorf(path, "unknown option %q (%v)", path, file)
	}
}

// resolvePaths rewrites the relative paths in v to be relative to dir. For a
// uri option, only the path of a file:// URI is rewritten.
func resolvePaths(v reflect.Value, dir string, uri bool) {
	resolve := resolvePath
	if uri {
		resolve = resolveUri
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(resolve(v.String(), dir))
	case reflect.Slice:
		for i := range v.Len() {
			v.Index(i).SetString(resolve(v.Index(i).String(), dir))
		}
	}
}

func resolvePath(p, dir string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// resolveUri rewrites the path of a file:// URI, and leaves every other
// scheme alone, as its path is not one of the local file system
func resolveUri(u, dir string) string {
	scheme, rest, found := strings.Cut(u, "://")
	if !found {
		return resolvePath(u, dir)
	}
	if !strings.EqualFold(scheme, "file") {
		return u
	}
	return scheme + "://" + resolvePath(rest, dir)
}
