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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
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
	// once and with its own message, which encoding/json cannot do
	var tree map[string]any
	d := json.NewDecoder(bytes.NewReader(data))
	if err := d.Decode(&tree); err != nil {
		r.Errorf("", "failed to parse config file %v: %v", file, err)
		return
	}
	if d.More() {
		r.Errorf("", "failed to parse config file %v: unexpected data after JSON object", file)
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
	if err := json.Unmarshal(data, tmp.Interface()); err != nil {
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) && te.Field != "" {
			r.Errorf(te.Field, "cannot use %v as %v (%v)", te.Value, te.Type, file)
		} else {
			r.Errorf("", "failed to parse config file %v: %v", file, err)
		}
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

// survey walks the decoded JSON and collects the paths of the options the
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

		if _, ok := s.byPath[path]; ok {
			*present = append(*present, path)
			continue
		}

		if s.sections[path] {
			sub, ok := node[k].(map[string]any)
			if !ok {
				r.Errorf(path, "expected an object (%v)", file)
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
