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
	"fmt"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"
)

// A Validator is a configuration struct or section with rules that span more
// than one option. Validate is called after the tag-derived checks, on the
// root and on every section that implements it, and must only report
// problems: it must not read files or contact the network, so that a
// configuration can be checked without side effects.
//
// The paths passed to the Report are relative to the section that implements
// Validate, as a section does not know where it is embedded.
type Validator interface {
	Validate(r *Report)
}

// A Report collects the problems found while loading a configuration. An
// invalid value is an error and aborts startup; an option that has no effect
// is a warning.
type Report struct {
	errs  []string
	warns []string
	scope string
}

// Path returns the full config path of key, which is relative to the section
// currently being validated, for use in a message.
func (r *Report) Path(key string) string {
	switch {
	case r.scope == "":
		return key
	case key == "":
		return r.scope
	}
	return r.scope + "." + key
}

// Errorf records an invalid configuration value. The path is the dotted
// config path of the offending option, relative to the section being
// validated. An empty path refers to the section itself.
func (r *Report) Errorf(path, format string, args ...any) {
	r.errs = append(r.errs, prefix(r.Path(path), format, args...))
}

// Missing records that an option the configuration needs is not set. Whether
// an option is needed usually depends on other options, so it is checked in
// Validate rather than declared by a tag. flag is the option's flag name, or
// empty for a file-only option.
func (r *Report) Missing(path, flag string) {
	if flag == "" {
		r.Errorf(path, "required option is not set")
		return
	}
	r.Errorf(path, "required option is not set (--%v)", flag)
}

// Warnf records an option that is accepted but has no effect.
func (r *Report) Warnf(path, format string, args ...any) {
	r.warns = append(r.warns, prefix(r.Path(path), format, args...))
}

func prefix(path, format string, args ...any) string {
	msg := fmt.Sprintf(format, args...)
	if path == "" {
		return msg
	}
	return path + ": " + msg
}

func (r *Report) logWarnings() {
	for _, w := range r.warns {
		log.Warn(w)
	}
}

// err renders the collected errors as a single error, listing them one per
// line, or nil if there are none.
func (r *Report) err() error {
	if len(r.errs) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString("invalid configuration:")
	for _, e := range r.errs {
		b.WriteString("\n  ")
		b.WriteString(e)
	}
	return errors.New(b.String())
}

func (s *schema) validate(r *Report) {

	for _, f := range s.fields {

		allowed, err := f.allowed()
		if err != nil {
			r.Errorf(f.path, "%v", err)
			continue
		}
		if len(allowed) == 0 {
			continue
		}

		switch f.kind {
		case kindString:
			// An empty string is the option being unused, not a value
			if v := f.value.String(); v != "" && !slices.Contains(allowed, v) {
				r.Errorf(f.path, "%q is not one of %v", v, allowed)
			}
		case kindStringSlice:
			for i := range f.value.Len() {
				v := f.value.Index(i).String()
				if !slices.Contains(allowed, v) {
					r.Errorf(fmt.Sprintf("%v[%v]", f.path, i), "%q is not one of %v", v, allowed)
				}
			}
		}
	}

	for _, v := range s.validators {
		r.scope = v.path
		v.v.Validate(r)
	}
	r.scope = ""
}
