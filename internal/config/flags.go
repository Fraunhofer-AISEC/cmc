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
	"reflect"
	"strconv"
	"strings"

	"github.com/urfave/cli/v3"
)

// cliFlag builds the command line flag for a single option. Slices are
// string flags holding a comma-separated list, as they have always been.
func (f *field) cliFlag(d Dirs, hidden bool) cli.Flag {

	def := d.expand(f.def)

	usage := f.usage
	if allowed, err := f.allowed(); err == nil && len(allowed) > 0 {
		usage = strings.TrimSpace(usage + " [" + strings.Join(allowed, " ") + "]")
	}

	switch f.kind {
	case kindBool:
		return &cli.BoolFlag{
			Name:        f.flag,
			Usage:       usage,
			Category:    f.category,
			DefaultText: def,
			Hidden:      hidden,
		}
	case kindInt:
		return &cli.IntFlag{
			Name:        f.flag,
			Usage:       usage,
			Category:    f.category,
			DefaultText: def,
			Hidden:      hidden,
		}
	default:
		return &cli.StringFlag{
			Name:        f.flag,
			Usage:       usage,
			Category:    f.category,
			DefaultText: def,
			Hidden:      hidden,
		}
	}
}

// applyFlags overrides the configuration with the flags that were explicitly
// given on the command line.
func (s *schema) applyFlags(cmd *cli.Command, r *Report) {
	for _, f := range s.fields {
		if f.flag == "" || !cmd.IsSet(f.flag) {
			continue
		}

		var raw string
		switch f.kind {
		case kindBool:
			raw = strconv.FormatBool(cmd.Bool(f.flag))
		case kindInt:
			raw = strconv.Itoa(cmd.Int(f.flag))
		default:
			raw = cmd.String(f.flag)
		}

		if err := f.assign(raw); err != nil {
			r.Errorf(f.path, "--%v: %v", f.flag, err)
		}
	}
}

// sectionFilter returns a predicate selecting the options that live inside
// one of the given sections. Sections are matched by address rather than by
// name, so a section cannot be passed that does not belong to root.
func sectionFilter(s *schema, sections []any) func(*field) bool {

	if len(sections) == 0 {
		return func(*field) bool { return true }
	}

	type span struct{ lo, hi uintptr }
	spans := make([]span, 0, len(sections))

	for _, sec := range sections {
		v := reflect.ValueOf(sec)
		if v.Kind() != reflect.Pointer || v.IsNil() || v.Elem().Kind() != reflect.Struct {
			panicf("section must be a non-nil pointer to a struct, got %T", sec)
		}
		size := v.Elem().Type().Size()
		if size == 0 {
			panicf("section %v is empty", v.Elem().Type())
		}
		spans = append(spans, span{v.Pointer(), v.Pointer() + size})
	}

	rootLo := s.root.Addr().Pointer()
	rootHi := rootLo + s.root.Type().Size()
	for _, sp := range spans {
		if sp.lo < rootLo || sp.hi > rootHi {
			panicf("section is not part of the configuration struct %v", s.root.Type())
		}
	}

	return func(f *field) bool {
		a := f.value.Addr().Pointer()
		for _, sp := range spans {
			if a >= sp.lo && a < sp.hi {
				return true
			}
		}
		return false
	}
}
