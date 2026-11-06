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

// Package config derives command line flags, defaults, validation and the printed configuration
// from a tagged struct. Each configuration value supports the following struct tags:
//
//  json      key in the config file.
//  flag      flag name. Flag:"-" marks an option that can only be set in a config file.
//  usage     flag help text.
//  default   value applied before config files and flags are read, and shown in --help.
//  enum      comma-separated allowed values. A value of the form "@name" resolves against the
//            registry filled by RegisterEnum, so it can respect build tags.
//  path      a relative value coming from a config file is resolved against that file's directory.
//            Values coming from a flag are not modigied. path:"uri" resolves the path of a file:// URI
//  secret    the value is redacted by Redacted
//
// A section may carry a category tag, which sets the group the section's flags appear under in
// --help. It defaults to the upper-cased section key. A category of "-" makes the section
// transparent: it groups nothing itself, so each of its subsections introduces its own category
// again.
//
// Values are applied in the order defaults, config files in the order given by --config, then the
// flags that were explicitly set.
package config

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

// FileFlagName is the name of the flag listing the config files to load.
const FileFlagName = "config"

// FileFlag returns the flag that Load reads the config file list from. It
// returns a new flag on every call, so that it can be attached to more than
// one command.
func FileFlag() cli.Flag {
	return &cli.StringFlag{
		Name:  FileFlagName,
		Usage: "comma-separated JSON configuration files, later files take precedence",
	}
}

// Load fills root, which must be a non-nil pointer to a tagged configuration
// struct, from the default tags, the config files listed by --config and the
// flags that were explicitly set, in that order, and validates the result.
//
// Every problem is reported in a single error. Warnings are logged. Load does
// not touch anything outside root and the config files it reads, so it is
// safe to call just to check a configuration.
//
// Load panics if root is not a well-formed configuration struct, as that is a
// programming error rather than a configuration error.
func Load(cmd *cli.Command, root any) error {

	s := newSchema(root)
	r := &Report{}

	s.applyDefaults()
	for _, file := range splitList(cmd.String(FileFlagName)) {
		s.applyFile(file, r)
	}

	// A config file that could not be applied makes every later check report
	// a value that was never really configured, so stop before validation
	// rather than burying the actual problem in follow-up errors
	if len(r.errs) == 0 {
		s.applyFlags(cmd, r)
		s.validate(r)
	}

	for _, w := range r.warns {
		log.Warn(w)
	}

	return r.err()
}

// Flags derives the command line flags from the tagged struct root. If
// sections is given, only the flags of those sections are returned; every
// section must be a pointer to a struct field of root. Leaves tagged
// flag:"-" are skipped.
//
// The returned flags do not include FileFlag, so that a command can decide
// where to attach it.
func Flags(root any, sections ...any) []cli.Flag {
	return flagsFor(root, false, sections)
}

// HiddenFlags is Flags for options that stay accepted on the command line but
// are left out of --help, because they have no effect in the mode the binary
// was started in. Whether they apply is a property of the invocation rather
// than of the struct, so it cannot be a tag.
func HiddenFlags(root any, sections ...any) []cli.Flag {
	return flagsFor(root, true, sections)
}

func flagsFor(root any, hidden bool, sections []any) []cli.Flag {

	s := newSchema(root)
	selected := sectionFilter(s, sections)

	flags := make([]cli.Flag, 0, len(s.fields))
	for _, f := range s.fields {
		if f.flag == "" || !selected(f) {
			continue
		}
		flags = append(flags, f.cliFlag(hidden))
	}

	return flags
}

func panicf(format string, args ...any) {
	panic(fmt.Sprintf("config: "+format, args...))
}
