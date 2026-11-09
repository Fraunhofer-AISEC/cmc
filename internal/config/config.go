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
//	toml      key in the config file.
//	flag      flag name. Flag:"-" marks an option that can only be set in a config file.
//	usage     flag help text.
//	default   value applied before config files and flags are read, and shown in --help. The
//	          placeholders {config}, {data} and {run} expand to the directories of DirsOf.
//	enum      comma-separated allowed values. A value of the form "@name" resolves against the
//	          registry filled by RegisterEnum, so it can respect build tags.
//	path      a relative value coming from a config file is resolved against that file's directory.
//	          Values coming from a flag are not modified. path:"uri" resolves the path of a file:// URI
//	secret    the value is redacted by Redacted
//
// A section may carry a category tag, which sets the group the section's flags appear under in
// --help. It defaults to the upper-cased section key. A category of "-" makes the section
// transparent: it groups nothing itself, so each of its subsections introduces its own category
// again.
//
// Values are applied in the order defaults, config files, then the flags that were explicitly set.
// The config files are those given by --config in that order. Without --config, the default file
// {config}/<binary>.toml is used if it exists.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

// FileFlagName is the name of the flag listing the config files to load.
const FileFlagName = "config"

// FileFlag returns the flag that Load reads the config file list from, with
// the default file of the binary name as default text. It returns a new flag
// on every call, so that it can be attached to more than one command.
func FileFlag(name string) cli.Flag {
	return &cli.StringFlag{
		Name:        FileFlagName,
		Usage:       "comma-separated TOML configuration files, later files take precedence",
		DefaultText: DefaultFile(name) + ", if it exists",
	}
}

// DefaultFile returns the config file of the binary name that is used when
// --config is not given.
func DefaultFile(name string) string {
	return filepath.Join(DirsOf(name).Config, name+".toml")
}

// Files returns the config files Load applies for the binary name: those
// listed by --config, or else the default file if it exists. An empty
// --config disables the default file.
func Files(cmd *cli.Command, name string) []string {
	if cmd.IsSet(FileFlagName) {
		return SplitList(cmd.String(FileFlagName))
	}
	return defaultFiles(name)
}

// defaultFiles returns the default file of the binary name, or nothing if it
// does not exist. Any other error keeps the file, so that loading reports it.
func defaultFiles(name string) []string {
	file := DefaultFile(name)
	if _, err := os.Stat(file); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return []string{file}
}

// Load fills root, which must be a non-nil pointer to a tagged configuration
// struct of the binary name, from the default tags, the config files returned by Files and the
// flags that were explicitly set, in that order, and validates the result.
//
// Every problem is reported in a single error. Warnings are logged. Load does
// not touch anything outside root and the config files it reads, so it is
// safe to call just to check a configuration.
//
// Load panics if root is not a well-formed configuration struct, as that is a
// programming error rather than a configuration error.
func Load(cmd *cli.Command, name string, root any) error {

	s := newSchema(root)
	r := &Report{}

	s.applyDefaults(DirsOf(name))
	for _, file := range Files(cmd, name) {
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

// New allocates a configuration of type T and loads it with Load. T must be a
// struct type that Load accepts a pointer to.
func New[T any](cmd *cli.Command, name string) (*T, error) {
	c := new(T)
	if err := Load(cmd, name, c); err != nil {
		return nil, err
	}
	return c, nil
}

// AllFlags returns FileFlag followed by the flags of every option of root of
// the binary name, for a command that accepts the whole configuration. A fresh set is built per
// call, as a flag carries the state of the command it is parsed for and must
// not be shared between commands.
func AllFlags(name string, root any) []cli.Flag {
	return append([]cli.Flag{FileFlag(name)}, Flags(name, root)...)
}

// Flags derives the command line flags from the tagged struct root of the
// binary name, which determines the directories shown in defaults. If
// sections is given, only the flags of those sections are returned; every
// section must be a pointer to a struct field of root. Leaves tagged
// flag:"-" are skipped.
//
// The returned flags do not include FileFlag, so that a command can decide
// where to attach it.
func Flags(name string, root any, sections ...any) []cli.Flag {
	return flagsFor(name, root, false, sections)
}

// HiddenFlags is Flags for options that stay accepted on the command line but
// are left out of --help, because they have no effect in the mode the binary
// was started in. Whether they apply is a property of the invocation rather
// than of the struct, so it cannot be a tag.
func HiddenFlags(name string, root any, sections ...any) []cli.Flag {
	return flagsFor(name, root, true, sections)
}

func flagsFor(name string, root any, hidden bool, sections []any) []cli.Flag {

	d := DirsOf(name)
	s := newSchema(root)
	selected := sectionFilter(s, sections)

	flags := make([]cli.Flag, 0, len(s.fields))
	for _, f := range s.fields {
		if f.flag == "" || !selected(f) {
			continue
		}
		flags = append(flags, f.cliFlag(d, hidden))
	}

	return flags
}

func panicf(format string, args ...any) {
	panic(fmt.Sprintf("config: "+format, args...))
}
