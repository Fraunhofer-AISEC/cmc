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
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v3"
)

// Command returns the "config" subcommand of the binary name with the
// validate, print and init subcommands for the root configuration type T.
// The subcommands inherit the flags of the parent command. If flags is not
// nil, it returns the configuration flags the parent does not have, and is
// called once per subcommand, as a flag must not be shared between commands.
func Command[T any](name string, flags func() []cli.Flag) *cli.Command {

	own := func(extra ...cli.Flag) []cli.Flag {
		if flags == nil {
			return extra
		}
		return append(flags(), extra...)
	}
	minimal := func() cli.Flag {
		return &cli.BoolFlag{Name: "minimal", Usage: "only write the options that differ from their default"}
	}

	return &cli.Command{
		Name:  "config",
		Usage: "Inspect or write the configuration",
		Commands: []*cli.Command{
			{
				Name:  "validate",
				Usage: "Load and validate the configuration, exit code 0 if it is valid",
				Flags: own(),
				Action: func(_ context.Context, cmd *cli.Command) error {
					if _, err := New[T](cmd, name); err != nil {
						return err
					}
					fmt.Fprintln(cmd.Root().Writer, "configuration is valid")
					return nil
				},
			},
			{
				Name:  "print",
				Usage: "Print the effective configuration, with secrets redacted",
				Flags: own(minimal()),
				Action: func(_ context.Context, cmd *cli.Command) error {
					c, err := New[T](cmd, name)
					if err != nil {
						return err
					}
					s, err := newSchema(c).render(DirsOf(name), writeOpts{
						annotate: true,
						minimal:  cmd.Bool("minimal"),
						redact:   true,
					})
					if err != nil {
						return err
					}
					fmt.Fprintln(cmd.Root().Writer, s)
					return nil
				},
			},
			{
				Name: "init",
				Usage: fmt.Sprintf("Write the configuration made of the defaults, the files given by --%v "+
					"and the given flags to %v", FileFlagName, DefaultFile(name)),
				Flags: own(
					minimal(),
					&cli.StringFlag{
						Name:        "output",
						Usage:       "file to write to, - for stdout",
						DefaultText: DefaultFile(name),
					},
					&cli.BoolFlag{
						Name:  "force",
						Usage: "overwrite an existing file, and write even an invalid configuration",
					},
				),
				Action: func(_ context.Context, cmd *cli.Command) error {
					return initConfig[T](cmd, name)
				},
			},
		},
	}
}

// initConfig implements config init. Unlike the other commands, it does not
// read the default file unless --config names it, so that it can create the
// file from scratch.
func initConfig[T any](cmd *cli.Command, name string) error {

	out := DefaultFile(name)
	if cmd.IsSet("output") {
		out = cmd.String("output")
	}
	force := cmd.Bool("force")

	if out != "-" && !force {
		if _, err := os.Stat(out); err == nil {
			return fmt.Errorf("%v already exists, use --force to overwrite it", out)
		}
	}

	var files []string
	if cmd.IsSet(FileFlagName) {
		files = SplitList(cmd.String(FileFlagName))
	}

	d := DirsOf(name)
	s := newSchema(new(T))
	r := &Report{}
	if !s.load(cmd, d, files, r) {
		return r.err()
	}
	r.logWarnings()
	if err := r.err(); err != nil {
		if !force {
			return fmt.Errorf("%w\nnothing written, use --force to write it anyway", err)
		}
		fmt.Fprintf(cmd.Root().ErrWriter, "%v\nwriting it anyway because of --force\n", err)
	}

	// A relative path from a flag is relative to the working directory, and
	// one from a file is relative to that file, which may lie elsewhere than
	// the written file. Either way it must not be resolved against the
	// written file, so the options that are written as active lines are made
	// absolute. Relative defaults are written commented out and keep their
	// meaning.
	if err := s.absPaths(d); err != nil {
		return err
	}

	content, err := s.render(d, writeOpts{annotate: true, minimal: cmd.Bool("minimal")})
	if err != nil {
		return err
	}
	content += "\n"

	if out == "-" {
		_, err := io.WriteString(cmd.Root().Writer, content)
		return err
	}
	if err := writeFile(out, content, d.root, force); err != nil {
		return err
	}
	fmt.Fprintf(cmd.Root().ErrWriter, "wrote %v\n", out)
	return nil
}

// absPaths makes every relative path value absolute against the working
// directory, unless the option is at its default.
func (s *schema) absPaths(d Dirs) error {

	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	defaults := s.defaults(d)
	for _, f := range s.fields {
		if f.isPath && !equalValues(f.value, defaults.byPath[f.path].value) {
			resolvePaths(f.value, wd, f.isUri)
		}
	}
	return nil
}

// writeFile writes the user's own config file, which may hold secrets, with
// mode 0600, creating the parent directory with the mode Dirs.Create uses.
func writeFile(file, content string, root, force bool) error {

	mode := os.FileMode(0700)
	if root {
		mode = 0755
	}
	if err := os.MkdirAll(filepath.Dir(file), mode); err != nil {
		return fmt.Errorf("failed to create the directory of %v: %w", file, err)
	}

	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(file, flags, 0600)
	if err != nil {
		return fmt.Errorf("failed to write %v: %w", file, err)
	}
	// An existing file keeps its mode on open
	err = errors.Join(f.Chmod(0600), writeAll(f, content), f.Close())
	if err != nil {
		return fmt.Errorf("failed to write %v: %w", file, err)
	}
	return nil
}

func writeAll(w io.Writer, s string) error {
	_, err := io.WriteString(w, s)
	return err
}
