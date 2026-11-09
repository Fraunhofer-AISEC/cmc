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
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
)

// Dirs are the standard directories of a binary. They follow the FHS when
// running as root and the XDG base directory specification otherwise.
type Dirs struct {
	// Config holds the config files of all binaries
	Config string
	// Data holds the persistent data of this binary only
	Data string
	// Run holds runtime files shared by all binaries, such as sockets
	Run string

	root bool
}

// baseDirs is the binary-independent part of the standard directories,
// computed once per process.
var baseDirs = sync.OnceValue(func() Dirs {
	return dirsFrom(os.Geteuid() == 0, os.Getenv, homeDir())
})

// DirsOf returns the standard directories of the binary name.
func DirsOf(name string) Dirs {
	d := baseDirs()
	d.Data = filepath.Join(d.Data, name)
	return d
}

// dirsFrom computes the directories without the binary name, so Data is the
// parent of the per-binary data folders.
func dirsFrom(root bool, getenv func(string) string, home string) Dirs {

	if root {
		return Dirs{Config: "/etc/cmc", Data: "/var/lib/cmc", Run: "/run/cmc", root: true}
	}

	// The specification asks to ignore relative values
	xdg := func(name, fallback string) string {
		if v := getenv(name); filepath.IsAbs(v) {
			return v
		}
		return filepath.Join(home, fallback)
	}

	data := xdg("XDG_DATA_HOME", ".local/share")
	run := filepath.Join(data, "cmc", "run")
	if v := getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(v) {
		run = filepath.Join(v, "cmc")
	}

	return Dirs{
		Config: filepath.Join(xdg("XDG_CONFIG_HOME", ".config"), "cmc"),
		Data:   filepath.Join(data, "cmc"),
		Run:    run,
	}
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return ""
}

// Create creates the directories the binary writes to, readable by everyone
// for root and private otherwise.
func (d Dirs) Create() error {
	mode := os.FileMode(0700)
	if d.root {
		mode = 0755
	}
	for _, dir := range []string{d.Data, d.Run} {
		if err := os.MkdirAll(dir, mode); err != nil {
			return fmt.Errorf("failed to create %v: %w", dir, err)
		}
	}
	return nil
}

// expand replaces the placeholders {config}, {data} and {run} in a default
// tag with the directories.
func (d Dirs) expand(s string) string {
	if !strings.Contains(s, "{") {
		return s
	}
	return strings.NewReplacer("{config}", d.Config, "{data}", d.Data, "{run}", d.Run).Replace(s)
}
