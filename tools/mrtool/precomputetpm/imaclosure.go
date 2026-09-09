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

package precomputetpm

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Maximum number of symlink hops before a chain is considered a loop
const maxSymlinkHops = 40

// imaClosure returns the transitive shared library closure of seeds, restricted to files inside
// roots. Objects loaded via dlopen() are not covered and must be named explicitly via --ima-path.
func imaClosure(roots, seeds []string) ([]string, error) {

	if len(roots) == 0 {
		return nil, fmt.Errorf("--ima-seed needs at least one directory in --ima-path to resolve against")
	}

	index, err := buildElfIndex(roots)
	if err != nil {
		return nil, fmt.Errorf("failed to index ELF objects: %w", err)
	}
	log.Debugf("Indexed %v distinct ELF object name(s) in %v tree(s)", len(index), len(roots))

	// IMA records the path the kernel resolved, not the one that was typed. Resolve the seeds
	// the same way.
	queue := make([]string, 0, len(seeds))
	for _, seed := range seeds {
		root, err := enclosingRoot(roots, seed)
		if err != nil {
			return nil, err
		}
		real, err := resolveInRoot(root, seed)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve seed %q: %w", seed, err)
		}
		queue = append(queue, real)
	}

	visited := make(map[string]struct{})
	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]

		if _, done := visited[path]; done {
			continue
		}
		visited[path] = struct{}{}

		for _, name := range importedNames(path) {
			candidates, ok := index[name]
			if !ok {
				// Not fatal, as the object might be provided by a tree that was not indexed
				log.Warnf("no file named %q in the indexed trees, required by %q", name, path)
				continue
			}
			queue = append(queue, candidates...)
		}
	}

	closure := make([]string, 0, len(visited))
	for path := range visited {
		closure = append(closure, path)
	}
	sort.Strings(closure)

	return closure, nil
}

// buildElfIndex maps every name an ELF object can be requested under to the real files that satisfy
// it. Symlinks are indexed under their own name pointing at their target, as a DT_NEEDED entry
// names a soname while the file that gets mapped and measured is the versioned real file behind it.
func buildElfIndex(roots []string) (map[string][]string, error) {

	seen := make(map[string]map[string]struct{})
	add := func(name, path string) {
		if _, ok := seen[name]; !ok {
			seen[name] = make(map[string]struct{})
		}
		seen[name][path] = struct{}{}
	}

	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Debugf("error accessing %q: %v", path, err)
				return nil
			}

			switch {
			case info.Mode().IsRegular():
				if hasElfMagic(path) {
					add(filepath.Base(path), path)
				}

			case info.Mode()&os.ModeSymlink != 0:
				real, err := resolveInRoot(root, path)
				if err != nil {
					log.Tracef("skipping symlink %q: %v", path, err)
					return nil
				}
				target, err := os.Stat(real)
				if err != nil || !target.Mode().IsRegular() || !hasElfMagic(real) {
					return nil
				}
				add(filepath.Base(path), real)
			}

			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("error walking the path %q: %w", root, err)
		}
	}

	index := make(map[string][]string, len(seen))
	for name, paths := range seen {
		list := make([]string, 0, len(paths))
		for path := range paths {
			list = append(list, path)
		}
		sort.Strings(list)
		index[name] = list
	}

	return index, nil
}

// importedNames returns the names path needs mapped alongside it: its DT_NEEDED entries and, for a
// dynamically linked executable, its interpreter. A file that is not an ELF object needs nothing
// and is not an error.
func importedNames(path string) []string {

	f, err := elf.Open(path)
	if err != nil {
		log.Tracef("not an ELF object, no dependencies: %q (%v)", path, err)
		return nil
	}
	defer f.Close()

	names, err := f.ImportedLibraries()
	if err != nil {
		log.Warnf("failed to read the dynamic section of %q: %v", path, err)
		names = nil
	}

	for _, prog := range f.Progs {
		if prog.Type != elf.PT_INTERP {
			continue
		}
		buf := make([]byte, prog.Filesz)
		if _, err := prog.ReadAt(buf, 0); err != nil {
			log.Warnf("failed to read PT_INTERP of %q: %v", path, err)
			break
		}
		if interp := string(bytes.TrimRight(buf, "\x00")); interp != "" {
			names = append(names, interp)
		}
	}

	// A DT_NEEDED entry is normally a bare soname, but may contain a slash, and PT_INTERP always
	// does. The index is keyed by basename either way
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, filepath.Base(name))
	}

	return out
}

// enclosingRoot returns the root the path lives under, which absolute symlink targets inside the
// tree are relative to
func enclosingRoot(roots []string, path string) (string, error) {
	for _, root := range roots {
		if isInRoot(root, path) {
			return root, nil
		}
	}
	return "", fmt.Errorf("%q is not inside any directory given to --ima-path", path)
}

func isInRoot(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

// resolveInRoot resolves path the way the guest kernel would: every component is followed, and an
// absolute symlink target is taken relative to root rather than to the host filesystem.
func resolveInRoot(root, path string) (string, error) {

	root = filepath.Clean(root)

	rel, err := filepath.Rel(root, filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("%q is not inside %q: %w", path, root, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%q is not inside %q", path, root)
	}

	cur := root
	rest := strings.Split(rel, string(filepath.Separator))
	hops := 0

	for len(rest) > 0 {
		name := rest[0]
		rest = rest[1:]

		switch name {
		case "", ".":
			continue
		case "..":
			// Clamp at the root, like a chroot: ".." in "/" is "/"
			if cur != root {
				cur = filepath.Dir(cur)
			}
			continue
		}

		next := filepath.Join(cur, name)
		info, err := os.Lstat(next)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			cur = next
			continue
		}

		hops++
		if hops > maxSymlinkHops {
			return "", fmt.Errorf("symlink chain from %q is longer than %v hops", path, maxSymlinkHops)
		}

		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			cur = root
			target = strings.TrimPrefix(target, string(filepath.Separator))
		}
		rest = append(strings.Split(target, string(filepath.Separator)), rest...)
	}

	return cur, nil
}
