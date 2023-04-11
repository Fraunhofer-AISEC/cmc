// Copyright (c) 2021 Fraunhofer AISEC
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

package internal

// Install github packages with "go get [url]"
import (
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "internal")

// Tries to retrieve a file from an absolute path, or path relative to
// the running binary or the optional base path
func GetFile(file string, base *string) ([]byte, error) {
	if file == "" {
		return nil, fmt.Errorf("empty filename passed")
	}
	f, err := GetFilePath(file, base)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %v: %v", f, err)
	}
	return data, nil
}

// Tries to retrieve a filepath from an absolute path, or path relative to
// the running binary or the optional base path
func GetFilePath(file string, base *string) (string, error) {

	if base != nil {
		log.Tracef("Get path of '%v' with optional base path '%v'", file, *base)
	} else {
		log.Tracef("Get path of '%v'", file)
	}

	// Search for the absolute path
	if path.IsAbs(file) && FileExists(file) {
		log.Tracef("Got: %v (absolute path)", file)
		return file, nil
	}

	// Search relative to the given base path
	var rf string
	var err error
	if base != nil {
		rf, err = filepath.Abs(filepath.Join(*base, file))
		if err == nil {
			if FileExists(rf) {
				log.Tracef("Got: %v (relative to base path)", rf)
				return rf, nil
			}
		}
	}

	// Search relative to the running binary
	bin, err := GetBinaryPath()
	if err != nil {
		return "", err
	}
	f, err := filepath.Abs(filepath.Join(bin, file))
	if err == nil {
		if FileExists(f) {
			log.Tracef("Got: %v (relative to binary)", f)
			return f, nil
		}
	}

	if base == nil {
		return "", fmt.Errorf("failed to find file. Places searched: %v, %v", file, f)
	}

	return "", fmt.Errorf("failed to find file. Places searched: %v, %v, %v", file, rf, f)
}

func Contains(elem string, list []string) bool {
	for _, s := range list {
		if strings.EqualFold(s, elem) {
			return true
		}
	}
	return false
}

func FileExists(f string) bool {
	if _, err := os.Stat(f); err == nil {
		return true
	}
	return false
}

func GetBinaryPath() (string, error) {
	bin, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get path of executable: %w", err)
	}
	d := filepath.Dir(bin)
	return d, nil
}

func FlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func IsDir(p string) (bool, error) {
	info, err := os.Stat(p)
	if err != nil {
		return false, fmt.Errorf("failed to get file info: %w", err)
	}

	return info.IsDir(), nil
}
