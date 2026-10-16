// Copyright (c) 2021 - 2026 Fraunhofer AISEC
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

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// version and commit can be set at link time for builds without version control
// information, e.g.,
//
//	go build -ldflags="\
//	  -X github.com/Fraunhofer-AISEC/cmc/internal.version=v1.2.3 \
//	  -X github.com/Fraunhofer-AISEC/cmc/internal.commit=0da672df7cc9add72b8ed46fa02e613893d79574"
//
// If unset, both values are taken from the Go build information.
var (
	version string
	commit  string
)

const unknown = "unknown"

// VersionInfo contains the build information of the binary
type VersionInfo struct {
	Version   string
	Commit    string
	Built     string
	GoVersion string
	Platform  string
}

// GetVersionInfo returns the build information of the binary, taken from the
// link time variables if set and from the Go build information otherwise
func GetVersionInfo() VersionInfo {
	v := VersionInfo{
		Version:   version,
		Commit:    commit,
		GoVersion: runtime.Version(),
		Platform:  fmt.Sprintf("%v/%v", runtime.GOOS, runtime.GOARCH),
	}

	if info, ok := debug.ReadBuildInfo(); ok {
		// Go reports "(devel)" if the binary was built without version control
		// information, in which case it carries no useful version at all
		if v.Version == "" && !strings.EqualFold(info.Main.Version, "(devel)") {
			v.Version = info.Main.Version
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if v.Commit == "" {
					v.Commit = s.Value
				}
			case "vcs.time":
				v.Built = s.Value
			}
		}
	}

	if v.Version == "" {
		v.Version = unknown
	}
	if v.Commit == "" {
		v.Commit = unknown
	}
	if v.Built == "" {
		v.Built = unknown
	}

	return v
}

func (v VersionInfo) String() string {
	return fmt.Sprintf("%v, commit %v, built %v, %v %v",
		v.Version, v.Commit, v.Built, v.GoVersion, v.Platform)
}

// GetVersion returns the plain version of the binary without further build
// information. Use GetVersionInfo to report the full build information.
func GetVersion() string {
	return GetVersionInfo().Version
}
