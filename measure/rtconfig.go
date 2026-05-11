// Copyright (c) 2024 Fraunhofer AISEC
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

package measure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/opencontainers/runtime-spec/specs-go"

	jcs "github.com/Fraunhofer-AISEC/cmc/jsoncanonicalizer"
)

func derefInt64(p *int64) int64 {
	if p == nil {
		return -1
	}
	return *p
}

func GetRootfsPath(configRaw []byte) (string, error) {
	var config specs.Spec
	if err := json.Unmarshal(configRaw, &config); err != nil {
		return "", fmt.Errorf("failed to unmarshal original OCI runtime config: %w", err)
	}
	if config.Root == nil {
		return "", fmt.Errorf("invalid OCI config: no rootfs specified")
	}

	return config.Root.Path, nil
}

func GetSpecMeasurement(id string, configRaw []byte) ([]byte, []byte, error) {

	normalizedConfig, err := Normalize(id, configRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to normalize config: %w", err)
	}

	hasher := sha256.New()
	hasher.Write(normalizedConfig)
	hash := hasher.Sum(nil)

	return hash, normalizedConfig, nil
}

func Normalize(id string, configRaw []byte) ([]byte, error) {

	// The container id varies depending on the client. For ctr, this is a user-specified
	// name. For docker, this is a random UUID which changes on different container invocations
	// replace the id with a placeholder to enable reproducible configs
	shortId := id
	if len(id) > 12 {
		shortId = shortId[:12]
	}
	configString := string(configRaw)

	// TODO check the security relevance of every manipulated OCI runtime config bundle property

	// Replace container-ID which is a random UUID that varies between each start of the same container
	configString = strings.ReplaceAll(configString, id, "<container-id>")
	configString = strings.ReplaceAll(configString, shortId, "<container-id>")
	reproducibleConfig := []byte(configString)

	// Unmarshal the config for further modifications
	var config specs.Spec
	err := json.Unmarshal(reproducibleConfig, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal OCI runtime config: %w", err)
	}

	// Make the docker prestart hooks reproducible
	// The prestart path (proc/<pid>/exe) is a symlink to the docker daemon
	if config.Hooks != nil {
		//lint:ignore SA1019 still needed for old configs
		for i := range config.Hooks.Prestart {
			//lint:ignore SA1019 still needed for old configs
			config.Hooks.Prestart[i].Path, err = filepath.EvalSymlinks(config.Hooks.Prestart[i].Path)
			if err != nil {
				return nil, fmt.Errorf("failed to evaluate dockerd symlink: %w", err)
			}

			// TODO FIXME The docker network controller ID is generated randomly (github.com/moby/moby/libnetwork/controller.go:New())
			// and then the truncated daemon.netController.ID() is added as an argument in the prestart
			// hooks (github.com/moby/moby/daemon/oci_linux.go:withLibnetwork()). This is a very hacky
			// way to make it reproducible
			//lint:ignore SA1019 still needed for old configs
			args := config.Hooks.Prestart[i].Args
			if len(args) >= 4 && args[0] == "libnetwork-setkey" && len(args[3]) == 12 && isHex(args[3]) {
				//lint:ignore SA1019 still needed for old configs
				config.Hooks.Prestart[i].Args[3] = "<docker-network-controller-id>"
			}
		}
	}

	// The hostname is the hostname seen from inside the container and cannot be predicted
	config.Hostname = ""

	// Some values from the config, which are not security relevant and may change
	// on different container invocations will be ignored
	// TODO FIXME check all properties for security relevance, currently experimental
	config.Annotations = nil
	config.Process.Terminal = false
	config.Process.ConsoleSize = nil

	// Some container engines such as docker store the rootfs in a non-reproducible
	// path. Therefore we store the path and hash the rootfs at this path, but remove the
	// path from the config.json.
	config.Root = nil

	// List environment variables alphabetically to guarantee reproducibility
	slices.Sort(config.Process.Env)

	// Docker-volume source paths (anonymous and named) contain
	// non-deterministic components and can be normalized, as this is Dockercan -internal
	// storage, as they start empty.
	for i := range config.Mounts {
		if strings.HasPrefix(config.Mounts[i].Source, "/var/lib/docker/volumes/") {
			config.Mounts[i].Source = "<docker-volume>"
		}
	}

	// List mounts alphabetically to guarantee reproducibility
	sort.Slice(config.Mounts, func(i, j int) bool {
		if config.Mounts[i].Source == config.Mounts[j].Source {
			return config.Mounts[i].Destination < config.Mounts[j].Destination
		}
		return config.Mounts[i].Source < config.Mounts[j].Source
	})

	// Sort linux arrays alphabetically
	if config.Linux != nil {
		slices.Sort(config.Linux.MaskedPaths)
		slices.Sort(config.Linux.ReadonlyPaths)
		sort.Slice(config.Linux.Namespaces, func(i, j int) bool {
			return config.Linux.Namespaces[i].Type < config.Linux.Namespaces[j].Type
		})
		if config.Linux.Resources != nil {
			sort.Slice(config.Linux.Resources.Devices, func(i, j int) bool {
				if config.Linux.Resources.Devices[i].Type != config.Linux.Resources.Devices[j].Type {
					return config.Linux.Resources.Devices[i].Type < config.Linux.Resources.Devices[j].Type
				}
				mi, mj := derefInt64(config.Linux.Resources.Devices[i].Major), derefInt64(config.Linux.Resources.Devices[j].Major)
				if mi != mj {
					return mi < mj
				}
				return derefInt64(config.Linux.Resources.Devices[i].Minor) < derefInt64(config.Linux.Resources.Devices[j].Minor)
			})
		}
		if config.Linux.Seccomp != nil {
			slices.Sort(config.Linux.Seccomp.Architectures)
			slices.Sort(config.Linux.Seccomp.Flags)
			for i := range config.Linux.Seccomp.Syscalls {
				slices.Sort(config.Linux.Seccomp.Syscalls[i].Names)
			}
			sort.Slice(config.Linux.Seccomp.Syscalls, func(i, j int) bool {
				ni := strings.Join(config.Linux.Seccomp.Syscalls[i].Names, ",")
				nj := strings.Join(config.Linux.Seccomp.Syscalls[j].Names, ",")
				if ni != nj {
					return ni < nj
				}
				return config.Linux.Seccomp.Syscalls[i].Action < config.Linux.Seccomp.Syscalls[j].Action
			})
		}
	}
	if config.Process.Capabilities != nil {
		slices.Sort(config.Process.Capabilities.Bounding)
		slices.Sort(config.Process.Capabilities.Effective)
		slices.Sort(config.Process.Capabilities.Inheritable)
		slices.Sort(config.Process.Capabilities.Permitted)
		slices.Sort(config.Process.Capabilities.Ambient)
	}

	data, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	// Transform to RFC 8785 canonical JSON form for reproducible hashing
	tbh, err := jcs.Transform(data)
	if err != nil {
		return nil, fmt.Errorf("failed to cannonicalize json: %w", err)
	}

	return tbh, nil
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}
