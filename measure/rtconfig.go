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

func GetSpecMeasurement(id string, configData []byte) ([]byte, []byte, string, error) {

	normalizedConfig, rootfs, err := normalize(id, configData)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to normalize config: %w", err)
	}

	hasher := sha256.New()
	hasher.Write(normalizedConfig)
	hash := hasher.Sum(nil)

	return hash, normalizedConfig, rootfs, nil
}

func normalize(id string, configData []byte) ([]byte, string, error) {

	// The container id varies depending on the client. For ctr, this is a user-specified
	// name. For docker, this is a random UUID which changes on different container invocations
	// replace the id with a placeholder to enable reproducible configs
	shortId := id
	if len(id) > 12 {
		shortId = shortId[:12]
	}
	configString := string(configData)

	// TODO check the security relevance of every manipulated OCI runtime config bundle property

	// Replace container-ID which is a random UUID that varies between each start of the same container
	configString = strings.ReplaceAll(configString, id, "<container-id>")
	configString = strings.ReplaceAll(configString, shortId, "<container-id>")
	reproducibleConfig := []byte(configString)

	// Unmarshal the config for further modifications
	var config specs.Spec
	err := json.Unmarshal(reproducibleConfig, &config)
	if err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal OCI runtime config: %w", err)
	}

	// Make the docker prestart hooks reproducible
	// The prestart path (proc/<pid>/exe) is a symlink to the docker daemon
	if config.Hooks != nil {
		//lint:ignore SA1019 still needed for old configs
		for i := range config.Hooks.Prestart {
			//lint:ignore SA1019 still needed for old configs
			config.Hooks.Prestart[i].Path, err = filepath.EvalSymlinks(config.Hooks.Prestart[i].Path)
			if err != nil {
				return nil, "", fmt.Errorf("failed to evaluate dockerd symlink: %w", err)
			}

			// TODO FIXME The docker network controller ID is generated randomly (github.com/moby/moby/libnetwork/controller.go:New())
			// and then the truncated daemon.netController.ID() is added as an argument in the prestart
			// hooks (github.com/moby/moby/daemon/oci_linux.go:withLibnetwork()). This is a very hacky
			// way to make it reproducible, ideally, the actual network ID controller ID should be
			// retrieved and then replaced
			//lint:ignore SA1019 still needed for old configs
			for j := range config.Hooks.Prestart[i].Args {
				//lint:ignore SA1019 still needed for old configs
				if len(config.Hooks.Prestart[i].Args[j]) == 12 && isHex(config.Hooks.Prestart[i].Args[j]) {
					//lint:ignore SA1019 still needed for old configs
					config.Hooks.Prestart[i].Args[j] = "<docker-network-controller-id>"
				}
			}
		}
	}

	// Some values from the config, which are not security relevant and may change
	// on different container invocations will be ignored
	// TODO FIXME check all properties for security relevance , currently experimental
	config.Annotations = nil
	config.Process.Terminal = false
	config.Process.ConsoleSize = nil

	// Some container engines such as docker store the rootfs in an non-reproducible
	// path. Therefore we store the path and hash the rootfs at this path, but remove the
	// path from the config.json.
	if config.Root == nil {
		return nil, "", fmt.Errorf("invalid OCI config: no rootfs specified")
	}
	rootfs := config.Root.Path
	config.Root = nil

	// List environment variables alphabetically to guarantee reproducibility
	slices.Sort(config.Process.Env)

	// List mounts alphabetically to guarantee reproducibility
	sort.Slice(config.Mounts, func(i, j int) bool {
		if config.Mounts[i].Source == config.Mounts[j].Source {
			return config.Mounts[i].Destination < config.Mounts[j].Destination
		}
		return config.Mounts[i].Source < config.Mounts[j].Source
	})

	data, err := json.Marshal(config)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal config: %w", err)
	}

	// Transform to RFC 8785 canonical JSON form for reproducible hashing
	tbh, err := jcs.Transform(data)
	if err != nil {
		return nil, "", fmt.Errorf("failed to cannonicalize json: %w", err)
	}

	return tbh, rootfs, nil
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}
