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
	"encoding/json"
	"fmt"
	"strings"

	jcs "github.com/Fraunhofer-AISEC/cmc/jsoncanonicalizer"
)

func GetConfigMeasurement(id string, configData []byte) ([]byte, []byte, error) {

	// The container id varies depending on the client. For ctr, this is a user-specified
	// name. For docker, this is a random UUID which changes on different container invocations
	// replace the id with a placeholder to enable reproducible configs
	shortId := id
	if len(id) > 12 {
		shortId = shortId[:12]
	}
	configString := string(configData)
	configString = strings.ReplaceAll(configString, id, "<container-id>")
	configString = strings.ReplaceAll(configString, shortId, "<container-id>")
	reproducibleConfig := []byte(configString)

	// Unmarshal the config for further modifications
	var config map[string]interface{}
	err := json.Unmarshal(reproducibleConfig, &config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal OCI runtime config: %w", err)
	}

	// Some values from the config, which are not security relevant and may change
	// on different container invocations will be ignored
	delete(config, "annotations")
	delete(config, "root")
	delete(config, "hooks")
	process, ok := config["process"].(map[string]interface{})
	if ok {
		delete(process, "terminal")
		delete(process, "consoleSize")
	}
	linux, ok := config["linux"].(map[string]interface{})
	if ok {
		delete(linux, "cgroupsPath")
	}

	data, err := json.Marshal(config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	// Transform to RFC 8785 canonical JSON form for reproducible hashing
	tbh, err := jcs.Transform(data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to cannonicalize json: %w", err)
	}

	hasher := sha256.New()
	hasher.Write(tbh)
	hash := hasher.Sum(nil)

	return hash, tbh, nil
}
