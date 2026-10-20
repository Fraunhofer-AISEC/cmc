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

package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

func ReadConfig(path string, cfg any) error {

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file %v: %w", path, err)
	}

	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(cfg); err != nil {
		return fmt.Errorf("failed to parse config file %v: %w", path, err)
	}
	if d.More() {
		return fmt.Errorf("failed to parse config file %v: unexpected data after JSON object",
			path)
	}

	return nil
}
