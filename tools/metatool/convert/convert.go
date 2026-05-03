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

package convert

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

func Convert(input []byte, outform string) ([]byte, error) {
	// Initialize serializers: detect input format
	var si ar.Serializer
	var err error
	if json.Valid(input) {
		si, err = ar.NewJsonSerializer()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize json serializer: %w", err)
		}
	} else if err := cbor.Wellformed(input); err == nil {
		si, err = ar.NewCborSerializer()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize cbor serializer: %w", err)
		}
	} else {
		return nil, errors.New("failed to detect serialization (only JSON and CBOR are supported)")
	}

	// Initialize serializers: use specified output format
	var so ar.Serializer
	if strings.EqualFold(outform, "json") {
		so, err = ar.NewJsonSerializer()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize json serializer: %w", err)
		}
	} else if strings.EqualFold(outform, "cbor") {
		so, err = ar.NewCborSerializer()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize cbor serializer: %w", err)
		}
	} else {
		return nil, fmt.Errorf("output format %v not supported (only JSON and CBOR are supported)",
			outform)
	}

	// Convert serialized input to go representation
	m := new(ar.Metadata)
	err = si.Unmarshal(input, m)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %v", err)
	}

	// Convert go representation to serialized output
	output, err := so.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal: %v", err)
	}

	return output, nil
}
