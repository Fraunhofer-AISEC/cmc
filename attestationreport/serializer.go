// Copyright (c) 2024 - 2026 Fraunhofer AISEC
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

package attestationreport

import (
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/plgd-dev/go-coap/v3/message"
)

// Verifier can either be a list of trusted CA certificates, or a trusted public key,
// or nil. In this case, the system cert store is used
type Verifier interface{}

// Serializer is a generic interface providing methods for data serialization and
// de-serialization. This enables to generate and verify attestation reports in
// different formats, such as JSON/JWS or CBOR/COSE
type Serializer interface {
	GetPayload(raw []byte) ([]byte, error)
	Marshal(v any) ([]byte, error)
	Unmarshal(data []byte, v any) error
	Sign(data []byte, driver Driver, sel KeySelection) ([]byte, error)
	Verify(data []byte, verifier Verifier) (MetadataResult, []byte, bool)
	String() string
}

func DetectSerialization(payload []byte) (Serializer, error) {
	if json.Valid(payload) {
		s, err := NewJsonSerializer()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize json serializer: %w", err)
		}
		return s, nil
	} else if err := cbor.Wellformed(payload); err == nil {
		s, err := NewCborSerializer()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize cbor serializer: %w", err)
		}
		return s, nil
	} else {
		return nil, fmt.Errorf("failed to detect serialization")
	}
}

// GetMediaType returns the media type that corresponds to the serializer
func GetMediaType(s Serializer) message.MediaType {
	switch s.(type) {
	case jsonSerializer:
		return message.AppJSON
	case cborSerializer:
		return message.AppCBOR
	default:
		log.Warnf("unknown serializer type %T", s)
		return message.TextPlain
	}
}

func GetEncoding(s Serializer) string {
	switch s.(type) {
	case jsonSerializer:
		return TYPE_ENCODING_B64
	case cborSerializer:
		return TYPE_ENCODING_CBOR
	default:
		log.Warnf("unknown serializer type %T", s)
		return "unknown"
	}
}
