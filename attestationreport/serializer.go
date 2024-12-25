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

package attestationreport

import (
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/plgd-dev/go-coap/v3/message"
)

// SignConfig allows to specify options for signing with the specified serializer
type SignConfig struct {
	UseAk bool // Use the AK instead of the IK for signing
}

// Serializer is a generic interface providing methods for data serialization and
// de-serialization. This enables to generate and verify attestation reports in
// different formats, such as JSON/JWS or CBOR/COSE
type Serializer interface {
	GetPayload(raw []byte) ([]byte, error)
	Marshal(v any) ([]byte, error)
	Unmarshal(data []byte, v any) error
	Sign(data []byte, driver Driver, sel KeySelection) ([]byte, error)
	Verify(data []byte, roots []*x509.Certificate) (MetadataResult, []byte, bool)
	String() string
}

func DetectSerialization(payload []byte) (Serializer, error) {
	if json.Valid(payload) {
		return JsonSerializer{}, nil
	} else if err := cbor.Valid(payload); err == nil {
		return CborSerializer{}, nil
	} else {
		return nil, fmt.Errorf("failed to detect serialization")
	}
}

// GetMediaType returns the media type that corresponds to the serializer
func GetMediaType(s Serializer) message.MediaType {
	switch s.(type) {
	case JsonSerializer:
		return message.AppJSON
	case CborSerializer:
		return message.AppCBOR
	default:
		log.Fatalf("internal error: unknown serializer type %T", s)
	}
	// Will not be reached, required to vaoid compiler error
	return message.TextPlain
}
