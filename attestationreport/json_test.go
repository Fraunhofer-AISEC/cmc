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

package attestationreport

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/invopop/jsonschema"
)

func TestHexByteSchema(t *testing.T) {
	schema := (&jsonschema.Reflector{}).Reflect(HexByte{})
	def, ok := schema.Definitions["HexByte"]
	if !ok {
		t.Fatalf("HexByte definition missing from schema")
	}
	if def.Type != "string" || def.ContentEncoding != "base16" {
		t.Fatalf("unexpected HexByte schema: type %q, contentEncoding %q",
			def.Type, def.ContentEncoding)
	}

	// The schema pattern must match what MarshalJSON actually produces
	pattern := regexp.MustCompile(def.Pattern)
	for _, b := range []HexByte{{}, {0x00}, {0xde, 0xad, 0xbe, 0xef}, {0xff, 0x0a}} {
		data, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("failed to marshal %v: %v", b, err)
		}
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			t.Fatalf("failed to unmarshal %s: %v", data, err)
		}
		if !pattern.MatchString(s) {
			t.Errorf("marshalled HexByte %q does not match schema pattern %q", s, def.Pattern)
		}
	}

	// Base64 of the same bytes must not match, as it did with the previous schema
	if pattern.MatchString("3q2+7w==") {
		t.Errorf("schema pattern %q accepts base64", def.Pattern)
	}
}
