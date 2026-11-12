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

package est

import (
	"bytes"
	"testing"
)

func TestDecodeMultipart(t *testing.T) {
	body, ctype, err := EncodeMultiPart([]MimeMultipart{
		{ContentType: MimeTypeOctetStream, Data: []byte("first")},
		{ContentType: MimeTypeOctetStream, Data: []byte{1, 2, 3}},
	})
	if err != nil {
		t.Fatalf("EncodeMultiPart: %v", err)
	}
	raw := body.Bytes()

	t.Run("complete", func(t *testing.T) {
		var a, b []byte
		err := DecodeMultipart(bytes.NewReader(raw), []MimeMultipart{
			{ContentType: MimeTypeOctetStream, Data: &a},
			{ContentType: MimeTypeOctetStream, Data: &b},
		}, ctype)
		if err != nil {
			t.Fatalf("DecodeMultipart: %v", err)
		}
		if string(a) != "first" || !bytes.Equal(b, []byte{1, 2, 3}) {
			t.Fatalf("unexpected parts %q %v", a, b)
		}
	})

	t.Run("missing part", func(t *testing.T) {
		var a, b, c []byte
		err := DecodeMultipart(bytes.NewReader(raw), []MimeMultipart{
			{ContentType: MimeTypeOctetStream, Data: &a},
			{ContentType: MimeTypeOctetStream, Data: &b},
			{ContentType: MimeTypeOctetStream, Data: &c},
		}, ctype)
		if err == nil {
			t.Fatal("expected error for missing part")
		}
	})

	t.Run("short uint64", func(t *testing.T) {
		var n uint64
		var b []byte
		err := DecodeMultipart(bytes.NewReader(raw), []MimeMultipart{
			{ContentType: MimeTypeOctetStream, Data: &n},
			{ContentType: MimeTypeOctetStream, Data: &b},
		}, ctype)
		if err == nil {
			t.Fatal("expected error for short uint64 part")
		}
	})
}
