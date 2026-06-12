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

package tcg

import (
	"encoding/binary"
	"testing"
)

func TestType17_SizeEncoding(t *testing.T) {
	cases := []struct {
		name        string
		sizeBytes   uint64
		wantSize16  uint16
		wantExtSize uint32
	}{
		{"1GiB", 1 << 30, 0x0400, 0},
		{"4GiB", 4 << 30, 0x1000, 0},
		{"32GiB-2MB", 32<<30 - 2<<20, 0x7ffe, 0},
		{"32GiB-1MB", 32<<30 - 1<<20, 0x7fff, 0x7fff}, // 0x7fff MB doesn't fit; spills to ExtendedSize
		{"32GiB", 32 << 30, 0x7fff, 32 << 10},         // crosses threshold; ExtendedSize takes over
		{"64GiB", 64 << 30, 0x7fff, 64 << 10},
		{"1TiB", 1 << 40, 0x7fff, 1 << 20},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := encodeType17(SmbiosDefaults(), 0, c.sizeBytes)
			gotSize16 := binary.LittleEndian.Uint16(body[8:])
			gotExt := binary.LittleEndian.Uint32(body[24:])
			if gotSize16 != c.wantSize16 {
				t.Errorf("Size = %#x, want %#x", gotSize16, c.wantSize16)
			}
			if gotExt != c.wantExtSize {
				t.Errorf("ExtendedSize = %#x, want %#x", gotExt, c.wantExtSize)
			}
		})
	}
}

func TestMappedAddressRegions(t *testing.T) {
	cases := []struct {
		name             string
		ramSize, below4G uint64
		want             []mappedRegion
	}{
		{"1GiB single region", 1 << 30, 1 << 30, []mappedRegion{
			{0, 1<<20 - 1}, // [0, 1 GiB)
		}},
		{"4GiB q35 split", 4 << 30, 2 << 30, []mappedRegion{
			{0, 0x001fffff},          // [0, 2 GiB)
			{0x00400000, 0x005fffff}, // [4 GiB, 6 GiB)
		}},
		{"8GiB q35 split", 8 << 30, 2 << 30, []mappedRegion{
			{0, 0x001fffff},          // [0, 2 GiB)
			{0x00400000, 0x009fffff}, // [4 GiB, 10 GiB)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mappedAddressRegions(c.ramSize, c.below4G)
			if len(got) != len(c.want) {
				t.Fatalf("region count = %d, want %d", len(got), len(c.want))
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("region[%d] = %+v, want %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestQemuQ35RamSplit(t *testing.T) {
	cases := []struct {
		ram       uint64
		wantBelow uint64
		wantAbove uint64
	}{
		{1 << 30, 1 << 30, 0},                // 1 GiB: all below
		{2 << 30, 2 << 30, 0},                // 2 GiB: all below
		{0xb0000000 - 1, 0xb0000000 - 1, 0},  // just under threshold: all below
		{0xb0000000, 0x80000000, 0x30000000}, // at threshold: 2 GiB below
		{4 << 30, 2 << 30, 2 << 30},
		{8 << 30, 2 << 30, 6 << 30},
		{64 << 30, 2 << 30, 62 << 30},
	}
	for _, c := range cases {
		below, above := QemuQ35RamSplit(c.ram)
		if below != c.wantBelow || above != c.wantAbove {
			t.Errorf("QemuQ35RamSplit(%#x) = (%#x, %#x), want (%#x, %#x)",
				c.ram, below, above, c.wantBelow, c.wantAbove)
		}
	}
}

func TestParseRamSize(t *testing.T) {
	cases := []struct {
		in      string
		want    uint64
		wantErr bool
	}{
		{"4G", 4 << 30, false},
		{"8g", 8 << 30, false},
		{"512M", 512 << 20, false},
		{"2Gi", 2 << 30, false},
		{"1024", 1024, false},
		{"", 0, true},
		{"4X", 0, true},
	}
	for _, c := range cases {
		got, err := ParseRamSize(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseRamSize(%q) = %d, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseRamSize(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseRamSize(%q) = %#x, want %#x", c.in, got, c.want)
		}
	}
}
