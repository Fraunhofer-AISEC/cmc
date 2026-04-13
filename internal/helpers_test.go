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

package internal

import (
	"bytes"
	"crypto"
	"reflect"
	"testing"
)

func TestFilterInts(t *testing.T) {
	type args struct {
		list        []int
		excludeList []int
	}
	tests := []struct {
		name string
		args args
		want []int
	}{
		{
			name: "Exclude PCRs Success",
			args: args{
				list:        []int{0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
				excludeList: []int{0, 6, 14, 15},
			},
			want: []int{1, 2, 3, 4, 7, 8, 9, 10, 11, 12, 13},
		},
		{
			name: "Exclude No PCRs Success",
			args: args{
				list:        []int{0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
				excludeList: []int{},
			},
			want: []int{0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FilterInts(tt.args.list, tt.args.excludeList); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FilterInts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name string
		elem string
		list []string
		want bool
	}{
		{"exact match", "foo", []string{"foo", "bar"}, true},
		{"case insensitive", "FOO", []string{"foo", "bar"}, true},
		{"not found", "baz", []string{"foo", "bar"}, false},
		{"empty list", "foo", []string{}, false},
		{"empty string found", "", []string{"", "bar"}, true},
		{"empty string not found", "", []string{"foo", "bar"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Contains(tt.elem, tt.list); got != tt.want {
				t.Errorf("Contains(%q, %v) = %v, want %v", tt.elem, tt.list, got, tt.want)
			}
		})
	}
}

func TestGetNetworkAndAddr(t *testing.T) {
	tests := []struct {
		name        string
		addr        string
		wantNetwork string
		wantErr     bool
	}{
		{"TCP ipv4", "127.0.0.1:8080", "tcp", false},
		{"TCP ipv6", "[::1]:443", "tcp", false},
		{"TCP hostname", "localhost:9090", "tcp", false},
		{"Unix socket absolute", "/tmp/cmc.sock", "unix", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network, addr, err := GetNetworkAndAddr(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetNetworkAndAddr(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
				return
			}
			if network != tt.wantNetwork {
				t.Errorf("GetNetworkAndAddr(%q) network = %q, want %q", tt.addr, network, tt.wantNetwork)
			}
			if addr == "" {
				t.Errorf("GetNetworkAndAddr(%q) returned empty addr", tt.addr)
			}
		})
	}
}

func TestIndexToMr(t *testing.T) {
	tests := []struct {
		index int
		want  string
	}{
		{0, "MRTD"},
		{1, "RTMR0"},
		{2, "RTMR1"},
		{3, "RTMR2"},
		{4, "RTMR3"},
		{5, "MRSEAM"},
		{6, "UNKNOWN"},
		{-1, "UNKNOWN"},
		{99, "UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := IndexToMr(tt.index); got != tt.want {
				t.Errorf("IndexToMr(%d) = %q, want %q", tt.index, got, tt.want)
			}
		})
	}
}

func TestFlattenUnflattenRoundtrip(t *testing.T) {
	tests := []struct {
		name string
		data [][]byte
	}{
		{"empty", [][]byte{}},
		{"single element", [][]byte{[]byte("hello")}},
		{"multiple elements", [][]byte{[]byte("aaa"), []byte("bbb"), []byte("ccc")}},
		{"contains empty slice", [][]byte{[]byte("data"), {}, []byte("more")}},
		{"binary data", [][]byte{{0x00, 0xff, 0x01}, {0xde, 0xad, 0xbe, 0xef}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flat := FlattenArray(tt.data)
			got, err := UnflattenArray(flat)
			if err != nil {
				t.Fatalf("UnflattenArray error: %v", err)
			}
			if len(got) != len(tt.data) {
				t.Fatalf("roundtrip length %d, want %d", len(got), len(tt.data))
			}
			for i := range tt.data {
				if !bytes.Equal(got[i], tt.data[i]) {
					t.Errorf("element %d = %x, want %x", i, got[i], tt.data[i])
				}
			}
		})
	}
}

func TestUnflattenArrayTruncated(t *testing.T) {
	// Length header says 5 bytes but data is shorter
	flat := FlattenArray([][]byte{[]byte("hello")})
	truncated := flat[:len(flat)-2]
	_, err := UnflattenArray(truncated)
	if err == nil {
		t.Error("UnflattenArray with truncated data should return error")
	}
}

func TestStrToInt(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		want    []int
		wantErr bool
	}{
		{"valid", []string{"1", "2", "3"}, []int{1, 2, 3}, false},
		{"single", []string{"42"}, []int{42}, false},
		{"empty", []string{}, []int{}, false},
		{"invalid", []string{"abc"}, nil, true},
		{"mixed", []string{"1", "x"}, nil, true},
		{"negative", []string{"-5", "10"}, []int{-5, 10}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := StrToInt(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("StrToInt(%v) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("StrToInt(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatRtmrData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"printable ASCII", []byte("hello"), "hello"},
		{"empty", []byte{}, ""},
		{"non-printable", []byte{0x80, 0x01}, ""},
		{"mixed", []byte{'a', 0x00}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatRtmrData(tt.data); got != tt.want {
				t.Errorf("FormatRtmrData(%x) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}

func TestConvertToMapAndArray(t *testing.T) {
	input := [][]byte{[]byte("item1"), []byte("item2")}
	m, err := ConvertToMap(input, crypto.SHA256)
	if err != nil {
		t.Fatalf("ConvertToMap error: %v", err)
	}
	if len(m) != 2 {
		t.Fatalf("ConvertToMap returned %d items, want 2", len(m))
	}

	// Each value should be one of the original items
	arr := ConvertToArray(m)
	if len(arr) != 2 {
		t.Fatalf("ConvertToArray returned %d items, want 2", len(arr))
	}

	// Verify all original items are present (order may differ)
	found := map[string]bool{}
	for _, v := range arr {
		found[string(v)] = true
	}
	if !found["item1"] || !found["item2"] {
		t.Errorf("ConvertToArray missing items: got %v", found)
	}
}

func TestConvertToMapEmpty(t *testing.T) {
	m, err := ConvertToMap([][]byte{}, crypto.SHA256)
	if err != nil {
		t.Fatalf("ConvertToMap error: %v", err)
	}
	if len(m) != 0 {
		t.Errorf("ConvertToMap(empty) returned %d items, want 0", len(m))
	}
}
