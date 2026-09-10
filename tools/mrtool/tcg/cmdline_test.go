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
	"crypto"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Golden vectors: --cmdline file contains exactly " console=ttyS0" (leading space,
// no trailing newline), --addzeros defaults to 1, so the measured buffer is
// UTF-16LE(<string>) || u16(0). See PLAN-mrtool-initrd-option.md §3.6.
func TestMeasureCmdline_InitrdOption(t *testing.T) {
	dir := t.TempDir()
	cmdlinePath := filepath.Join(dir, "cmdline")
	if err := os.WriteFile(cmdlinePath, []byte(" console=ttyS0"), 0o600); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}

	tests := []struct {
		name       string
		option     InitrdOption
		wantDigest string
	}{
		{
			name:       "none",
			option:     InitrdOptionNone,
			wantDigest: "7d2bf43704b2d8bd6c97904aa13207d248409530d7bc81854814a79d34be422f",
		},
		{
			name:       "prefix",
			option:     InitrdOptionPrefix,
			wantDigest: "361f34652060ae3541fd7eebc957b0248244fd1d3640894811451769be7b294e",
		},
		{
			name:       "suffix",
			option:     InitrdOptionSuffix,
			wantDigest: "16d126ba8c256c2266c9a48c4b74eef4e338b033a8b313a8b640a9be1725d7f2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest := make([]byte, 32)
			_, refvals, err := MeasureCmdline(crypto.SHA256, TPM, digest, nil, 9,
				cmdlinePath, "EV_EVENT_TAG", 1, false, tt.option)
			if err != nil {
				t.Fatalf("MeasureCmdline: %v", err)
			}
			if len(refvals) != 1 {
				t.Fatalf("expected 1 refval, got %d", len(refvals))
			}
			got := hex.EncodeToString(refvals[0].Hashes[0].Content)
			if got != tt.wantDigest {
				t.Errorf("digest mismatch\n got: %s\nwant: %s", got, tt.wantDigest)
			}
		})
	}
}
