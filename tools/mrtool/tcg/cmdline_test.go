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
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestMeasureKernelHandoff(t *testing.T) {
	dir := t.TempDir()
	cmdlinePath := filepath.Join(dir, "cmdline")
	if err := os.WriteFile(cmdlinePath, []byte(" console=ttyS0"), 0o600); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
	initrdPath := filepath.Join(dir, "initrd")
	initrd := []byte("initrd contents")
	if err := os.WriteFile(initrdPath, initrd, 0o600); err != nil {
		t.Fatalf("write initrd: %v", err)
	}
	initrdDigest := sha256.Sum256(initrd)

	// The LoadOptions digest is the one MeasureCmdline produces on its own
	loadOptions := make([]byte, 32)
	_, cmdlineRefvals, err := MeasureCmdline(crypto.SHA256, TPM, loadOptions, nil, 9,
		cmdlinePath, "EV_EVENT_TAG", 1, false, InitrdOptionNone)
	if err != nil {
		t.Fatalf("MeasureCmdline: %v", err)
	}
	loadOptionsDigest := cmdlineRefvals[0].Hashes[0].Content

	tests := []struct {
		name  string
		conf  Conf
		names []string
		want  [][]byte
	}{
		{
			// A firmware-loaded kernel: EDK2 records the LoadOptions only as EV_EVENT_TAG
			name: "direct",
			conf: Conf{
				Kernel:  "bzImage",
				Cmdline: cmdlinePath,
				Initrd:  initrdPath,
			},
			names: []string{"EV_EVENT_TAG", "EV_EVENT_TAG"},
			want:  [][]byte{loadOptionsDigest, initrdDigest[:]},
		},
		{
			// A chainloaded kernel: the LoadOptions are recorded twice over the same digest
			name: "chainloaded",
			conf: Conf{
				Kernel:      "linux",
				Bootloaders: []string{"systemd-bootx64.efi"},
				Cmdline:     cmdlinePath,
				Initrd:      initrdPath,
			},
			names: []string{"EV_IPL", "EV_EVENT_TAG", "EV_EVENT_TAG"},
			want:  [][]byte{loadOptionsDigest, loadOptionsDigest, initrdDigest[:]},
		},
		{
			// A BLS Type#1 entry without an initrd is still chainloaded
			name: "chainloaded without initrd",
			conf: Conf{
				Kernel:      "linux",
				Bootloaders: []string{"systemd-bootx64.efi"},
				Cmdline:     cmdlinePath,
			},
			names: []string{"EV_IPL", "EV_EVENT_TAG"},
			want:  [][]byte{loadOptionsDigest, loadOptionsDigest},
		},
		{
			// A loader measuring the kernel itself, e.g. GRUB, needs the explicit override
			name: "override direct",
			conf: Conf{
				Kernel:      "linux",
				Bootloaders: []string{"shimx64.efi", "grubx64.efi"},
				Cmdline:     cmdlinePath,
				LoadOptions: LoadOptionsDirect,
			},
			names: []string{"EV_EVENT_TAG"},
			want:  [][]byte{loadOptionsDigest},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.conf.AddZeros = 1

			_, refvals, err := tt.conf.MeasureKernelHandoff(crypto.SHA256, TPM, make([]byte, 32),
				nil, 9)
			if err != nil {
				t.Fatalf("MeasureKernelHandoff: %v", err)
			}
			if len(refvals) != len(tt.want) {
				t.Fatalf("expected %d refvals, got %d", len(tt.want), len(refvals))
			}
			for i, refval := range refvals {
				if refval.Name != tt.names[i] {
					t.Errorf("refval %d: name %q, want %q", i, refval.Name, tt.names[i])
				}
				if !bytes.Equal(refval.Hashes[0].Content, tt.want[i]) {
					t.Errorf("refval %d: digest %x, want %x", i, refval.Hashes[0].Content,
						tt.want[i])
				}
			}
		})
	}
}

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
