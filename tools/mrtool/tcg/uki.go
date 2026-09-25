// Copyright (c) 2025 Fraunhofer AISEC
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
	"debug/pe"
	"fmt"
	"os"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// UkiSections are the sections of a Unified Kernel Image in the order in which systemd-stub
// measures them into PCR11. The order is the order of the UnifiedSection enum in
// systemd (src/fundamental/uki.h) and is independent of the order of the PE section table.
var UkiSections = []string{
	".linux",
	".osrel",
	".cmdline",
	".initrd",
	".ucode",
	".splash",
	".dtb",
	".uname",
	".sbat",
	".pcrpkey",
	".profile",
	".dtbauto",
	".hwids",
	".efifw",
}

// MeasureUki measures a Unified Kernel Image as systemd-stub does: for every UKI section, the
// section name is measured first, followed by the section contents.
func MeasureUki(alg crypto.Hash, ta TrustAnchor, digest []byte, refvals []*ar.Component,
	index int, path string,
) ([]byte, []*ar.Component, error) {

	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open UKI %v: %w", path, err)
	}
	defer f.Close()

	p, err := pe.NewFile(f)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse UKI %v: %w", path, err)
	}
	defer p.Close()

	for _, name := range UkiSections {

		s := p.Section(name)
		if s == nil {
			continue
		}

		data, err := readPeSection(f, s)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read UKI section %v: %w", name, err)
		}

		log.Debugf("Measuring UKI section %v (%v bytes)", name, len(data))

		// systemd-stub measures the NUL-terminated ASCII section name first
		var rv *ar.Component
		rv, digest, err = CreateExtendRefval(alg, ta, index, digest, append([]byte(name), 0),
			"EV_IPL", fmt.Sprintf("%v (section name)", name))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create reference value for %v: %w", name, err)
		}
		refvals = append(refvals, rv)

		// ...followed by the section contents
		rv, digest, err = CreateExtendRefval(alg, ta, index, digest, data, "EV_IPL", name)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create reference value for %v: %w", name, err)
		}
		refvals = append(refvals, rv)
	}

	return digest, refvals, nil
}

// readPeSection returns VirtualSize bytes of the section as they are present in the loaded image:
// the raw data from the file, zero-padded if the section is larger in memory than on disk.
func readPeSection(f *os.File, s *pe.Section) ([]byte, error) {

	size := int(s.VirtualSize)
	if size == 0 {
		size = int(s.Size)
	}

	raw := size
	if int(s.Size) < raw {
		raw = int(s.Size)
	}

	buf := make([]byte, size)
	if raw > 0 {
		if _, err := f.ReadAt(buf[:raw], int64(s.Offset)); err != nil {
			return nil, fmt.Errorf("failed to read %v bytes at offset %v: %w", raw, s.Offset, err)
		}
	}

	return buf, nil
}
