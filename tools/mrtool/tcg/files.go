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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

func MeasureFiles(alg crypto.Hash, ta TrustAnchor, digest []byte, refvals []*ar.ReferenceValue,
	index int, files []string,
) ([]byte, []*ar.ReferenceValue, error) {

	for _, p := range files {
		info, err := os.Lstat(p)
		if err != nil {
			return nil, nil, fmt.Errorf("stat %q: %w", p, err)
		}

		switch {
		case info.Mode().IsRegular():
			// Regular file
			return MeasureFile(alg, ta, digest, refvals, index, p)

		case info.IsDir():
			// Directory: walk recursively
			err := filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !d.Type().IsRegular() {
					return nil // Skip dirs, symlinks, devices, etc.
				}
				var err2 error
				digest, refvals, err2 = MeasureFile(alg, ta, digest, refvals, index, path)
				if err2 != nil {
					return err2
				}
				return nil
			})
			if err != nil {
				return nil, nil, fmt.Errorf("failed to walk directory: %w", err)
			}

		default:
			// Symlink, device, socket, etc.
			log.Debugf("Not measuring path type: %q (%s)", p, info.Mode())
		}
	}
	return digest, refvals, nil

}

func MeasureFile(alg crypto.Hash, ta TrustAnchor, digest []byte, refvals []*ar.ReferenceValue,
	index int, file string,
) ([]byte, []*ar.ReferenceValue, error) {

	data, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to measure file: %w", err)
	}

	var rv *ar.ReferenceValue
	rv, digest, err = CreateExtendRefval(alg, ta, index, digest, data, "EV_IPL", filepath.Base(file))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create reference value: %w", err)
	}

	return digest, append(refvals, rv), nil
}
