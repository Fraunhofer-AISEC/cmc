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

package measure

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func GetRootfsMeasurement(rootfsPath string) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	rootfsPath = filepath.Clean(rootfsPath) + string(os.PathSeparator)

	err := filepath.Walk(rootfsPath, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		var link string
		if fi.Mode()&os.ModeSymlink != 0 {
			link, err = os.Readlink(file)
			if err != nil {
				return err
			}
		}

		header, err := tar.FileInfoHeader(fi, link)
		if err != nil {
			return err
		}

		header.ModTime = time.Unix(0, 0)

		relativePath, err := filepath.Rel(rootfsPath, file)
		if err != nil {
			return err
		}
		header.Name = relativePath

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if !fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
			f, err := os.Open(file)
			if err != nil {
				return err
			}
			defer f.Close()

			if _, err := io.Copy(tw, f); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk through rootfs: %w", err)
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("failed to close tar writer: %w", err)
	}

	hasher := sha256.New()
	hasher.Write(buf.Bytes())
	hash := hasher.Sum(nil)

	return hash, nil
}
