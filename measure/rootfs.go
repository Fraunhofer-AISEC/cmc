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

package measure

import (
	"archive/tar"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/pkg/archive/tarheader"
	"github.com/containerd/continuity/fs"
	"golang.org/x/sys/unix"
)

// PAX header prefix used for extended file attributes (xattrs)
const paxSchilyXattr = "SCHILY.xattr."

// GetRootfsMeasurement computes a deterministic hash of the container rootfs
func GetRootfsMeasurement(rootfsPath string) ([]byte, error) {
	hasher := sha256.New()
	tw := tar.NewWriter(hasher)

	rootfsPath = filepath.Clean(rootfsPath)
	inodeSrc := map[uint64]string{}

	err := filepath.Walk(rootfsPath, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("failed to walk file path: %w", err)
		}

		if file == rootfsPath {
			return nil
		}

		if fi.Mode()&os.ModeSocket != 0 {
			return nil
		}

		var link string
		if fi.Mode()&os.ModeSymlink != 0 {
			link, err = os.Readlink(file)
			if err != nil {
				return fmt.Errorf("failed to read link: %w", err)
			}
		}

		header, err := tarheader.FileInfoHeaderNoLookups(fi, link)
		if err != nil {
			return fmt.Errorf("failed to get file info header: %w", err)
		}

		header.ModTime = time.Unix(0, 0)
		header.AccessTime = time.Time{}
		header.ChangeTime = time.Time{}
		header.Format = tar.FormatPAX

		relativePath, err := filepath.Rel(rootfsPath, file)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}
		name := filepath.ToSlash(relativePath)
		if fi.IsDir() && !strings.HasSuffix(name, "/") {
			name += "/"
		}
		header.Name = name

		inode, isHardlink := fs.GetLinkInfo(fi)
		if isHardlink {
			if source, ok := inodeSrc[inode]; ok {
				header.Typeflag = tar.TypeLink
				header.Linkname = source
				header.Size = 0
			} else {
				inodeSrc[inode] = name
			}
		}

		if capability, err := getSecurityCapability(file); err != nil {
			return fmt.Errorf("failed to get capabilities xattr: %w", err)
		} else if len(capability) > 0 {
			if header.PAXRecords == nil {
				header.PAXRecords = map[string]string{}
			}
			header.PAXRecords[paxSchilyXattr+"security.capability"] = string(capability)
		}

		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write header: %w", err)
		}

		if header.Typeflag == tar.TypeReg && header.Size > 0 {
			f, err := os.Open(file)
			if err != nil {
				return fmt.Errorf("failed to open: %w", err)
			}
			defer f.Close()

			if _, err := io.Copy(tw, f); err != nil {
				return fmt.Errorf("failed to copy: %w", err)
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

	hash := hasher.Sum(nil)

	return hash, nil
}

// getSecurityCapability reads the security.capability xattr from path
func getSecurityCapability(path string) ([]byte, error) {
	dest := make([]byte, 256)
	sz, err := unix.Lgetxattr(path, "security.capability", dest)
	if err != nil {
		if err == unix.ENOTSUP || err == unix.ENODATA {
			return nil, nil
		}
		return nil, err
	}
	if sz <= 0 {
		return nil, nil
	}
	return dest[:sz], nil
}
