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

package precomputetpm

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

func performImaPrecomputation(pcr int, bootAggregate []byte, paths []string, strip, prepend string, imaTemplate string) ([]*ar.ReferenceValue, error) {

	refvals := make([]*ar.ReferenceValue, 0)
	fileCh := make(chan string, 100)
	resultCh := make(chan *ar.ReferenceValue, 100)

	if bootAggregate != nil {
		log.Debugf("Precomputing boot aggregate...")

		refval, err := precomputeImaBootAggregate(bootAggregate, imaTemplate, pcr, false)
		if err != nil {
			return nil, fmt.Errorf("failed to precompute boot_aggregate: %w", err)
		}
		refvals = append(refvals, refval)
	}

	log.Debugf("Precomputing %v paths...", len(paths))

	var wg sync.WaitGroup
	numWorkers := runtime.NumCPU() / 2
	log.Debugf("Using %v workers", numWorkers)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileCh {
				refval, err := precomputeImaEntry(path, strip, prepend, imaTemplate, pcr, true)
				if err != nil {
					log.Errorf("error hashing %q: %v", path, err)
					continue
				}
				log.Tracef("%s: %s", refval.SubType, hex.EncodeToString(refval.Sha256))
				resultCh <- refval
			}
		}()
	}

	// Collector goroutine
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for r := range resultCh {
			refvals = append(refvals, r)
		}
	}()

	// Walk all given paths
	for _, root := range paths {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Debugf("error accessing %q: %v", path, err)
				return nil
			}
			if info.Mode().IsRegular() {
				fileCh <- path
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("error walking the path %q: %w", root, err)
		}
	}

	close(fileCh)
	wg.Wait()
	close(resultCh)
	collectWg.Wait()

	return refvals, nil
}

func precomputeImaTemplate(hash []byte, path string, template string) ([]byte, error) {

	const hashAlgo = "sha256:"
	if len(hash) != sha256.Size {
		return nil, fmt.Errorf("unexpected hash length %v", len(hash))
	}

	imaDigestLen := uint32(len(hashAlgo) + 1 + sha256.Size)
	pathLen := uint32(len(path) + 1)
	sigLen := uint32(0)

	var tmpl []byte

	switch template {
	case "ima-sig":
		tmpl = buildTemplate(hashAlgo, hash, path, imaDigestLen, pathLen, &sigLen)

	case "ima-ng":
		tmpl = buildTemplate(hashAlgo, hash, path, imaDigestLen, pathLen, nil)

	default:
		return nil, fmt.Errorf("template %q not supported", template)
	}

	th := sha256.Sum256(tmpl)

	return th[:], nil
}

func precomputeImaBootAggregate(hash []byte, template string, pcr int, optional bool) (*ar.ReferenceValue, error) {

	tmpl, err := precomputeImaTemplate(hash, "boot_aggregate", template)
	if err != nil {
		return nil, fmt.Errorf("failed to precompute ima template: %w", err)
	}

	// Create reference value
	r := &ar.ReferenceValue{
		Type:     "TPM Reference Value",
		SubType:  "boot_aggregate",
		Index:    pcr,
		Sha256:   tmpl,
		Optional: optional,
	}

	return r, nil
}

func precomputeImaEntry(path, strip, prepend, template string, pcr int, optional bool) (*ar.ReferenceValue, error) {

	fileHash, err := hashFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to hash file: %w", err)
	}

	hashedPath := modifyPath(path, strip, prepend)

	tmpl, err := precomputeImaTemplate(fileHash, hashedPath, template)
	if err != nil {
		return nil, fmt.Errorf("failed to precompute ima template: %w", err)
	}

	// Create reference value
	r := &ar.ReferenceValue{
		Type:        "TPM Reference Value",
		SubType:     filepath.Base(hashedPath),
		Index:       pcr,
		Sha256:      tmpl,
		Description: hashedPath,
		Optional:    optional,
	}

	return r, nil
}

func buildTemplate(hashAlgo string, hash []byte, path string, imaDigestLen, pathLen uint32, sigLen *uint32) []byte {
	var buf []byte

	// ima_digest_len
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, imaDigestLen)
	buf = append(buf, tmp...)

	// hashAlgo + NUL
	buf = append(buf, []byte(hashAlgo)...)
	buf = append(buf, 0)

	// sha256 hash
	buf = append(buf, hash...)

	// path_len
	binary.LittleEndian.PutUint32(tmp, pathLen)
	buf = append(buf, tmp...)

	// path + NUL
	buf = append(buf, []byte(path)...)
	buf = append(buf, 0)

	// sig_len if ima-sig
	if sigLen != nil {
		binary.LittleEndian.PutUint32(tmp, *sigLen)
		buf = append(buf, tmp...)
	}

	return buf
}

func hashFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func modifyPath(s, prefix, prepend string) string {
	if s == "" {
		return ""
	}
	s = strings.TrimPrefix(s, prefix)
	return prepend + s
}
