// Copyright (c) 2021 - 2024 Fraunhofer AISEC
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

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
)

const (
	devices     = "/dev/vd*"
	cmdlineFile = "/proc/cmdline"
)

func retrieveProvisioningData(c *config) error {

	// Read cmdline
	log.Tracef("Reading cmdline...")
	cmdline, err := os.ReadFile(cmdlineFile)
	if err != nil {
		return fmt.Errorf("failed to read: %w", err)
	}
	log.Tracef("cmdline: %v", string(cmdline))

	log.Tracef("Extracting config size and hash from cmdline...")
	hash, err := configHash(string(cmdline))
	if err != nil {
		return err
	}
	size, err := configSize(string(cmdline))
	if err != nil {
		return err
	}
	log.Debugf("Config hash: %v", hex.EncodeToString(hash))
	log.Debugf("Config size: %v", size)

	// Read provisioning partition
	log.Tracef("Retrieving provisioning data...")
	prov, err := getProvisioningData(size, hash)
	if err != nil {
		return fmt.Errorf("failed to get provisioning data: %w", err)
	}

	// Parse CA and token
	log.Tracef("Parsing provisioning data...")
	keys := []string{"token", "ca"}
	data, err := extractValues(prov, keys)
	if err != nil {
		return fmt.Errorf("failed to extract provisioning data: %w", err)
	}
	log.Tracef("token: %v", string(data["token"]))
	log.Tracef("ca: %v", string(data["ca"]))

	// Store CA and bootstrap token
	log.Tracef("Storing provisioning data...")
	err = os.WriteFile(c.EstTlsCa, data["ca"], 0644)
	if err != nil {
		return fmt.Errorf("failed to write: %w", err)
	}
	log.Tracef("Stored CA to %v", c.EstTlsCa)

	err = os.WriteFile(c.Token, data["token"], 0644)
	if err != nil {
		return fmt.Errorf("failed to write: %w", err)
	}
	log.Tracef("Stored token to %v", c.Token)

	log.Trace("Finished")

	return nil
}

func extractValues(data []byte, keys []string) (map[string][]byte, error) {
	result := make(map[string][]byte)

	for i, key := range keys {
		keyWithEquals := []byte(key + "=")
		start := bytes.Index(data, keyWithEquals)
		if start == -1 {
			return nil, fmt.Errorf("key %v not found", key)
		}
		start += len(keyWithEquals)

		var end int
		if i+1 < len(keys) {
			nextKeyWithEquals := []byte(keys[i+1] + "=")
			end = bytes.Index(data[start:], nextKeyWithEquals)
			if end != -1 {
				end += start
			}
		}

		if end == 0 || end == -1 {
			end = len(data)
		}

		result[keys[i]] = trim(data[start:end])
	}

	return result, nil
}

func configHash(cmdline string) ([]byte, error) {
	re := regexp.MustCompile(`config_hash=([a-f0-9]+)`)
	matches := re.FindStringSubmatch(cmdline)
	if len(matches) != 2 {
		return nil, fmt.Errorf("failed to extract hash")
	}
	hash, err := hex.DecodeString(matches[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode hash: %w", err)
	}
	return hash, nil
}

func configSize(cmdline string) (int, error) {
	re := regexp.MustCompile(`config_size=([0-9]+)`)
	matches := re.FindStringSubmatch(cmdline)
	if len(matches) != 2 {
		return 0, fmt.Errorf("failed to extract size")
	}
	size, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, fmt.Errorf("failed to convert config size")
	}
	return size, nil
}

func getProvisioningData(expectedSize int, expectedHash []byte) ([]byte, error) {

	matches, err := filepath.Glob(devices)
	if err != nil {
		return nil, fmt.Errorf("glob error: %w", err)
	}

	for _, dev := range matches {

		log.Tracef("Checking %v for provisioning data...", dev)

		if !isBlockDevice(dev) {
			log.Tracef("%v is not a block device", dev)
			continue
		}

		file, err := os.Open(dev)
		if err != nil {
			log.Tracef("Could not open %q: %v", dev, err)
			continue
		}

		buf := make([]byte, expectedSize)
		n, err := io.ReadFull(file, buf)
		file.Close()
		if err != nil {
			log.Tracef("Failed to read: %v", err)
			continue
		}

		if n != expectedSize {
			log.Tracef("Size of %v does not match expected size (%v vs. %v)", dev, n, expectedSize)
			file.Close()
			continue
		}

		actualHash := sha256.Sum256(buf)

		if bytes.Equal(expectedHash, actualHash[:]) {
			log.Debug("Found provisioining partition with expected hash and size")
			return buf, nil
		}
	}
	return nil, fmt.Errorf("failed to find provisioning partition with expected hash and size")
}

func isBlockDevice(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Mode&syscall.S_IFMT == syscall.S_IFBLK)
}

func trim(b []byte) []byte {
	return bytes.TrimRight(b, "\n\x00")
}
