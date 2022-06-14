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

package provclient

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/exp/maps"

	log "github.com/sirupsen/logrus"
)

// Pre is a struct for parsing HTML content
type Pre struct {
	XMLName xml.Name  `xml:"pre"`
	Content []Content `xml:"a"`
}

// Content is a struct for parsing HTML content
type Content struct {
	XMLName xml.Name `xml:"a"`
	Type    string   `xml:"href,attr"`
	Name    string   `xml:",chardata"`
}

type Config struct {
	FetchMetadata bool
	StoreMetadata bool
	LocalPath     string
	RemoteAddr    string
}

// ProvisionMetadata either loads the metadata from the file system or fetches it
// from a remote HTTP server. Optionally, it can store the fetched metadata on the filesystem
func ProvisionMetadata(c *Config) ([][]byte, error) {
	if c.FetchMetadata {
		data, err := FetchMetadata(c.RemoteAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch device metadata from %v: %v", c.RemoteAddr, err)
		}
		if c.StoreMetadata {
			err := StoreMetadata(data, c.LocalPath)
			if err != nil {
				return nil, fmt.Errorf("failed to store metadata: %v", err)
			}
		}
		metadata := make([][]byte, 0, len(data))
		for _, v := range data {
			metadata = append(metadata, v)
		}
		return metadata, nil
	} else {
		metadata, err := LoadMetadata(c.LocalPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load metadata from %v: %v", c.LocalPath, err)
		}
		return metadata, nil
	}
}

// LoadMetadata loads the metadata (manifests and descriptions) from the file system
func LoadMetadata(dir string) (metadata [][]byte, err error) {
	// Read number of files
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata folder: %v", err)
	}

	// Retrieve the metadata files
	metadata = make([][]byte, 0)
	log.Tracef("Parsing %v metadata files in %v", len(files), dir)
	for i := 0; i < len(files); i++ {
		file := path.Join(dir, files[i].Name())
		if fileInfo, err := os.Stat(file); err == nil {
			if fileInfo.IsDir() {
				log.Tracef("Skipping directory %v", file)
				continue
			}
		}
		log.Tracef("Reading file %v", file)
		data, err := ioutil.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %v: %v", file, err)
		}
		metadata = append(metadata, data)
	}
	return metadata, nil
}

// StoreMetadata stores the metadata locally into the specified file system folder
func StoreMetadata(data map[string][]byte, localPath string) error {
	if _, err := os.Stat(localPath); err != nil {
		if err := os.Mkdir(localPath, 0755); err != nil {
			return fmt.Errorf("failed to create directory for local data '%v': %v", localPath, err)
		}
	} else {
		log.Tracef("Removing old metadata in %v before fetching new metadata from provisioning server", localPath)
		dir, err := ioutil.ReadDir(localPath)
		if err != nil {
			return fmt.Errorf("failed to read local storage directory %v: %v", localPath, err)
		}
		for _, d := range dir {
			file := path.Join(localPath, d.Name())
			if fileInfo, err := os.Stat(file); err == nil {
				if fileInfo.IsDir() {
					log.Tracef("\tSkipping directory %v", d.Name())
					continue
				}
				log.Tracef("\tRemoving file %v", d.Name())
				if err := os.Remove(file); err != nil {
					log.Warnf("\tFailed to remove file %v: %v", d.Name(), err)
				}
			}
		}
	}

	for filename, content := range data {
		file := filepath.Join(localPath, filename)
		log.Debug("Writing file: ", file)
		err := ioutil.WriteFile(file, content, 0644)
		if err != nil {
			return fmt.Errorf("failed to write file: %v", err)
		}
	}

	return nil
}

// FetchMetadata fetches the metadata (manifests and descriptions) from a remote server
func FetchMetadata(addr string) (map[string][]byte, error) {

	// Read file root directory
	log.Info("Requesting data for ", addr)
	resp, err := http.Get(addr)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET request to %v failed: %v", addr, err)
	}
	defer resp.Body.Close()
	log.Debug("Response Status: ", resp.Status)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP GET request returned status %v", resp.Status)
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %v", err)
	}
	log.Trace("Content:\n", string(content))

	// Parse root directory
	var pre Pre
	err = xml.Unmarshal(content, &pre)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal HTTP response: %v", err)
	}

	// Parse subdirectories recursively and save files
	data, err := fetchDataRecursively(pre, addr)
	if err != nil {
		return nil, fmt.Errorf("error fetching metadata recursively: %v", err)
	}

	return data, nil
}

func fetchDataRecursively(pre Pre, addr string) (map[string][]byte, error) {
	data := make(map[string][]byte, 0)
	for i := 0; i < len(pre.Content); i++ {

		// Read content
		var subpath string
		if addr[len(addr)-1:] == "/" {
			subpath = addr + pre.Content[i].Name
		} else {
			subpath = addr + "/" + pre.Content[i].Name
		}
		log.Debug("Requesting ", subpath)
		resp, err := http.Get(subpath)
		if err != nil {
			return nil, fmt.Errorf("HTTP GET request failed: %v", err)
		}
		defer resp.Body.Close()
		log.Trace("Response Status: ", resp.Status)
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("HTTP GET request returned status %v", resp.Status)
		}

		log.Debug("Found: ", pre.Content[i].Name, " Type:", resp.Header.Values("Content-Type")[0])

		if strings.Compare(resp.Header.Values("Content-Type")[0], "text/html; charset=utf-8") == 0 {

			// Content is a subdirectory, parse recursively
			content, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Error("Failed to read response")
			}
			log.Trace("Content:\n", string(content))

			var pre Pre
			err = xml.Unmarshal(content, &pre)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal HTTP response: %v", err)
			}
			d, err := fetchDataRecursively(pre, subpath)
			maps.Copy(data, d)
			if err != nil {
				return nil, fmt.Errorf("error fetching metadata recursively: %v", err)
			}
		} else {

			// Content is a file, gather content
			content, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read HTTP response body: %v", err)
			}
			log.Trace("Content:\n", string(content))

			data[pre.Content[i].Name] = content
		}
	}
	return data, nil
}
