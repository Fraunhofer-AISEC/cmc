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

// FetchMetadata fetches the metadata (manifests and descriptions) from a remote server
func FetchMetadata(serverAddr, serverPath, localPath string) error {

	if _, err := os.Stat(localPath); err != nil {
		if err := os.Mkdir(localPath, 0755); err != nil {
			return fmt.Errorf("Failed to create directory for local data '%v': %v", localPath, err)
		}
	} else {
		log.Tracef("Removing old metadata in %v before fetching new metadata from provisioning server", localPath)
		dir, err := ioutil.ReadDir(localPath)
		if err != nil {
			return fmt.Errorf("Failed to read local storage directory %v: %v", localPath, err)
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

	// Read file root directory
	log.Info("Requesting data for ", serverPath)
	resp, err := http.Get(serverAddr + serverPath)
	if err != nil {
		log.Error("HTTP request failed: ", err)
		return err
	}
	defer resp.Body.Close()
	log.Debug("Response Status: ", resp.Status)
	if resp.StatusCode != 200 {
		log.Warn("Request returned error - ", resp.Status)
		return err
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error("Failed to read response")
		return err
	}
	log.Trace("Content:\n", string(content))

	// Parse root directory
	var pre Pre
	err = xml.Unmarshal(content, &pre)
	if err != nil {
		log.Error("Error Unmarshalling - ", err)
		return err
	}

	// Parse subdirectories recursively and save files
	err = fetchDataRecursively(pre, serverAddr, serverPath, localPath)
	if err != nil {
		log.Error("Error saving data - ", err)
		return err
	}

	return nil
}

func fetchDataRecursively(pre Pre, serverAddr, serverPath, localPath string) error {
	for i := 0; i < len(pre.Content); i++ {

		// Read content
		subpath := filepath.Join(serverPath, pre.Content[i].Name)
		log.Debug("Requesting ", subpath)
		resp, err := http.Get(serverAddr + subpath)
		if err != nil {
			log.Error("HTTP request failed: ", err)
			return err
		}
		defer resp.Body.Close()
		log.Debug("Response Status: ", resp.Status)
		if resp.StatusCode != 200 {
			log.Warn("Request returned error - ", resp.Status)
			return fmt.Errorf("Request returned error - %v", resp.Status)
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
				log.Error("Error Unmarshalling - ", err)
				return err
			}
			err = fetchDataRecursively(pre, serverAddr, subpath, localPath)
			if err != nil {
				log.Error("Error saving data - ", err)
				return err
			}
		} else {

			// Content is a file, save it to disk
			content, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Error("Failed to read response - ", err)
				return err
			}
			log.Trace("Content:\n", string(content))

			lp := filepath.Join(localPath, serverPath[len(serverPath):])
			log.Debug("Creating path ", lp)
			if err = os.MkdirAll(lp, 0755); err != nil {
				log.Error("Failed to create path - ", err)
			}
			file := filepath.Join(lp, pre.Content[i].Name)
			log.Debug("Writing file: ", file)
			err = os.WriteFile(file, content, 0644)
			if err != nil {
				log.Error("Error saving file - ", err)
			}
		}
	}
	return nil
}
