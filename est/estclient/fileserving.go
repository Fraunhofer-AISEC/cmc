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

package client

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
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
func FetchMetadata(addr string) ([][]byte, error) {

	client := NewClient(nil)

	resp, err := request(client.client, http.MethodGet, addr, "", "", "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	log.Debug("Response Status: ", resp.Status)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP GET request returned status %v", resp.Status)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %v", err)
	}

	// Parse root directory
	var pre Pre
	err = xml.Unmarshal(content, &pre)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal HTTP response: %v", err)
	}

	// Parse subdirectories recursively and save files
	data, err := fetchDataRecursively(client, pre, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch recursively: %v", err)
	}

	return data, nil
}

func fetchDataRecursively(client *Client, pre Pre, addr string) ([][]byte, error) {
	metadata := make([][]byte, 0)
	for i := 0; i < len(pre.Content); i++ {

		// Read content
		var subpath string
		if addr[len(addr)-1:] == "/" {
			subpath = addr + pre.Content[i].Name
		} else {
			subpath = addr + "/" + pre.Content[i].Name
		}

		log.Debug("Requesting ", subpath)
		resp, err := request(client.client, http.MethodGet, subpath, "", "", "", nil)
		if err != nil {
			return nil, fmt.Errorf("failed to perform request: %w", err)
		}
		defer resp.Body.Close()

		log.Trace("Response Status: ", resp.Status)
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("HTTP GET request returned status %v", resp.Status)
		}

		log.Debug("Found: ", pre.Content[i].Name, " Type:", resp.Header.Values("Content-Type")[0])

		if strings.Compare(resp.Header.Values("Content-Type")[0], "text/html; charset=utf-8") == 0 {

			// Content is a subdirectory, parse recursively
			content, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Error("Failed to read response")
			}

			var pre Pre
			err = xml.Unmarshal(content, &pre)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal HTTP response: %v", err)
			}
			d, err := fetchDataRecursively(client, pre, subpath)
			metadata = append(metadata, d...)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch recursively: %v", err)
			}
		} else {

			// Content is a file, gather content
			d, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read HTTP response body: %v", err)
			}

			metadata = append(metadata, d)
		}
	}
	return metadata, nil
}
