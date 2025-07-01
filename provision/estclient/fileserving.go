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

package estclient

import (
	"crypto/x509"
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
func FetchMetadata(addr string, rootCas []*x509.Certificate,
	useSystemRoots bool,
) ([][]byte, error) {

	client, err := New(addr, rootCas, useSystemRoots, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create EST client: %w", err)
	}

	resp, err := request(client.client, http.MethodGet, addr, "", "", "", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	log.Debugf("Metadata request response Status: %v", resp.Status)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP GET request returned status %v", resp.Status)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	// Extract relevant content, avoiding xml errors of irrelevant sections
	scontent := string(content)
	startTag := "<pre>"
	endTag := "</pre>"
	startIdx := strings.Index(scontent, startTag)
	endIdx := (strings.Index(scontent, endTag))
	if startIdx == -1 || endIdx == -1 {
		return nil, fmt.Errorf("failed to extract xml from content: %v", scontent)
	}
	extracted := []byte(scontent[startIdx : endIdx+len(endTag)])

	// Parse root directory
	var pre Pre
	err = xml.Unmarshal(extracted, &pre)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal HTTP response: %w. Response: %v",
			err, string(content))
	}

	// Parse subdirectories recursively and save files
	data, err := fetchDataRecursively(client, pre, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch recursively: %w", err)
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

		log.Tracef("Requesting data from %v", subpath)
		resp, err := request(client.client, http.MethodGet, subpath, "", "", "", nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to perform request: %w", err)
		}
		defer resp.Body.Close()

		log.Tracef("Response Status: %v", resp.Status)
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("HTTP GET request returned status %v", resp.Status)
		}

		log.Tracef("Found: %v, type: %v", pre.Content[i].Name, resp.Header.Values("Content-Type")[0])

		if strings.Compare(resp.Header.Values("Content-Type")[0], "text/html; charset=utf-8") == 0 {

			// Content is a subdirectory, parse recursively
			content, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Errorf("Failed to read response: %v", err)
			}

			var pre Pre
			err = xml.Unmarshal(content, &pre)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal HTTP response: %w", err)
			}
			d, err := fetchDataRecursively(client, pre, subpath)
			metadata = append(metadata, d...)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch recursively: %w", err)
			}
		} else {

			// Content is a file, gather content
			d, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
			}

			metadata = append(metadata, d)
		}
	}
	return metadata, nil
}
