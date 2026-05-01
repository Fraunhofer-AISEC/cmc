// Copyright (c) 2026 Fraunhofer AISEC
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

package provision

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// OmspRequests are used for requesting information about the revocation status of SW manifests
// The respective OmspResponses are defined in the attestationreport package as the struct should fit the generic Metadata template
type OmspRequest struct {
	ArVersion      string   `json:"arVersion" cbor:"0,keyasint"`
	ManifestHashes []string `json:"requests" cbor:"1,keyasint"`
}

// FetchRevocationStatus fetches evidence of the current revocation status for all used manifests from a remote server
// possibly add parameter for manifest identifiers
func FetchRevocationStatus(endpoint string, or OmspRequest, ser ar.Serializer, rootCas []*x509.Certificate, useSystemRoots bool) ([]byte, error) {
	log.Tracef("Requesting OMSP")

	client, err := NewHttpClient(rootCas, useSystemRoots, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create OMSP client: %w", err)
	}

	method := http.MethodPost
	orbody, err := ser.Marshal(or)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OMSP request: %w", err)
	}
	body := io.NopCloser(bytes.NewBuffer(orbody))

	log.Debug("Sending OMSP request")
	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("failed to make new HTTP request: %w", err)
	}

	if ser.String() == "JSON" {
		req.Header.Set("Content-Type", "application/json")
	} else if ser.String() == "CBOR" {
		req.Header.Set("Content-Type", "application/cbor")
	} else {
		return nil, fmt.Errorf("serializer %v not supported", ser.String())
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform HTTP request: %w", err)
	}
	defer resp.Body.Close()
	log.Debug("Finished OMSP HTTP request")

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Server responded %v: %v", resp.Status, string(payload))
	}

	log.Tracef("Received OMSP response with content %v", string(payload))
	return payload, nil
}
