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

package internal

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
)

// HTTP header constants
const (
	HttpAcceptHeader             = "Accept"
	HttpContentTypeHeader        = "Content-Type"
	HttpContentTypeOptionsHeader = "X-Content-Type-Options"
	HttpEncodingTypeBase64       = "base64"
	HttpParamValueCertsOnly      = "certs-only"
	HttpParamValueGenKey         = "server-generated-key"
	HttpRetryAfterHeader         = "Retry-After"
	HttpServerHeader             = "Server"
	HttpServerKeyGenBoundary     = "estServerKeyGenBoundary"
	HttpStrictTransportHeader    = "Strict-Transport-Security"
	HttpTransferEncodingHeader   = "Content-Transfer-Encoding"
	HttpUserAgentHeader          = "User-Agent"
)

// NewHttpClient returns an http.Client whose TLS root pool is built from the supplied
// rootCas and optionally the system cert pool. Client authentication (mTLS) is optional
func NewHttpClient(rootCas []*x509.Certificate, allowSystemCerts bool, clientCerts []tls.Certificate,
) (*http.Client, error) {

	rootpool, err := CreateCertPool(rootCas, allowSystemCerts)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert pool: %w", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            rootpool,
				InsecureSkipVerify: false,
				Certificates:       clientCerts,
			},
			DisableKeepAlives: false,
		},
	}

	return client, nil
}

func Request(
	client *http.Client,
	method, endpoint, accepts string,
	contentType, transferEncoding string,
	bearerToken []byte,
	body io.Reader,
) (*http.Response, error) {

	log.Debugf("Sending EST %v request to %v", method, endpoint)

	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("failed to make new HTTP request: %w", err)
	}

	if accepts != "" {
		req.Header.Set(HttpAcceptHeader, accepts)
	}
	if contentType != "" {
		req.Header.Set(HttpContentTypeHeader, contentType)
	}
	if transferEncoding != "" {
		req.Header.Set(HttpTransferEncodingHeader, transferEncoding)
	}
	if bearerToken != nil {
		log.Trace("Adding bootstrap token to authorization header")
		req.Header.Set("Authorization", "Bearer "+string(bearerToken))
	} else {
		log.Tracef("Sending request without authorization token")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform HTTP request: %w", err)
	}

	log.Debug("Finished EST HTTP request")

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		payload, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
		}
		return nil, fmt.Errorf("HTTP Server responded %v: %v", resp.Status, string(payload))
	}

	return resp, nil
}
