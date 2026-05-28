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
	"net/http"
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
