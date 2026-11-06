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

package internal

import (
	"fmt"
	"strings"
)

// ParseApiEndpoint splits a CMC API endpoint into the API name and the address the API
// is served on or connected to. The expected form is <api>://<address>, e.g.
//
//	socket:///run/cmc/cmc.sock
//	socket://127.0.0.1:9955
//	grpc://127.0.0.1:9955
//	coap://127.0.0.1:9955
//
// APIs that do not take an address, such as the libapi, may be given as a bare name.
// The API name is not validated here, as the set of available APIs depends on the
// binary and its build tags.
func ParseApiEndpoint(endpoint string) (string, string, error) {

	e := strings.TrimSpace(endpoint)
	if e == "" {
		return "", "", fmt.Errorf("no CMC API endpoint configured")
	}

	if api, addr, found := strings.Cut(e, "://"); found {
		if api == "" {
			return "", "", fmt.Errorf("invalid CMC API endpoint %q: missing API", endpoint)
		}
		return strings.ToLower(api), addr, nil
	}

	// An API without an address, such as libapi
	if !strings.ContainsAny(e, ":/") {
		return strings.ToLower(e), "", nil
	}

	return "", "", fmt.Errorf(
		"invalid CMC API endpoint %q: expected <api>://<address>, e.g. socket:///run/cmc/cmc.sock or grpc://127.0.0.1:9955",
		endpoint)
}

// ParseModeAddr splits an option of the form <mode>[:<address>] into its mode and its
// address, e.g. "est:https://localhost:9000" into "est" and "https://localhost:9000".
// Modes that do not take an address, such as "direct", return an empty address.
func ParseModeAddr(s string) (string, string) {
	mode, addr, _ := strings.Cut(strings.TrimSpace(s), ":")
	return strings.ToLower(mode), strings.TrimSpace(addr)
}
