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

package internal

import (
	"fmt"
	"strings"
)

type AuthMethod uint32

const (
	AuthNone  AuthMethod = 0
	AuthToken AuthMethod = 1 << iota
	AuthCertificate
	AuthAttestation
)

func ParseAuthMethods(input []string) (AuthMethod, error) {
	var methods AuthMethod
	for _, part := range input {
		switch strings.TrimSpace(strings.ToLower(part)) {
		case "none":
			methods |= AuthNone
		case "token":
			methods |= AuthToken
		case "certificate":
			methods |= AuthCertificate
		case "attestation":
			methods |= AuthAttestation
		default:
			return 0, fmt.Errorf("unknown auth method: %q", part)
		}
	}
	return methods, nil
}

func (a AuthMethod) Has(method AuthMethod) bool {
	return a&method != 0
}

func (a AuthMethod) String() string {
	if a == AuthNone {
		return "none"
	}

	var parts []string
	if a.Has(AuthToken) {
		parts = append(parts, "token")
	}
	if a.Has(AuthCertificate) {
		parts = append(parts, "certificate")
	}
	if a.Has(AuthAttestation) {
		parts = append(parts, "attestation")
	}

	return strings.Join(parts, ",")
}
