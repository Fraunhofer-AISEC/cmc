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
	"net"
	"os"
	"strings"
)

func Fqdn() (string, error) {

	//Get short hostname
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	// Resolve to FQDN via reverse lookup
	addrs, err := net.LookupIP(hostname)
	if err != nil || len(addrs) == 0 {
		return hostname, nil // Fallback to short hostname
	}
	for _, ip := range addrs {
		names, err := net.LookupAddr(ip.String())
		if err == nil && len(names) > 0 {
			return strings.TrimSuffix(names[0], "."), nil
		}
	}

	return hostname, nil
}
