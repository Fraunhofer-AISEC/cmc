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

package attestedtls

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// tlsHandshakeError enriches a failed TLS handshake with diagnostic information.
func tlsHandshakeError(err error, config *tls.Config, peer, serverName string) error {

	// The configured root CAs are only available as a pool and therefore not listed
	details := internal.TlsErrorDetails(err, config, serverName, nil)
	if details == "" {
		return fmt.Errorf("failed to establish tls connection to %v: %w", peer, err)
	}
	return fmt.Errorf("failed to establish tls connection to %v: %w\n%v", peer, err, details)
}

// serverName returns the name the peer certificate is validated against: the explicitly
// configured SNI name, or otherwise the host part of the dialed address.
func serverName(config *tls.Config, peer string) string {
	if config.ServerName != "" {
		return config.ServerName
	}
	host, _, err := net.SplitHostPort(peer)
	if err != nil {
		return ""
	}
	return host
}
