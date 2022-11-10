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

package attestedtls

import (
	"crypto/tls"
	"fmt"
	"net"
)

// Wraps tls.Dial
// Additionally performs remote attestation
// before returning the established connection.
func Dial(network string, addr string, config *tls.Config, moreConfigs ...ConnectionOption[cmcConfig]) (*tls.Conn, error) {
	//use mTLS if client provides its own certificate
	mTLS := (config.Certificates != nil)

	// Create TLS connection
	var dialer net.Dialer
	dialer.Timeout = timeout
	conn, err := tls.DialWithDialer(&dialer, network, addr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to establish tls connection: %w", err)
	}

	// get cmc Config: start with defaults
	cc := cmcConfig{
		cmcAddress: cmcAddressDefault,
		cmcPort:    cmcPortDefault,
	}
	for _, c := range moreConfigs {
		c(&cc)
	}

	// Perform remote attestation
	// include components of tls.Conn to link both protocols: use peer (server) cert
	// FUTURE: check if certificate can be obtained differently
	err = verify(conn, conn.ConnectionState().PeerCertificates[0].Raw[:], cc)
	if err != nil {
		return nil, fmt.Errorf("failed to verify listener: %w", err)
	}

	if mTLS {
		log.Info("Performing mTLS: verifying dialer...")
		// attest itself: include own certificate in AR
		// Future: check if certificate can be obtained differently
		err = attest(conn, config.Certificates[0].Certificate[0], cc)
		if err != nil {
			return nil, fmt.Errorf("remote verification of dialer failed: %w", err)
		}
	} else {
		log.Info("No mTLS performed")
	}

	// finished
	log.Info("Client-side aTLS connection complete")
	return conn, nil
}
