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
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"
)

// Wraps tls.Dial
// Additionally performs remote attestation
// before returning the established connection.
func Dial(network string, addr string, config *tls.Config, moreConfigs ...ConnectionOption[CmcConfig]) (*tls.Conn, error) {

	if config == nil {
		return nil, errors.New("failed to dial. TLS configuration not provided")
	}

	// Create TLS connection
	var dialer net.Dialer
	dialer.Timeout = timeout
	dialer.Deadline = (time.Now().Add(timeout))
	conn, err := tls.DialWithDialer(&dialer, network, addr, config)
	if err != nil {
		details := fmt.Sprintf("%v certificate chain(s) provided: ", len(config.Certificates))
		for _, cert := range config.Certificates {
			details = details + fmt.Sprintf("%v with SANS %v; ", cert.Leaf.Subject.CommonName, cert.Leaf.DNSNames)
		}
		return nil, fmt.Errorf("failed to establish tls connection: %w. %v", err, details)
	}

	cs := conn.ConnectionState()
	if !cs.HandshakeComplete {
		return nil, errors.New("internal error: handshake not complete")
	}
	log.Trace("TLS handshake complete, generating channel bindings")
	chbindings, err := cs.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to export keying material for channel binding: %w", err)
	}

	// Retrieve peer's TLS leaf certificate fingerprint to be used as peer ID for peer cache
	log.Trace("Retrieving TLS certificate fingerprint as peer ID")
	var fingerprint string
	if len(cs.PeerCertificates) > 0 {
		f := sha256.Sum256(cs.PeerCertificates[0].Raw)
		fingerprint = hex.EncodeToString(f[:])
	}

	// Get cmc Config: start with defaults
	cc := CmcConfig{
		CmcAddr: cmcAddrDefault,
		CmcApi:  CmcApis[cmcApiSelectDefault],
		Attest:  attestDefault,
	}
	for _, c := range moreConfigs {
		c(&cc)
	}

	// Check that selected API is implemented
	if cc.CmcApi == nil {
		return nil, fmt.Errorf("selected CMC API is not implemented")
	}

	// Perform remote attestation with unique channel binding as specified in RFC5056,
	// RFC5705, and RFC9266
	err = atlsHandshakeStart(conn, chbindings, fingerprint, cc, Endpoint_Client)
	err = aTlsHandshakeComplete(conn, err)
	if err != nil {
		return nil, fmt.Errorf("atls handshake failed: %w", err)
	}

	log.Info("Client-side aTLS connection complete")
	return conn, nil
}
