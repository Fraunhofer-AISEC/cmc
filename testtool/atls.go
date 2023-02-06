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

package main

// Install github packages with "go get [url]"
import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"time"

	// local modules
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

/* Creates TLS connection between this client and a server and performs a remote
 * attestation of the server before exchanging few a exemplary messages with it
 */
func dial(api atls.CmcApiSelect, addr, cmcAddr string, mtls bool, ca, policies []byte) {
	var conf *tls.Config

	// Add root CA
	roots := x509.NewCertPool()
	success := roots.AppendCertsFromPEM(ca)
	if !success {
		log.Fatal("Could not add cert to root CAs")
	}

	if mtls {
		// Load own certificate
		var cert tls.Certificate
		cert, err := atls.GetCert(
			atls.WithCmcAddr(cmcAddr),
			atls.WithCmcApi(api))
		if err != nil {
			log.Fatalf("failed to get TLS Certificate: %v", err)
		}
		// Create TLS config with root CA and own certificate
		conf = &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      roots,
		}
	} else {
		// Create TLS config with root CA only
		conf = &tls.Config{
			RootCAs:       roots,
			Renegotiation: tls.RenegotiateNever,
		}
	}

	internal.PrintTlsConfig(conf, ca)

	conn, err := atls.Dial("tcp", addr, conf,
		atls.WithCmcAddr(cmcAddr),
		atls.WithCmcCa(ca),
		atls.WithCmcPolicies(policies),
		atls.WithCmcApi(api),
		atls.WithMtls(mtls))
	if err != nil {
		var attestedErr atls.AttestedError
		if errors.As(err, &attestedErr) {
			result, err := json.Marshal(attestedErr.GetVerificationResult())
			if err != nil {
				log.Fatalf("Internal error: failed to marshal verification result: %v",
					err)
			}
			log.Fatalf("Cannot establish connection: Remote attestation Failed. Verification Result: %v", string(result))
		}
		log.Fatalf("Failed to dial server: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeoutSec * time.Second))
	// write sth
	msg := "hello\n"
	log.Infof("Sending to peer: %v", msg)
	_, err = conn.Write([]byte(msg))
	if err != nil {
		log.Fatalf("Failed to write: %v", err)
	}
	// read sth
	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("Failed to read. %v", err)
	}
	log.Infof("Received from peer: %v", string(buf[:n-1]))
}

func listen(api atls.CmcApiSelect, addr, cmcAddr string, mtls bool, ca, policies []byte) {

	// Add root CA
	roots := x509.NewCertPool()
	success := roots.AppendCertsFromPEM(ca)
	if !success {
		log.Fatal("Could not add cert to root CAs")
	}

	// Load certificate
	cert, err := atls.GetCert(
		atls.WithCmcAddr(cmcAddr),
		atls.WithCmcApi(api))
	if err != nil {
		log.Fatalf("failed to get TLS Certificate: %v", err)
	}

	var clientAuth tls.ClientAuthType
	if mtls {
		// Mandate client authentication
		clientAuth = tls.RequireAndVerifyClientCert
	} else {
		// Make client authentication optional
		clientAuth = tls.VerifyClientCertIfGiven
	}

	// Create TLS config
	config := &tls.Config{
		Certificates:  []tls.Certificate{cert},
		ClientAuth:    clientAuth,
		ClientCAs:     roots,
		Renegotiation: tls.RenegotiateNever,
	}

	internal.PrintTlsConfig(config, ca)

	// Listen: TLS connection
	ln, err := atls.Listen("tcp", addr, config,
		atls.WithCmcAddr(cmcAddr),
		atls.WithCmcCa(ca),
		atls.WithCmcPolicies(policies),
		atls.WithCmcApi(api),
		atls.WithMtls(mtls))
	if err != nil {
		log.Fatalf("Failed to listen for connections: %v", err)
	}
	defer ln.Close()

	for {
		log.Infof("serving under %v", addr)
		// Finish TLS connection establishment with Remote Attestation
		conn, err := ln.Accept()
		if err != nil {
			var attestedErr atls.AttestedError
			if errors.As(err, &attestedErr) {
				result, err := json.Marshal(attestedErr.GetVerificationResult())
				if err != nil {
					log.Errorf("Internal error: failed to marshal verification result: %v", err)
				} else {
					log.Errorf("Cannot establish connection: Remote attestation Failed. Verification Result: %v", string(result))
				}
			} else {
				log.Errorf("Failed to establish connection: %v", err)
			}
			continue
		}
		// Handle established connections
		go handleConnection(conn)
	}
}

// Simply acts as an echo server and returns the received string
func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)

	msg, err := r.ReadString('\n')
	if err != nil {
		log.Errorf("Failed to read: %v", err)
	}
	log.Infof("Received from peer: %v", msg)

	log.Infof("Echoing: %v", msg)
	_, err = conn.Write([]byte(msg + "\n"))
	if err != nil {
		log.Errorf("Failed to write: %v", err)
	}
}
