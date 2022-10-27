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

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"net"
	"os"

	log "github.com/sirupsen/logrus"

	// local modules
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
)

func main() {
	var cert tls.Certificate
	var err error
	var config *tls.Config

	caFile := flag.String("ca", "ca.pem", "TLS Certificate of CA / Entity that is RoT of the connector's TLS certificate")
	port := flag.String("cmcport", "9955", "TCP Port to connect to the CMC daemon gRPC interface")
	connectoraddress := flag.String("addr", "0.0.0.0:443", "ip:port on which to listen")
	policiesFile := flag.String("policies", "", "JSON policies file for custom verification")
	flag.Parse()

	log.SetLevel(log.TraceLevel)

	// Get root CA cert
	rootCA, err := os.ReadFile(*caFile)
	if err != nil {
		log.Error("[Testconnector] Could not find root CA cert file.")
		return
	}

	// Add root CA
	roots := x509.NewCertPool()
	success := roots.AppendCertsFromPEM(rootCA)
	if !success {
		log.Error("[Testconnector] Could not add cert to root CAs.")
		return
	}

	// Load certificate
	cert, err = atls.GetCert(atls.WithCmcPort(*port))
	if err != nil {
		log.Error("[Testconnector] failed to get TLS Certificate. ", err)
		return
	}

	// Add optional policies if present
	var policies []byte = nil
	if *policiesFile != "" {
		log.Debug("Policies specified. Adding them to verification request")
		policies, err = os.ReadFile(*policiesFile)
		if err != nil {
			log.Fatalf("Failed to read policies file: %v", err)
		}
	} else {
		log.Debug("No policies specified. Verifying with default parameters")
	}

	// Create TLS config
	config = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven, // make mTLS an option
		ClientCAs:    roots,
	}

	// Listen: TLS connection
	ln, err := atls.Listen("tcp", *connectoraddress, config, atls.WithCmcPort(*port), atls.WithCmcCa(rootCA), atls.WithCmcPolicies(policies))
	if err != nil {
		log.Error(err)
		log.Error("[Testconnector] Failed to listen for connections")
		return
	}
	defer ln.Close()

	for {
		log.Info("[Testconnector] serving under " + *connectoraddress)
		// Finish TLS connection establishment with Remote Attestation
		conn, err := ln.Accept()
		if err != nil {
			var attestedErr atls.AttestedError
			if errors.As(err, &attestedErr) {
				result, err := json.Marshal(attestedErr.GetVerificationResult())
				if err != nil {
					log.Errorf("[Testconnector] Internal error: failed to marshal verification result: %v", err)
				} else {
					log.Errorf("[Testconnector] Cannot establish connection: Remote attestation Failed. Verification Result: %v", string(result))
				}
			} else {
				log.Errorf("[Testconnector] Failed to establish connection: %v", err)
			}
			continue
		}
		// Handle established connections
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)

	// read
	msg, err := r.ReadString('\n')
	if err != nil {
		log.Error(err)
		log.Error("[Testconnector] Failed to read")
		return
	}
	println(msg)

	// write
	_, err = conn.Write([]byte("answer to : " + msg + "\n"))
	if err != nil {
		log.Error(err)
		log.Error("[Testconnector] Failed to write")
		return
	}
}
