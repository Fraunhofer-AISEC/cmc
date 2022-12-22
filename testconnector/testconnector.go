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
	"strings"

	"github.com/sirupsen/logrus"

	// local modules
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

var log = logrus.WithField("service", "testconnector")

func main() {
	var cert tls.Certificate
	var err error
	var config *tls.Config

	caFile := flag.String("ca", "ca.pem", "TLS Certificate of CA / Entity that is RoT of the connector's TLS certificate")
	port := flag.String("cmcport", "9955", "TCP Port to connect to the CMC daemon")
	connectoraddress := flag.String("addr", "0.0.0.0:443", "ip:port on which to listen")
	policiesFile := flag.String("policies", "", "JSON policies file for custom verification")
	apiFlag := flag.String("api", "grpc", "API to contact the cmcd (grpc or coap)")
	flag.Parse()

	logrus.SetLevel(logrus.TraceLevel)

	// Get root CA cert
	rootCA, err := os.ReadFile(*caFile)
	if err != nil {
		log.Error("Could not find root CA cert file.")
		return
	}

	// Add root CA
	roots := x509.NewCertPool()
	success := roots.AppendCertsFromPEM(rootCA)
	if !success {
		log.Error("Could not add cert to root CAs.")
		return
	}

	// Get API
	var api atls.CmcApiSelect
	if strings.EqualFold(*apiFlag, "grpc") {
		log.Info("Using CMC gRPC API")
		api = atls.CmcApi_GRPC
	} else if strings.EqualFold(*apiFlag, "coap") {
		log.Info("Using CMC CoAP API")
		api = atls.CmcApi_COAP
	} else {
		log.Fatalf("API type '%v' is not supported", *apiFlag)
	}

	// Load certificate
	cert, err = atls.GetCert(
		atls.WithCmcAddress("127.0.0.1"),
		atls.WithCmcPort(*port),
		atls.WithCmcApi(api))
	if err != nil {
		log.Fatalf("failed to get TLS Certificate: %v", err)
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

	internal.PrintTlsConfig(config, rootCA)

	// Listen: TLS connection
	ln, err := atls.Listen("tcp", *connectoraddress, config,
		atls.WithCmcAddress("127.0.0.1"),
		atls.WithCmcPort(*port),
		atls.WithCmcCa(rootCA),
		atls.WithCmcPolicies(policies),
		atls.WithCmcApi(api))
	if err != nil {
		log.Fatalf("Failed to listen for connections: %v", err)
	}
	defer ln.Close()

	for {
		log.Info("serving under " + *connectoraddress)
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

func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)

	// read
	msg, err := r.ReadString('\n')
	if err != nil {
		log.Error(err)
		log.Error("Failed to read")
		return
	}
	println(msg)

	// write
	_, err = conn.Write([]byte("answer to : " + msg + "\n"))
	if err != nil {
		log.Error(err)
		log.Error("Failed to write")
		return
	}
}
