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
	"flag"
	"io/ioutil"
	"net"

	log "github.com/sirupsen/logrus"

	// local modules
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
)

func main() {
	var cert tls.Certificate
	var err error
	var config *tls.Config

	rootCACertFile := flag.String("rootcacertfile", "ca.pem", "TLS Certificate of CA / Entity that is RoT of the connector's TLS certificate")
	port := flag.String("port", "9955", "TCP Port to connect to the CMC daemon gRPC interface")
	connectoraddress := flag.String("connector", "0.0.0.0:443", "ip:port on which to listen")
	policiesFile := flag.String("policies", "", "JSON policies file for custom verification")
	flag.Parse()

	log.SetLevel(log.TraceLevel)

	// Get root CA cert
	rootCA, err := ioutil.ReadFile(*rootCACertFile)
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
		policies, err = ioutil.ReadFile(*policiesFile)
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
			log.Error(err)
			ae, ok := err.(atls.AttestedError)
			if ok {
				log.Error(ae.GetVerificationResult())
			}
			log.Error("[Testconnector] Failed to establish connection")
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
