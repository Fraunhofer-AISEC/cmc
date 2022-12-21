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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	// local modules
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

/* Creates TLS connection between this client and a server and performs a remote
 * attestation of the server before exchanging few a exemplary messages with it
 */
func testTLSConnInternal(api atls.CmcApiSelect, destAddr, cmcAddr, ca string, mTLS bool, policies []byte) {
	var conf *tls.Config

	// get root CA cert
	rootCA, err := os.ReadFile(ca)
	if err != nil {
		log.Error(err)
		log.Fatal("Could not find root CA cert file")
	}

	// Add root CA
	roots := x509.NewCertPool()
	success := roots.AppendCertsFromPEM(rootCA)
	if !success {
		log.Fatal("Could not add cert to root CAs")
	}

	addrParts := strings.Split(cmcAddr, ":")
	if len(addrParts) != 2 {
		log.Fatal("Invalid Address, must be <address>:<port>")
	}

	if mTLS {
		// Load own certificate
		var cert tls.Certificate
		cert, err = atls.GetCert(
			atls.WithCmcAddress(addrParts[0]),
			atls.WithCmcPort(addrParts[1]),
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
			RootCAs: roots,
		}
	}

	internal.PrintTlsConfig(conf, rootCA)

	conn, err := atls.Dial("tcp", destAddr, conf,
		atls.WithCmcAddress(addrParts[0]),
		atls.WithCmcPort(addrParts[1]),
		atls.WithCmcCa(rootCA),
		atls.WithCmcPolicies(policies),
		atls.WithCmcApi(api))
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
		log.Fatalf("failed to dial server: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeoutSec * time.Second))
	// write sth
	_, err = conn.Write([]byte("hello\n"))
	if err != nil {
		log.Fatalf("failed to write: %v", err)
	}
	// read sth
	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("failed to read. %v", err)
	}
	log.Info("received: " + string(buf[:n]))
}
