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
	"flag"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// Mode defines the mode the testclient should run
type Mode int

const (
	// Generate an attestation report (Mode)
	Generate = 0
	// Verify an attestatoin report (Mode)
	Verify = 1
	// Create a TLS connection with an exemplary connector = server (Mode)
	TLSConn = 2
)

const (
	timeoutSec = 10
)

type Api interface {
	generate(addr, reportFile, nonceFile string)
	verify(addr, reportFile, resultFile, nonceFile, caFile string, policies []byte)
	testTLSConn(destAddr, cmcAddr, ca string, mTLS bool, policies []byte)
}

var apis = map[string]Api{}

var log = logrus.WithField("service", "testclient")

func main() {
	logrus.SetLevel(logrus.TraceLevel)

	parsedMode := flag.String("mode", "generate", "[generate | verify | tlsconn ]")
	cmcAddr := flag.String("cmcAddr", "127.0.0.1:9955", "TCP address to connect to the CMC daemon gRPC interface")
	reportFile := flag.String("report", "attestation-report", "Output file for the attestation report")
	resultFile := flag.String("result", "attestation-result.json", "Output file for the attestation result")
	nonceFile := flag.String("nonce", "nonce", "Output file for the nonce")
	destAddr := flag.String("destAddr", "0.0.0.0:443", "ip:port to connect to the test connector")
	rootCACertFile := flag.String("ca", "ca.pem", "TLS Certificate of CA / Entity that is RoT of the connector's TLS certificate")
	mTLS := flag.Bool("mTLS", false, "Performs mutual TLS with remote attestation on both sides. Only in mode tlsconn")
	policiesFile := flag.String("policies", "", "JSON policies file for custom verification")
	apiFlag := flag.String("api", "grpc", "API to contact the cmcd (grpc or coap)")
	flag.Parse()

	var mode Mode
	if strings.EqualFold(*parsedMode, "generate") {
		mode = Generate
	} else if strings.EqualFold(*parsedMode, "verify") {
		mode = Verify
	} else if strings.EqualFold(*parsedMode, "tlsconn") {
		mode = TLSConn
	} else {
		log.Fatal("Wrong mode. Possible [Generate | Verify | TLSConn]")
	}

	api, ok := apis[strings.ToLower(*apiFlag)]
	if !ok {
		log.Fatalf("API '%v' is not implemented\n", *apiFlag)
	}

	// Add optional policies if present
	var policies []byte = nil
	if mode == Verify {
		var err error
		if *policiesFile != "" {
			log.Debug("Policies specified. Adding them to verification request")
			policies, err = os.ReadFile(*policiesFile)
			if err != nil {
				log.Fatalf("Failed to read policies file: %v", err)
			}
		} else {
			log.Debug("No policies specified. Verifying with default parameters")
		}
	}

	if mode == Generate {
		api.generate(*cmcAddr, *reportFile, *nonceFile)
	} else if mode == Verify {
		api.verify(*cmcAddr, *reportFile, *resultFile, *nonceFile, *rootCACertFile, policies)
	} else if mode == TLSConn {
		api.testTLSConn(*destAddr, *cmcAddr, *rootCACertFile, *mTLS, policies)
	} else {
		log.Println("Unknown mode")
	}
}
