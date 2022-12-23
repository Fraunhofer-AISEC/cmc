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

// Mode defines the mode to be run
type Mode int

const (
	Generate = 0 // Generate an attestation report
	Verify   = 1 // Verify an attestation report
	Dial     = 2 // Act as client to establish an attested TLS connection
	Listen   = 3 // Act as server in etsblishing attested TLS connections
)

const (
	timeoutSec = 10
)

type Api interface {
	generate(addr, reportFile, nonceFile string)
	verify(addr, reportFile, resultFile, nonceFile string, ca, policies []byte)
	dial(addr, cmcAddr string, mtls bool, ca, policies []byte)
	listen(addr, cmcAddr string, mtls bool, ca, policies []byte)
}

var apis = map[string]Api{}

var log = logrus.WithField("service", "testtool")

func main() {
	logrus.SetLevel(logrus.TraceLevel)

	modeFlag := flag.String("mode", "generate", "[generate | verify | dial  | listen ]")
	addr := flag.String("addr", "0.0.0.0:443", "server ip:port to connect to / listen on via attested tls")
	cmcAddr := flag.String("cmc", "127.0.0.1:9955", "TCP address to connect to the cmcd API")
	reportFile := flag.String("report", "attestation-report", "Output file for the attestation report")
	resultFile := flag.String("result", "attestation-result.json", "Output file for the attestation result")
	nonceFile := flag.String("nonce", "nonce", "Output file for the nonce")
	caFile := flag.String("ca", "ca.pem", "TLS Certificate of CA / Entity that is RoT of the connector's TLS certificate")
	mtls := flag.Bool("mtls", false, "Performs mutual TLS with remote attestation on both sides. Only in mode tlsconn")
	policiesFile := flag.String("policies", "", "JSON policies file for custom verification")
	apiFlag := flag.String("api", "grpc", "API to contact the cmcd (grpc or coap)")
	flag.Parse()

	var mode Mode
	if strings.EqualFold(*modeFlag, "generate") {
		mode = Generate
	} else if strings.EqualFold(*modeFlag, "verify") {
		mode = Verify
	} else if strings.EqualFold(*modeFlag, "dial") {
		mode = Dial
	} else if strings.EqualFold(*modeFlag, "listen") {
		mode = Listen
	} else {
		log.Fatal("Wrong mode. Possible [Generate | Verify | TLSConn]")
	}

	api, ok := apis[strings.ToLower(*apiFlag)]
	if !ok {
		log.Fatalf("API '%v' is not implemented\n", *apiFlag)
	}

	// Get root CA certificate in PEM format
	var ca []byte
	var err error
	if mode != Generate {
		ca, err = os.ReadFile(*caFile)
		if err != nil {
			log.Fatalf("Failed to read file %v: %v", *caFile, err)
		}
	}

	// Add optional policies if present
	var policies []byte = nil
	if *policiesFile != "" {
		log.Debug("Adding specified policies")
		policies, err = os.ReadFile(*policiesFile)
		if err != nil {
			log.Fatalf("Failed to read policies file: %v", err)
		}
	}

	if mode == Generate {
		api.generate(*cmcAddr, *reportFile, *nonceFile)
	} else if mode == Verify {
		api.verify(*cmcAddr, *reportFile, *resultFile, *nonceFile, ca, policies)
	} else if mode == Dial {
		api.dial(*addr, *cmcAddr, *mtls, ca, policies)
	} else if mode == Listen {
		api.listen(*addr, *cmcAddr, *mtls, ca, policies)
	} else {
		log.Fatalf("Unknown mode %v", mode)
	}
}
