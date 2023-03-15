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
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/Fraunhofer-AISEC/cmc/est/client"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// Mode defines the mode to be run
type Mode int

const (
	Generate = 0 // Generate an attestation report
	Verify   = 1 // Verify an attestation report
	Dial     = 2 // Act as client to establish an attested TLS connection
	Listen   = 3 // Act as server in etsblishing attested TLS connections
	CaCerts  = 4 // Retrieve CA certs from EST server
	IoTHub   = 5 // Simulate an IoT hub for Cortex-M IAS Attestation Demo
)

const (
	timeoutSec = 10
)

type Api interface {
	generate(c *config)
	verify(c *config)
	dial(c *config)
	listen(c *config)
}

var apis = map[string]Api{}

var log = logrus.WithField("service", "testtool")

type config struct {
	Mode         string
	Addr         string
	CmcAddr      string
	ReportFile   string
	ResultFile   string
	NonceFile    string
	CaFile       string
	Mtls         bool
	PoliciesFile string
	ApiFlag      string

	ca       []byte
	policies []byte
}

func getConfig() *config {
	var err error

	// configFile := flag.String("config", "", "configuration file")
	modeFlag := flag.String("mode", "generate", "[generate | verify | dial  | listen | cacerts | iothub ]")
	addr := flag.String("addr", "0.0.0.0:443", "server ip:port to connect to / listen on via attested tls")
	cmcAddr := flag.String("cmc", "127.0.0.1:9955", "TCP address to connect to the cmcd API")
	reportFile := flag.String("report", "attestation-report", "Output file for the attestation report")
	resultFile := flag.String("result", "attestation-result.json", "Output file for the attestation result")
	nonceFile := flag.String("nonce", "nonce", "Output file for the nonce")
	caFile := flag.String("ca", "", "TLS Certificate of CA / Entity that is RoT of the connector's TLS certificate")
	mtls := flag.Bool("mtls", false, "Performs mutual TLS with remote attestation on both sides. Only in mode tlsconn")
	policiesFile := flag.String("policies", "", "JSON policies file for custom verification")
	apiFlag := flag.String("api", "grpc", fmt.Sprintf("API to contact the cmcd. Possible: %v", maps.Keys(apis)))
	flag.Parse()

	c := &config{
		Mode:         *modeFlag,
		Addr:         *addr,
		CmcAddr:      *cmcAddr,
		ReportFile:   *reportFile,
		ResultFile:   *resultFile,
		NonceFile:    *nonceFile,
		CaFile:       *caFile,
		Mtls:         *mtls,
		PoliciesFile: *policiesFile,
		ApiFlag:      *apiFlag,
	}

	// Get root CA certificate in PEM format if specified
	if c.CaFile != "" {
		c.ca, err = os.ReadFile(c.CaFile)
		if err != nil {
			log.Fatalf("Failed to read file %v: %v", *caFile, err)
		}
	}

	// Add optional policies if specified
	if c.PoliciesFile != "" {
		log.Debug("Adding specified policies")
		c.policies, err = os.ReadFile(c.PoliciesFile)
		if err != nil {
			log.Fatalf("Failed to read policies file: %v", err)
		}
	}

	return c
}

func main() {
	logrus.SetLevel(logrus.TraceLevel)

	c := getConfig()

	var mode Mode
	if strings.EqualFold(c.Mode, "generate") {
		mode = Generate
	} else if strings.EqualFold(c.Mode, "verify") {
		mode = Verify
	} else if strings.EqualFold(c.Mode, "dial") {
		mode = Dial
	} else if strings.EqualFold(c.Mode, "listen") {
		mode = Listen
	} else if strings.EqualFold(c.Mode, "cacerts") {
		mode = CaCerts
	} else {
		log.Errorf("Undefined mode %v", c.Mode)
		flag.Usage()
		return
	}

	api, ok := apis[strings.ToLower(c.ApiFlag)]
	if !ok {
		log.Errorf("API %v is not implemented\n", c.ApiFlag)
		flag.Usage()
		return
	}

	switch mode {
	case Generate:
		api.generate(c)
	case Verify:
		api.verify(c)
	case Dial:
		api.dial(c)
	case Listen:
		api.listen(c)
	case CaCerts:
		getCaCerts(c)
	default:
		log.Fatalf("Unknown mode %v", mode)
	}
}

func getCaCerts(c *config) {
	log.Info("Retrieving CA certs")
	estclient := client.NewClient(nil)
	certs, err := estclient.CaCerts(c.Addr)
	if err != nil {
		log.Fatalf("Failed to retrieve certificates: %v", err)
	}
	log.Debug("Received certs:")
	for _, c := range certs {
		log.Debugf("\t%v", c.Subject.CommonName)
	}
	// Store CA certificate
	err = os.WriteFile(c.CaFile, internal.WriteCertPem(certs[len(certs)-1]), 0644)
	if err != nil {
		log.Fatalf("Failed to store CA certificate: %v", err)
	}
}
