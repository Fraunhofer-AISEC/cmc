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
	"strings"

	"github.com/sirupsen/logrus"
)

var (
	log = logrus.WithField("service", "testtool")

	cmds = map[string]func(*config){
		"generate": generate,   // Generate an attestation report
		"verify":   verify,     // Verify an attestation report
		"dial":     dial,       // Act as client to establish an attested TLS connection
		"listen":   listen,     // Act as server in etsblishing attested TLS connections
		"caCerts":  getCaCerts, // Retrieve CA certs from EST server
		"ioTHub":   iotHub,     // Simulate an IoT hub for Cortex-M IAS Attestation Demo
	}
)

func main() {
	logrus.SetLevel(logrus.TraceLevel)

	c := getConfig()

	cmd, ok := cmds[strings.ToLower(c.Mode)]
	if !ok {
		log.Errorf("Undefined mode %v", c.Mode)
		flag.Usage()
		return
	}

	cmd(c)
}
