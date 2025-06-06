// Copyright (c) 2021 - 2025 Fraunhofer AISEC
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
	"flag"
	"strings"
)

var (
	cmds = map[string]func(*config){
		"cacerts":   cacerts,   // Retrieve CA certs from EST server
		"generate":  generate,  // Generate an attestation report
		"verify":    verify,    // Verify an attestation report
		"measure":   measure,   // Record measurements
		"dial":      dial,      // Act as client to establish an attested TLS connection
		"listen":    listen,    // Act as server in etsblishing attested TLS connections
		"request":   request,   // Perform an attested HTTPS request
		"serve":     serve,     // Establish an attested HTTPS server
		"token":     token,     // Request a bootstrap-token for EST certificate requests
		"provision": provision, // Retrieve provisioning data for CVMs
	}
)

func main() {

	c := getConfig()

	cmd, ok := cmds[strings.ToLower(c.Mode)]
	if !ok {
		log.Errorf("Undefined mode %v", c.Mode)
		flag.Usage()
		return
	}

	cmd(c)
}
