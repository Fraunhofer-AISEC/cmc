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
	"os"

	// local modules

	est "github.com/Fraunhofer-AISEC/cmc/est/estclient"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

func getCaCertsInternal(c *config) {
	addr := ""
	if len(c.Addr) > 0 {
		addr = c.Addr[0]
	}

	log.Info("Retrieving CA certs")
	client := est.NewClient(nil)
	certs, err := client.CaCerts(addr)
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
