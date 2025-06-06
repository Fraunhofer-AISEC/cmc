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
	"crypto/x509"
	"os"

	// local modules

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision/estclient"
)

func getCaCerts(c *config) {
	addr := ""
	if len(c.Addr) > 0 {
		addr = c.Addr[0]
	}

	log.Info("Retrieving CA certs")

	estTlsCas := make([]*x509.Certificate, 0, len(c.EstTlsCas))
	for _, file := range c.EstTlsCas {
		log.Tracef("Reading EST TLS CA certificate from %v", file)
		ca, err := internal.ReadCert(file)
		if err != nil {
			log.Fatalf("Failed to read EST TLS CA certificate: %v", err)
		}
		estTlsCas = append(estTlsCas, ca)
	}

	client, err := estclient.NewClient(estTlsCas, c.EstTlsSysRoots, nil)
	if err != nil {
		log.Fatalf("Failed to create EST client: %v", err)
	}

	certs, err := client.CaCerts(addr)
	if err != nil {
		log.Fatalf("Failed to retrieve certificates: %v", err)
	}
	log.Debug("Received certs:")
	for _, c := range certs {
		log.Debugf("\t%v", c.Subject.CommonName)
	}
	// Store CA certificate
	err = os.WriteFile(c.EstCa, internal.WriteCertPem(certs[len(certs)-1]), 0644)
	if err != nil {
		log.Fatalf("Failed to store CA certificate: %v", err)
	}
}
