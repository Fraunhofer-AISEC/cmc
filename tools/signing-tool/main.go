// Copyright(c) 2021 Fraunhofer AISEC
// Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the License); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an AS IS BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"os"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	log "github.com/sirupsen/logrus"
)

type Serializer interface {
	Sign(data []byte, keys []crypto.PrivateKey, x5cs [][]*x509.Certificate) ([]byte, error)
}

func main() {
	log.SetLevel(log.TraceLevel)

	metadata := flag.String("in", "", "Path to input metadata as JSON or CBOR to be signed")
	keyFiles := flag.String("keys", "", "Paths to keys in PEM format to be used for signing, as a comma-separated list")
	x5cFiles := flag.String("x5cs", "", "Paths to PEM encoded x509 certificate chains. Certificate chains must begin with the leaf certificates, the single certificates must be comma-separated. The certificate chains must be colon separated, e.g.: '--x5cs leaf1,intermediate1,ca1:leaf2,intermediate2,ca2")
	format := flag.String("format", "JSON", "Format of the metadata (JSON or CBOR)")
	outputFile := flag.String("out", "", "Path to the output file to save signed metadata")
	flag.Parse()

	if *metadata == "" {
		log.Error("input metadata file not specified (--in)")
		flag.Usage()
		return
	}
	if *keyFiles == "" {
		log.Error("key file(s) not specified (--keys)")
		flag.Usage()
		return
	}
	if *x5cFiles == "" {
		log.Error("certificate chain file(s) not specified (--x5cs)")
		flag.Usage()
		return
	}
	if *outputFile == "" {
		log.Error("output file not specified (--out)")
		flag.Usage()
		return
	}

	// Load metadata
	data, err := os.ReadFile(*metadata)
	if err != nil {
		log.Fatalf("failed to read metadata file %v", *metadata)
	}

	// Load keys
	s1 := strings.Split(*keyFiles, ",")
	keys := make([]crypto.PrivateKey, 0)
	for _, keyFile := range s1 {
		keyPem, err := os.ReadFile(keyFile)
		if err != nil {
			log.Fatalf("failed to read key file %v", err)
		}

		block, _ := pem.Decode(keyPem)
		if block == nil || block.Type != "EC PRIVATE KEY" {
			log.Fatal("failed to decode PEM block containing private key")
		}

		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			log.Fatal("Failed to parse private key")
		}

		keys = append(keys, key)
	}
	if len(keys) == 0 {
		log.Fatal("No valid keys specified")
	}
	log.Tracef("Read %v private keys", len(keys))

	// Load certificate chains, splitted by colons
	certChains := make([][]*x509.Certificate, 0)
	chains := strings.Split(*x5cFiles, ":")
	for _, chain := range chains {

		// Load certificates in chain, splitted by commas
		certChain := make([]*x509.Certificate, 0)
		certFiles := strings.Split(chain, ",")
		for _, certFile := range certFiles {

			certPem, err := os.ReadFile(certFile)
			if err != nil {
				log.Fatalf("failed to read certificate(s) file %v", err)
			}

			c, err := ar.LoadCert(certPem)
			if err != nil {
				log.Fatalf("Failed to load certificates: %v", err)
			}

			certChain = append(certChain, c)
		}
		certChains = append(certChains, certChain)
	}
	if len(certChains) == 0 {
		log.Fatal("No valid certificates specified")
	}
	log.Tracef("Read %v certificate chains", len(certChains))

	if len(certChains) != len(keys) {
		log.Fatalf("Number of certificates (%v) does not match number of keys (%v)", len(certChains), len(keys))
	}

	// Create serializer based on specified format
	var s Serializer
	if strings.EqualFold(*format, "json") {
		s = JsonSerializer{}
	} else if strings.EqualFold(*format, "cbor") {
		s = CborSerializer{}
	} else {
		log.Fatalf("Serializer %v not supported (only JSON and CBOR are supported)", *format)
	}

	// Sign metadata
	signedData, err := s.Sign(data, keys, certChains)
	if err != nil {
		log.Fatalf("failed to sign data: %v", err)
	}

	log.Trace("Signed metadata")

	log.Tracef("Writing metadata to file %v", *outputFile)
	err = os.WriteFile(*outputFile, signedData, 0644)
	if err != nil {
		log.Fatalf("failed to write output file: %v", err)
	}

	log.Tracef("Finished")
}
