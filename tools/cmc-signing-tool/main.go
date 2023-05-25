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
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/fxamacker/cbor/v2"
)

type Serializer interface {
	Sign(data []byte, keys []crypto.PrivateKey, x5cs [][]*x509.Certificate) ([]byte, error)
}

func main() {
	log.SetLevel(log.TraceLevel)

	metadata := flag.String("in", "", "Path to input metadata as JSON or CBOR to be signed")
	keyFiles := flag.String("keys", "", "Paths to keys in PEM format to be used for signing, as a comma-separated list")
	x5cFiles := flag.String("x5cs", "", "Paths to PEM encoded x509 certificate chains. Certificate chains must begin with the leaf certificates, the single certificates must be comma-separated. The certificate chains must be colon separated, e.g.: '--x5cs leaf1,intermediate1,ca1:leaf2,intermediate2,ca2")
	outputFile := flag.String("out", "", "Path to the output file to save signed metadata")
	flag.Parse()

	if *metadata == "" {
		log.Error("input metadata file not specified (-in)")
		flag.Usage()
		return
	}
	if *keyFiles == "" {
		log.Error("key file(s) not specified (-keys)")
		flag.Usage()
		return
	}
	if *x5cFiles == "" {
		log.Error("certificate chain file(s) not specified (-x5cs)")
		flag.Usage()
		return
	}
	if *outputFile == "" {
		log.Error("output file not specified (-out)")
		flag.Usage()
		return
	}

	// Load metadata
	log.Infof("Reading: %v", *metadata)
	data, err := os.ReadFile(*metadata)
	if err != nil {
		log.Fatalf("failed to read metadata file %v", *metadata)
	}

	// Load keys from file system
	s1 := strings.Split(*keyFiles, ",")
	keysPem := make([][]byte, 0)
	for _, keyFile := range s1 {
		k, err := os.ReadFile(keyFile)
		if err != nil {
			log.Fatalf("failed to read key file %v", err)
		}
		keysPem = append(keysPem, k)
	}

	// Load certificate chains, splitted by colons, from file system
	certChainsPem := make([][][]byte, 0)
	chains := strings.Split(*x5cFiles, ":")
	for _, chain := range chains {

		// Load certificates in chain, splitted by commas
		certChainPem := make([][]byte, 0)
		certFiles := strings.Split(chain, ",")
		for _, certFile := range certFiles {

			certPem, err := os.ReadFile(certFile)
			if err != nil {
				log.Fatalf("failed to read certificate(s) file %v", err)
			}
			certChainPem = append(certChainPem, certPem)
		}
		certChainsPem = append(certChainsPem, certChainPem)
	}

	signedData, err := sign(data, keysPem, certChainsPem)
	if err != nil {
		log.Fatalf("Failed to sign data: %v", err)
	}

	log.Infof("Writing  %v", *outputFile)
	err = os.WriteFile(*outputFile, signedData, 0644)
	if err != nil {
		log.Fatalf("failed to write output file: %v", err)
	}

	log.Tracef("Finished")
}

func sign(data []byte, keysPem [][]byte, chainsPem [][][]byte) ([]byte, error) {

	// Load keys
	keys := make([]crypto.PrivateKey, 0)
	for _, keyPem := range keysPem {
		block, _ := pem.Decode(keyPem)
		if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") {
			return nil, errors.New("failed to decode PEM block containing private key")
		}

		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err == nil {
			keys = append(keys, key)
		} else {
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key: %w", err)
			}
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("no valid keys specified")
	}
	log.Tracef("Read %v private keys", len(keys))

	// Load certificate chains
	certChains := make([][]*x509.Certificate, 0)
	for i, chainPem := range chainsPem {
		certChain := make([]*x509.Certificate, 0)
		for _, certPem := range chainPem {
			c, err := internal.ParseCertPem(certPem)
			if err != nil {
				return nil, fmt.Errorf("failed to load certificates: %w", err)
			}
			certChain = append(certChain, c)
		}
		if len(certChain) == 0 {
			return nil, fmt.Errorf("certificate chain %v is empty", i)
		}
		certChains = append(certChains, certChain)
	}
	if len(certChains) == 0 {
		return nil, errors.New("no valid certificates specified")
	}
	log.Tracef("Read %v certificate chains", len(certChains))

	if len(certChains) != len(keys) {
		return nil, fmt.Errorf("number of certificates (%v) does not match number of keys (%v)",
			len(certChains), len(keys))
	}

	// Detect serialization format. Currently, JSON and CBOR are supported
	var s Serializer
	if json.Valid(data) {
		log.Trace("Detected JSON serialization")
		s = JsonSerializer{}
	} else if err := cbor.Valid(data); err == nil {
		log.Trace("Detected CBOR serialization")
		s = CborSerializer{}
	} else {
		return nil, errors.New("failed to detect serialization (only JSON and CBOR are supported)")
	}

	// Sign metadata
	signedData, err := s.Sign(data, keys, certChains)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	log.Trace("Signed metadata")

	return signedData, nil
}
