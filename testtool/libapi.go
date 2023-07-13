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

//go:build !nodefaults || libapi

package main

// Install github packages with "go get [url]"
import (

	// local modules

	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
)

type LibApi struct {
	cmc *cmc.Cmc
}

func init() {
	apis["libapi"] = LibApi{}
}

func (a LibApi) generate(c *config) {

	if a.cmc == nil {
		cmc, err := initialize(c)
		if err != nil {
			log.Errorf("failed to initialize CMC: %v", err)
			return
		}
		a.cmc = cmc
	}

	// Generate random nonce
	nonce := make([]byte, 8)
	_, err := rand.Read(nonce)
	if err != nil {
		log.Fatalf("Failed to read random bytes: %v", err)
	}

	// Generate attestation report
	report, err := ar.Generate(nonce, a.cmc.Metadata, a.cmc.Drivers, a.cmc.Serializer)
	if err != nil {
		log.Errorf("Failed to generate attestation report: %v", err)
		return
	}

	// Sign attestation report
	log.Debug("Prover: Signing Attestation Report")
	r, err := ar.Sign(report, a.cmc.Drivers[0], a.cmc.Serializer)
	if err != nil {
		log.Errorf("Failed to sign attestation report: %v", err)
		return
	}

	// Save the attestation report for the verifier
	err = os.WriteFile(c.ReportFile, r, 0644)
	if err != nil {
		log.Fatalf("Failed to save attestation report as %v: %v", c.ReportFile, err)
	}
	fmt.Println("Wrote attestation report: ", c.ReportFile)

	// Save the nonce for the verifier
	os.WriteFile(c.NonceFile, nonce, 0644)
	if err != nil {
		log.Fatalf("Failed to save nonce as %v: %v", c.NonceFile, err)
	}
	fmt.Println("Wrote nonce: ", c.NonceFile)
}

func (a LibApi) verify(c *config) {
	if a.cmc == nil {
		cmc, err := initialize(c)
		if err != nil {
			log.Errorf("failed to initialize CMC: %v", err)
			return
		}
		a.cmc = cmc
	}

	// Read the attestation report, CA and the nonce previously stored
	report, err := os.ReadFile(c.ReportFile)
	if err != nil {
		log.Fatalf("Failed to read file %v: %v", c.ReportFile, err)
	}

	nonce, err := os.ReadFile(c.NonceFile)
	if err != nil {
		log.Fatalf("Failed to read nonce: %v", err)
	}

	// Verify the attestation report
	result := ar.Verify(report, nonce, c.ca, c.policies, a.cmc.PolicyEngineSelect)

	log.Debug("Verifier: Marshaling Attestation Result")
	r, err := json.Marshal(result)
	if err != nil {
		log.Errorf("Verifier: failed to marshal Attestation Result: %v", err)
		return
	}

	var out bytes.Buffer
	json.Indent(&out, r, "", "    ")

	// Save the Attestation Result
	os.WriteFile(c.ResultFile, out.Bytes(), 0644)
	fmt.Println("Wrote file ", c.ResultFile)
}

func (a LibApi) cacerts(c *config) {
	getCaCertsInternal(c)
}

func (a LibApi) dial(c *config) {
	if a.cmc == nil {
		cmc, err := initialize(c)
		if err != nil {
			log.Errorf("failed to initialize CMC: %v", err)
			return
		}
		a.cmc = cmc
	}

	dialInternal(c, attestedtls.CmcApi_Lib, a.cmc)
}

func (a LibApi) listen(c *config) {

	if a.cmc == nil {
		cmc, err := initialize(c)
		if err != nil {
			log.Errorf("failed to initialize CMC: %v", err)
			return
		}
		a.cmc = cmc
	}

	listenInternal(c, attestedtls.CmcApi_Lib, a.cmc)
}

func (a LibApi) iothub(c *config) {
	log.Fatalf("IoT hub not implemented for lib API")
}

func initialize(c *config) (*cmc.Cmc, error) {

	if len(c.Addr) == 0 {
		return nil, errors.New("cannot initialize CMC. No addresses configured")
	}

	cmcConf := &cmc.Config{
		Addr:           c.Addr[0],
		ProvServerAddr: c.ProvAddr,
		Metadata:       c.Metadata,
		Drivers:        c.Drivers,
		UseIma:         false,
		ImaPcr:         10,
		KeyConfig:      "EC256",
		Api:            "libapi",
		LogLevel:       "trace",
		Storage:        c.Storage,
		Cache:          c.Cache,
	}

	return cmc.NewCmc(cmcConf)
}
