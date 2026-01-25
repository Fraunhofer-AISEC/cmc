// Copyright (c) 2021 - 2024 Fraunhofer AISEC
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

import (

	// local modules

	"crypto/rand"
	"fmt"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/api"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	pub "github.com/Fraunhofer-AISEC/cmc/publish"
)

type LibApi struct {
	cmc *cmc.Cmc
}

func init() {
	apis["libapi"] = LibApi{}
}

func (a LibApi) generate(c *config) error {

	if a.cmc == nil {
		cmc, err := cmc.NewCmc(&c.Config)
		if err != nil {
			return fmt.Errorf("failed to initialize CMC: %v", err)
		}
		a.cmc = cmc
	}

	if a.cmc.Metadata == nil {
		return fmt.Errorf("metadata not specified. Can work only as verifier")
	}

	// Generate random nonce
	nonce := make([]byte, 8)
	_, err := rand.Read(nonce)
	if err != nil {
		return fmt.Errorf("failed to read random bytes: %w", err)
	}

	// Generate attestation report
	report, metadata, cacheMisses, err := cmc.Generate(nonce, nil, a.cmc)
	if err != nil {
		return fmt.Errorf("failed to generate attestation report: %w", err)
	}

	resp := &api.AttestationResponse{
		Report:      report,
		Metadata:    metadata,
		CacheMisses: cacheMisses,
	}

	// Marshal the attestation response for saving it to the file system
	data, err := c.apiSerializer.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal attestation response: %w", err)
	}

	// Save the attestation report for the verifier
	err = pub.SaveReport(c.ReportFile, c.NonceFile, data, nonce)
	if err != nil {
		return fmt.Errorf("failed to save report: %w", err)
	}

	return nil
}

func (a LibApi) verify(c *config) error {
	if a.cmc == nil {
		cmc, err := cmc.NewCmc(&c.Config)
		if err != nil {
			return fmt.Errorf("failed to initialize CMC: %v", err)
		}
		a.cmc = cmc
	}

	// Read the attestation report and the nonce previously stored
	report, nonce, err := pub.LoadReport(c.ReportFile, c.NonceFile, c.apiSerializer)
	if err != nil {
		return fmt.Errorf("failed to load report: %w", err)
	}

	// Verify the attestation report
	log.Debug("Verifier: verifying attestation report")
	resp, err := cmc.Verify(report.Report, nonce,
		c.policies, "", nil,
		report.Metadata, a.cmc)
	if err != nil {
		return fmt.Errorf("failed to verify: %v", err)
	}

	err = pub.PublishResult(c.Publish, c.publishToken, c.ResultFile, resp)
	if err != nil {
		return fmt.Errorf("failed to save result: %w", err)
	}

	return nil
}

func (a LibApi) updateCerts(c *config) error {

	if a.cmc == nil {
		cmc, err := cmc.NewCmc(&c.Config)
		if err != nil {
			return fmt.Errorf("failed to initialize CMC: %v", err)
		}
		a.cmc = cmc
	}

	// Generate attestation report
	err := cmc.UpdateCerts(a.cmc)
	if err != nil {
		return fmt.Errorf("failed to update certs: %v", err)
	}

	return nil
}

func (a LibApi) updateMetadata(c *config) error {

	if a.cmc == nil {
		cmc, err := cmc.NewCmc(&c.Config)
		if err != nil {
			return fmt.Errorf("failed to initialize CMC: %v", err)
		}
		a.cmc = cmc
	}

	// Generate attestation report
	err := cmc.UpdateMetadata(a.cmc)
	if err != nil {
		return fmt.Errorf("failed to update certs: %v", err)
	}

	return nil
}

func getLibApiCmcObj(c *config) *cmc.Cmc {
	if !strings.EqualFold(c.Api, "libapi") {
		return nil
	}

	api, ok := apis["libapi"].(LibApi)
	if !ok {
		log.Fatalf("internal error: failed to retrieve libapi")
	}

	if api.cmc == nil {
		cmc, err := cmc.NewCmc(&c.Config)
		if err != nil {
			log.Fatalf("failed to initialize CMC: %v", err)
		}
		api.cmc = cmc
	}

	return api.cmc
}
