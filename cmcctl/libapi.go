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

	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/keymgr"
	"github.com/Fraunhofer-AISEC/cmc/prover"
	pub "github.com/Fraunhofer-AISEC/cmc/publish"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
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

	// Generate random nonce
	nonce := make([]byte, 8)
	_, err := rand.Read(nonce)
	if err != nil {
		return fmt.Errorf("failed to read random bytes: %w", err)
	}

	// Request updated OMSP responses if stored ones are too old
	a.cmc.UpdateOmsps()

	// Generate attestation report
	report, err := prover.Generate(nonce, nil, a.cmc.GetMetadata(), a.cmc.Drivers, c.serializer,
		a.cmc.HashAlg)
	if err != nil {
		return fmt.Errorf("failed to generate attestation report: %w", err)
	}

	// Save the attestation report for the verifier
	err = pub.SaveReport(c.ReportFile, c.NonceFile, report, nonce)
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
	report, nonce, err := pub.LoadReport(c.ReportFile, c.NonceFile, c.serializer)
	if err != nil {
		return fmt.Errorf("failed to load report: %w", err)
	}

	// Verify the attestation report
	log.Debug("Verifier: verifying attestation report")
	resp := verifier.Verify(report, nonce, c.policies, a.cmc.PolicyEngineSelect,
		a.cmc.PolicyOverwrite, a.cmc.RootCas, a.cmc.PeerCache, "", "", a.cmc.UseOmsp)

	hostname, _ := internal.Fqdn()
	resp.Verifier = ar.Endpoint{Hostname: hostname}

	err = pub.Publish(c.PublishResults, c.PublishOcsf, c.PublishNetwork, c.publishToken, c.ResultFile, resp,
		c.rootCas, c.AllowSystemCerts, c.publishClientCert)
	if err != nil {
		return fmt.Errorf("failed to save result: %w", err)
	}

	return nil
}

func (a LibApi) enroll(c *config) error {

	if a.cmc == nil {
		cmc, err := cmc.NewCmc(&c.Config)
		if err != nil {
			return fmt.Errorf("failed to initialize CMC: %v", err)
		}
		a.cmc = cmc
	}

	log.Tracef("Requested key parameters: type %q, alg %q, cn %q, dns %q, ips %q",
		c.KeyType, c.KeyConfig,
		c.TlsCn, c.TlsDnsNames, c.TlsIpAddresses)

	keyId, err := a.cmc.KeyMgr.EnrollKey(&keymgr.KeyEnrollmentParams{
		KeyConfig: api.TLSKeyConfig{
			Type:        c.KeyType,
			Alg:         c.KeyConfig,
			Cn:          c.TlsCn,
			DNSNames:    c.TlsDnsNames,
			IPAddresses: c.TlsIpAddresses,
		},
		Metadata:  a.cmc.GetMetadata(),
		Drivers:   a.cmc.Drivers,
		ArHashAlg: a.cmc.HashAlg,
	})
	if err != nil {
		return fmt.Errorf("failed to enroll key: %v", err)
	}

	log.Infof("Created new TLS key with KeyID %v", keyId)

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
