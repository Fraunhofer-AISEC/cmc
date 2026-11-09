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

type LibApi struct{}

func init() {
	apis["libapi"] = LibApi{}
}

func (a LibApi) generate(c *Config) error {

	// Generate random nonce
	nonce := make([]byte, 8)
	_, err := rand.Read(nonce)
	if err != nil {
		return fmt.Errorf("failed to read random bytes: %w", err)
	}

	// Request updated OMSP responses if stored ones are too old
	c.cmc.UpdateOmsps()

	// Generate attestation report
	report, err := prover.Generate(nonce, nil, nil, c.cmc.GetMetadata(), c.cmc.Drivers, c.serializer,
		c.cmc.HashAlg)
	if err != nil {
		return fmt.Errorf("failed to generate attestation report: %w", err)
	}

	// Save the attestation report for the verifier
	err = pub.SaveReport(c.Files.Report, c.Files.Nonce, report, nonce)
	if err != nil {
		return fmt.Errorf("failed to save report: %w", err)
	}

	return nil
}

func (a LibApi) verify(c *Config) error {

	// Read the attestation report and the nonce previously stored
	report, nonce, err := pub.LoadReport(c.Files.Report, c.Files.Nonce, c.serializer)
	if err != nil {
		return fmt.Errorf("failed to load report: %w", err)
	}

	// Verify the attestation report
	log.Debug("Verifier: verifying attestation report")
	resp := verifier.Verify(report, nonce, c.policies, c.cmc.PolicyEngineSelect,
		c.cmc.PolicyOverwrite, c.cmc.RootCas, c.cmc.PeerCache, "", "",
		c.cmc.Metadata.Omsp.Enabled, c.cmc.LocalRole)

	hostname, _ := internal.Fqdn()
	resp.Verifier = ar.Endpoint{Hostname: hostname}

	err = pub.Publish(c.Publish.Results, c.Publish.Ocsf, c.Publish.Network, c.publishToken, c.Publish.Result, resp,
		c.rootCas, c.Trust.AllowSystemCerts, c.publishClientCert)
	if err != nil {
		return fmt.Errorf("failed to save result: %w", err)
	}

	return nil
}

func (a LibApi) enroll(c *Config) error {

	log.Tracef("Requested key parameters: type %q, alg %q, cn %q, dns %q, ips %q",
		c.Identity.KeyType, c.Identity.KeyConfig,
		c.Identity.Cn, c.Identity.DnsNames, c.Identity.IpAddresses)

	keyId, err := c.cmc.KeyMgr.EnrollKey(&keymgr.KeyEnrollmentParams{
		KeyConfig: api.TLSKeyConfig{
			Type:        c.Identity.KeyType,
			Alg:         c.Identity.KeyConfig,
			Cn:          c.Identity.Cn,
			DNSNames:    c.Identity.DnsNames,
			IPAddresses: c.Identity.IpAddresses,
		},
		Metadata:  c.cmc.GetMetadata(),
		Drivers:   c.cmc.Drivers,
		ArHashAlg: c.cmc.HashAlg,
	})
	if err != nil {
		return fmt.Errorf("failed to enroll key: %v", err)
	}

	if err := internal.SaveKeyId(c.Identity.KeyId, keyId); err != nil {
		return err
	}

	log.Infof("Created new TLS key with KeyID %v", keyId)

	return nil
}

func (a LibApi) updateCerts(c *Config) error {

	// Generate attestation report
	err := cmc.UpdateCerts(c.cmc)
	if err != nil {
		return fmt.Errorf("failed to update certs: %v", err)
	}

	return nil
}

func (a LibApi) updateMetadata(c *Config) error {

	// Generate attestation report
	err := cmc.UpdateMetadata(c.cmc)
	if err != nil {
		return fmt.Errorf("failed to update certs: %v", err)
	}

	return nil
}
