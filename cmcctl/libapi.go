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
	"crypto/sha256"
	"errors"
	"os"

	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	m "github.com/Fraunhofer-AISEC/cmc/measure"
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

	if a.cmc.Metadata == nil {
		log.Fatalf("Metadata not specified. Can work only as verifier")
	}

	// Generate random nonce
	nonce := make([]byte, 8)
	_, err := rand.Read(nonce)
	if err != nil {
		log.Fatalf("Failed to read random bytes: %v", err)
	}

	// Generate attestation report
	report, metadata, cacheMisses, err := cmc.Generate(nonce, nil, a.cmc)
	if err != nil {
		log.Errorf("Failed to generate attestation report: %v", err)
		return
	}

	resp := &api.AttestationResponse{
		Report:      report,
		Metadata:    metadata,
		CacheMisses: cacheMisses,
	}

	// Marshal the attestation response for saving it to the file system
	data, err := c.apiSerializer.Marshal(resp)
	if err != nil {
		log.Fatalf("Failed to marshal attestation response: %v", err)
	}

	// Save the attestation report for the verifier
	err = saveReport(c, data, nonce)
	if err != nil {
		log.Fatalf("failed to save report: %v", err)
	}
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

	// Read the attestation report and the nonce previously stored
	report, nonce, err := loadReport(c)
	if err != nil {
		log.Fatalf("Failed to load report: %v", err)
	}

	// Verify the attestation report
	log.Debug("Verifier: verifying attestation report")
	resp, err := cmc.Verify(report.Report, nonce,
		internal.WriteCertsDer(c.identityCas),
		internal.WriteCertsDer(c.metadataCas),
		c.policies, "", nil,
		report.Metadata, a.cmc)
	if err != nil {
		log.Errorf("Verifier: failed to verify: %v", err)
		return
	}

	err = publishResult(c.Publish, c.ResultFile, resp)
	if err != nil {
		log.Fatalf("Failed to save result: %v", err)
	}
}

func (a LibApi) measure(c *config) {
	if a.cmc == nil {
		cmc, err := initialize(c)
		if err != nil {
			log.Errorf("failed to initialize CMC: %v", err)
			return
		}
		a.cmc = cmc
	}

	if c.CtrConfig == "" {
		log.Fatalf("Mode measure requires OCI runtime config to be specified")
	}
	if c.CtrRootfs == "" {
		log.Fatalf("Mode measure requires container rootfs to be specified")
	}

	ctrConfig, err := os.ReadFile(c.CtrConfig)
	if err != nil {
		log.Fatalf("Failed to read oci runtime config: %v", err)
	}

	configHash, _, _, err := m.GetSpecMeasurement("mycontainer", ctrConfig)
	if err != nil {
		log.Fatalf("Failed to measure config: %v", err)
	}

	rootfsHash, err := m.GetRootfsMeasurement(c.CtrRootfs)
	if err != nil {
		log.Fatalf("Failed to measure rootfs: %v", err)
	}

	// Create template hash
	tbh := []byte(configHash)
	tbh = append(tbh, rootfsHash...)
	hasher := sha256.New()
	hasher.Write(tbh)
	templateHash := hasher.Sum(nil)

	event := &ar.MeasureEvent{
		Sha256:    templateHash,
		EventName: c.CtrName,
		CtrData: &ar.CtrData{
			ConfigSha256: configHash,
			RootfsSha256: rootfsHash,
		},
	}

	err = m.Measure(event,
		&m.MeasureConfig{
			Serializer: a.cmc.Serializer,
			Pcr:        a.cmc.CtrPcr,
			LogFile:    a.cmc.CtrLog,
			Driver:     a.cmc.CtrDriver,
		})
	if err != nil {
		log.Fatalf("Failed to record measurement: %v", err)
	}

	log.Debug("Measure: Recorded measurement")
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

func (a LibApi) request(c *config) {
	if a.cmc == nil {
		cmc, err := initialize(c)
		if err != nil {
			log.Errorf("failed to initialize CMC: %v", err)
			return
		}
		a.cmc = cmc
	}

	requestInternal(c, attestedtls.CmcApi_Lib, a.cmc)
}

func (a LibApi) serve(c *config) {
	if a.cmc == nil {
		cmc, err := initialize(c)
		if err != nil {
			log.Errorf("failed to initialize CMC: %v", err)
			return
		}
		a.cmc = cmc
	}

	serveInternal(c, attestedtls.CmcApi_Lib, a.cmc)
}

func initialize(c *config) (*cmc.Cmc, error) {

	if len(c.Addr) == 0 {
		return nil, errors.New("cannot initialize CMC. No addresses configured")
	}

	cmcConf := &cmc.Config{
		CmcAddr:        c.CmcAddr,
		ProvAddr:       c.ProvAddr,
		Metadata:       c.Metadata,
		Drivers:        c.Drivers,
		Ima:            c.Ima,
		ImaPcr:         c.ImaPcr,
		KeyConfig:      c.KeyConfig,
		Api:            "libapi",
		PolicyEngine:   c.PolicyEngine,
		Storage:        c.Storage,
		Cache:          c.Cache,
		PeerCache:      c.PeerCache,
		MeasurementLog: c.MeasurementLog,
		Ctr:            c.Ctr,
		CtrDriver:      c.CtrDriver,
		CtrPcr:         c.CtrPcr,
		CtrLog:         c.CtrLog,
	}

	return cmc.NewCmc(cmcConf)
}
