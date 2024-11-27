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

	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/Fraunhofer-AISEC/cmc/api"
	"github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
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
	report, _, err := cmc.Generate(&api.AttestationRequest{Nonce: nonce}, a.cmc)
	if err != nil {
		log.Errorf("Failed to generate attestation report: %v", err)
		return
	}

	// Save the attestation report for the verifier
	err = os.WriteFile(c.ReportFile, report, 0644)
	if err != nil {
		log.Fatalf("Failed to save attestation report as %v: %v", c.ReportFile, err)
	}
	log.Infof("Wrote attestation report length %v: %v", len(report), c.ReportFile)

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
	log.Debug("Verifier: verifying attestation report")
	result, err := cmc.Verify(&api.VerificationRequest{
		Nonce:             nonce,
		AttestationReport: report,
		Ca:                c.ca,
		Policies:          c.policies,
	}, a.cmc)
	if err != nil {
		log.Errorf("Verifier: failed to verify: %v", err)
		return
	}

	err = saveResult(c.ResultFile, c.Publish, result)
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

	ctrConfig, err := os.ReadFile(c.CtrConfig)
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}

	configHash, _, _, err := m.GetSpecMeasurement("mycontainer", ctrConfig)
	if err != nil {
		log.Fatalf("Failed to measure config: %v", err)
	}

	rootfsHash, err := m.GetRootfsMeasurement(c.CtrRootfs)
	if err != nil {
		log.Fatalf("Failed to measure rootfs: %v", err)
	}

	req := &api.MeasureRequest{
		Name:         c.CtrName,
		ConfigSha256: configHash,
		RootfsSha256: rootfsHash,
		OciSpec:      ctrConfig,
	}

	err = m.Measure(req,
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

func (a LibApi) iothub(c *config) {
	log.Fatalf("IoT hub not implemented for lib API")
}

func initialize(c *config) (*cmc.Cmc, error) {

	if len(c.Addr) == 0 {
		return nil, errors.New("cannot initialize CMC. No addresses configured")
	}

	cmcConf := &cmc.Config{
		Addr:           c.Addr[0],
		ProvServerAddr: c.ProvServerAddr,
		Metadata:       c.Metadata,
		Drivers:        c.Drivers,
		UseIma:         c.UseIma,
		ImaPcr:         c.ImaPcr,
		KeyConfig:      c.KeyConfig,
		Api:            "libapi",
		PolicyEngine:   c.PolicyEngine,
		LogLevel:       c.LogLevel,
		Storage:        c.Storage,
		Cache:          c.Cache,
		PeerCache:      c.PeerCache,
		MeasurementLog: c.MeasurementLog,
		UseCtr:         c.UseCtr,
		CtrDriver:      c.CtrDriver,
		CtrPcr:         c.CtrPcr,
		CtrLog:         c.CtrLog,
		ExtCtrLog:      c.ExtCtrLog,
	}

	return cmc.NewCmc(cmcConf)
}
