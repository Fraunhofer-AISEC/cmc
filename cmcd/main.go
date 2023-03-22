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
	"path"
	"strings"

	// local modules

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/est/client"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/snpdriver"
	"github.com/Fraunhofer-AISEC/cmc/swdriver"
	"github.com/Fraunhofer-AISEC/cmc/tpmdriver"
)

func main() {

	log.Infof("Starting cmcd %v", getVersion())

	c, err := getConfig()
	if err != nil {
		log.Errorf("failed to load config: %v", err)
		return
	}

	provConfig := &client.Config{
		FetchMetadata: c.FetchMetadata,
		StoreMetadata: true,
		LocalPath:     c.LocalPath,
		RemoteAddr:    c.MetadataAddr,
	}
	metadata, err := client.ProvisionMetadata(provConfig)
	if err != nil {
		log.Errorf("Failed to provision metadata: %v", err)
		return
	}

	var tpm *tpmdriver.Tpm
	var snp *snpdriver.Snp
	var sw *swdriver.Sw

	measurements := make([]ar.Measurement, 0)
	var signer ar.Signer

	if strings.EqualFold(c.SigningInterface, "SW") {
		log.Warn("Using unsafe swdriver as Signing Interface")
		swConfig := swdriver.Config{
			StoragePath: path.Join(c.LocalPath, "internal"),
			Url:         c.ProvServerAddr,
			Metadata:    metadata,
			Serializer:  c.serializer,
		}
		sw, err = swdriver.NewSwDriver(swConfig)
		if err != nil {
			log.Errorf("failed to create new SW driver: %v", err)
			return
		}

		signer = sw
	}

	if strings.EqualFold(c.SigningInterface, "TPM") || internal.Contains("TPM", c.MeasurementInterfaces) {
		tpmConfig := &tpmdriver.Config{
			StoragePath: path.Join(c.LocalPath, "internal"),
			ServerAddr:  c.ProvServerAddr,
			KeyConfig:   c.KeyConfig,
			Metadata:    metadata,
			UseIma:      c.UseIma,
			ImaPcr:      c.ImaPcr,
			Serializer:  c.serializer,
		}

		tpm, err = tpmdriver.NewTpm(tpmConfig)
		if err != nil {
			log.Errorf("Failed to create new TPM driver: %v", err)
			return
		}
		defer tpmdriver.CloseTpm()
	}

	if internal.Contains("TPM", c.MeasurementInterfaces) {
		log.Info("Using TPM as Measurement Interface")
		measurements = append(measurements, tpm)
	}

	if strings.EqualFold(c.SigningInterface, "TPM") {
		log.Info("Using TPM as Signing Interface")
		signer = tpm
	}

	if internal.Contains("SNP", c.MeasurementInterfaces) {
		log.Info("Using SNP as Measurement Interface")
		snpConfig := snpdriver.Config{
			Url: c.ProvServerAddr,
		}
		snp, err = snpdriver.NewSnpDriver(snpConfig)
		if err != nil {
			log.Errorf("failed to create new SNP driver: %v", err)
			return
		}

		measurements = append(measurements, snp)
	}

	serverConfig := &ServerConfig{
		Metadata:              metadata,
		MeasurementInterfaces: measurements,
		Signer:                signer,
		Serializer:            c.serializer,
		PolicyEngineSelect:    c.policyEngineSelect,
	}

	server, ok := servers[strings.ToLower(c.Api)]
	if !ok {
		log.Errorf("API '%v' is not implemented", c.Api)
		return
	}

	server.Serve(c.Addr, serverConfig)
}
