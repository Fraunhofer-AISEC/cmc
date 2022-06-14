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
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"

	"encoding/json"
	"flag"

	log "github.com/sirupsen/logrus"

	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/provclient"
	"github.com/Fraunhofer-AISEC/cmc/snpdriver"
	"github.com/Fraunhofer-AISEC/cmc/swdriver"
	"github.com/Fraunhofer-AISEC/cmc/tpmdriver"
)

type config struct {
	Addr                  string   `json:"addr"`
	ProvServerAddr        string   `json:"provServerAddr"`
	LocalPath             string   `json:"localPath"`
	FetchMetadata         bool     `json:"fetchMetadata"`
	MeasurementInterfaces []string `json:"measurementInterfaces"` // TPM, SNP
	SigningInterface      string   `json:"signingInterface"`      // TPM, SW
	UseIma                bool     `json:"useIma"`
	ImaPcr                int32    `json:"imaPcr"`
	KeyConfig             string   `json:"keyConfig,omitempty"` // RSA2048 RSA4096 EC256 EC384 EC521
}

func loadConfig(configFile string) (*config, error) {

	log.Infof("Using Config File %v", configFile)
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read cmcd config file %v: %v", configFile, err)
	}
	// Default configuration
	c := &config{
		KeyConfig: "EC256",
	}
	// Obtain custom configuration
	err = json.Unmarshal(data, c)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cmcd config: %v", err)
	}
	c.LocalPath = getFilePath(c.LocalPath, filepath.Dir(configFile))

	// Check measurement and signing interface
	for _, m := range c.MeasurementInterfaces {
		if m != "TPM" && m != "SNP" {
			return nil, fmt.Errorf("measurement interface of type %v not supported", m)
		}
	}
	if c.SigningInterface != "TPM" && c.SigningInterface != "SW" && c.SigningInterface != "" {
		return nil, fmt.Errorf("signing Interface of type %v not supported", c.SigningInterface)
	}

	printConfig(c)

	return c, nil
}

func main() {

	log.SetLevel(log.TraceLevel)

	log.Info("Starting cmcd")

	configFile := flag.String("config", "", "configuration file")
	metadataAddr := flag.String("addr", "", "metadata server address")
	flag.Parse()

	if *configFile == "" {
		log.Error("Config file not specified with -config. Abort")
		return
	}

	c, err := loadConfig(*configFile)
	if err != nil {
		log.Errorf("failed to load config: %v", err)
		return
	}

	provConfig := &provclient.Config{
		FetchMetadata: c.FetchMetadata,
		StoreMetadata: true,
		LocalPath:     c.LocalPath,
		RemoteAddr:    *metadataAddr,
	}
	metadata, err := provclient.ProvisionMetadata(provConfig)
	if err != nil {
		log.Errorf("Failed to provision metadata: %v", err)
		return
	}

	var tpm *tpmdriver.Tpm
	var snp *snpdriver.Snp
	var sw *swdriver.Sw

	measurements := make([]ar.Measurement, 0)
	var signer ar.Signer

	if c.SigningInterface == "SW" {
		log.Info("Using SW as Signing Interface")
		swConfig := swdriver.Config{
			Url:         c.ProvServerAddr,
			StoragePath: path.Join(c.LocalPath, "internal"),
			Metadata:    metadata,
		}
		sw, err = swdriver.NewSwDriver(swConfig)
		if err != nil {
			log.Errorf("failed to create new SW driver: %v", err)
			return
		}

		signer = sw
	}

	if c.SigningInterface == "TPM" || contains("TPM", c.MeasurementInterfaces) {
		tpmConfig := &tpmdriver.Config{
			StoragePath: path.Join(c.LocalPath, "internal"),
			ServerAddr:  c.ProvServerAddr,
			KeyConfig:   c.KeyConfig,
			Metadata:    metadata,
			UseIma:      c.UseIma,
			ImaPcr:      c.ImaPcr,
		}

		tpm, err = tpmdriver.NewTpm(tpmConfig)
		if err != nil {
			log.Errorf("Failed to create new TPM driver: %v", err)
			return
		}
		defer tpmdriver.CloseTpm()
	}

	if contains("TPM", c.MeasurementInterfaces) {
		log.Info("Using TPM as Measurement Interface")
		measurements = append(measurements, tpm)
	}

	if c.SigningInterface == "TPM" {
		log.Info("Using TPM as Signing Interface")
		signer = tpm
	}

	if contains("SNP", c.MeasurementInterfaces) {
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
	}

	server := NewServer(serverConfig)

	err = Serve(c.Addr, &server)
	if err != nil {
		log.Error(err)
		return
	}
}
