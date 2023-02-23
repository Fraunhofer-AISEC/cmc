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
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"

	"encoding/json"
	"flag"

	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/est/client"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/snpdriver"
	"github.com/Fraunhofer-AISEC/cmc/swdriver"
	"github.com/Fraunhofer-AISEC/cmc/tpmdriver"
	"github.com/sirupsen/logrus"
)

type config struct {
	Addr                  string   `json:"addr"`
	ProvServerAddr        string   `json:"provServerAddr"`
	LocalPath             string   `json:"localPath"`
	FetchMetadata         bool     `json:"fetchMetadata"`
	MeasurementInterfaces []string `json:"measurementInterfaces"`  // TPM, SNP
	SigningInterface      string   `json:"signingInterface"`       // TPM, SW
	UseIma                bool     `json:"useIma"`                 // TRUE, FALSE
	ImaPcr                int32    `json:"imaPcr"`                 // 10-15
	KeyConfig             string   `json:"keyConfig,omitempty"`    // RSA2048 RSA4096 EC256 EC384 EC521
	Serialization         string   `json:"serialization"`          // JSON, CBOR
	Api                   string   `json:"api"`                    // gRPC, CoAP
	PolicyEngine          string   `json:"policyEngine,omitempty"` // JS, DUKTAPE
}

var log = logrus.WithField("service", "cmcd")

func loadConfig(configFile string) (*config, error) {

	log.Infof("Using Config File %v", configFile)
	data, err := os.ReadFile(configFile)
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
	c.LocalPath = internal.GetFilePath(c.LocalPath, filepath.Dir(configFile))

	// Check measurement, signing and serializer interface
	for _, m := range c.MeasurementInterfaces {
		if !strings.EqualFold(m, "TPM") && !strings.EqualFold(m, "SNP") {
			return nil, fmt.Errorf("measurement interface of type %v not supported", m)
		}
	}
	if !strings.EqualFold(c.SigningInterface, "TPM") && !strings.EqualFold(c.SigningInterface, "SW") {
		return nil, fmt.Errorf("signing Interface of type %v not supported", c.SigningInterface)
	}
	if !strings.EqualFold(c.Serialization, "CBOR") && !strings.EqualFold(c.Serialization, "JSON") {
		return nil, fmt.Errorf("serialization interface of type %v not supported", c.Serialization)
	}

	printConfig(c)

	return c, nil
}

func printConfig(c *config) {
	log.Info("Using the following configuration:")
	log.Info("\tCMC Listen Address       : ", c.Addr)
	log.Info("\tProvisioning Server URL  : ", c.ProvServerAddr)
	log.Info("\tLocal Storage Path       : ", c.LocalPath)
	log.Info("\tFetch Metadata           : ", c.FetchMetadata)
	log.Info("\tUse IMA                  : ", c.UseIma)
	log.Info("\tIMA PCR                  : ", c.ImaPcr)
	log.Info("\tSerialization            : ", c.Serialization)
	log.Info("\tAPI                      : ", c.Api)
	log.Info("\tPolicy Engine            : ", c.PolicyEngine)
}

func getVersion() string {
	version := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		if strings.EqualFold(info.Main.Version, "(devel)") {
			commit := "unknown"
			created := "unknown"
			for _, elem := range info.Settings {
				if strings.EqualFold(elem.Key, "vcs.revision") {
					commit = elem.Value
				}
				if strings.EqualFold(elem.Key, "vcs.time") {
					created = elem.Value
				}
			}
			version = fmt.Sprintf("%v, commit %v, created %v", info.Main.Version, commit, created)
		} else {
			version = info.Main.Version
		}
	}
	return version
}

func main() {

	logrus.SetLevel(logrus.TraceLevel)

	log.Infof("Starting cmcd %v", getVersion())

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

	provConfig := &client.Config{
		FetchMetadata: c.FetchMetadata,
		StoreMetadata: true,
		LocalPath:     c.LocalPath,
		RemoteAddr:    *metadataAddr,
	}
	metadata, err := client.ProvisionMetadata(provConfig)
	if err != nil {
		log.Errorf("Failed to provision metadata: %v", err)
		return
	}

	var tpm *tpmdriver.Tpm
	var snp *snpdriver.Snp
	var sw *swdriver.Sw
	var jsonSerializer ar.JsonSerializer
	var cborSerializer ar.CborSerializer

	measurements := make([]ar.Measurement, 0)
	var signer ar.Signer
	var serializer ar.Serializer

	if strings.EqualFold(c.Serialization, "JSON") {
		log.Info("Using JSON/JWS as serialization interface")
		serializer = jsonSerializer
	}

	if strings.EqualFold(c.Serialization, "CBOR") {
		log.Info("Using CBOR/COSE as serialization interface")
		serializer = cborSerializer
	}

	if strings.EqualFold(c.SigningInterface, "SW") {
		log.Warn("Using unsafe swdriver as Signing Interface")
		swConfig := swdriver.Config{
			StoragePath: path.Join(c.LocalPath, "internal"),
			Url:         c.ProvServerAddr,
			Metadata:    metadata,
			Serializer:  serializer,
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
			Serializer:  serializer,
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

	var policyEngineSelect ar.PolicyEngineSelect = ar.PolicyEngineSelect_None
	if strings.EqualFold(c.PolicyEngine, "JS") {
		policyEngineSelect = ar.PolicyEngineSelect_JS
	} else if strings.EqualFold(c.PolicyEngine, "DUKTAPE") {
		policyEngineSelect = ar.PolicyEngineSelect_DukTape
	}

	serverConfig := &ServerConfig{
		Metadata:              metadata,
		MeasurementInterfaces: measurements,
		Signer:                signer,
		Serializer:            serializer,
		PolicyEngineSelect:    policyEngineSelect,
	}

	server, ok := servers[strings.ToLower(c.Api)]
	if !ok {
		log.Errorf("API '%v' is not implemented", c.Api)
		return
	}

	server.Serve(c.Addr, serverConfig)
}
