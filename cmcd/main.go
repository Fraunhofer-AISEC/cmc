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
	"os"
	"path"
	"path/filepath"
	"strconv"

	"encoding/json"
	"flag"

	log "github.com/sirupsen/logrus"

	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	pc "github.com/Fraunhofer-AISEC/cmc/provclient"
	"github.com/Fraunhofer-AISEC/cmc/snpdriver"
	"github.com/Fraunhofer-AISEC/cmc/swdriver"
	"github.com/Fraunhofer-AISEC/cmc/tpmdriver"
)

type config struct {
	Port                  int      `json:"port"`
	ProvServerAddr        string   `json:"provServerAddr"`
	LocalPath             string   `json:"localPath"`
	FetchMetadata         bool     `json:"fetchMetadata"`
	MeasurementInterfaces []string `json:"measurementInterfaces"` // TPM, SNP
	SigningInterface      string   `json:"signingInterface"`      // TPM, SW
	UseIma                bool     `json:"useIma"`
	ImaPcr                int32    `json:"imaPcr"`
	KeyConfig             string   `json:"keyConfig,omitempty"` // RSA2048 RSA4096 EC256 EC384 EC521

	internalPath    string
	akPath          string
	akCertPath      string
	tlsKeyPath      string
	tlsCertPath     string
	deviceSubCaPath string
	caPath          string
}

func loadConfig(configFile string) (*config, error) {
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

	// Convert path to absolute paths (might already be absolute or relative to config file)
	// The filenames are just internal names for files retrieved over the
	// network during provisioning
	c.LocalPath = getFilePath(c.LocalPath, filepath.Dir(configFile))
	c.internalPath = path.Join(c.LocalPath, "internal")
	c.akPath = path.Join(c.internalPath, "ak_encrypted.json")
	c.akCertPath = path.Join(c.internalPath, "ak_cert.pem")
	c.tlsKeyPath = path.Join(c.internalPath, "tls_key_encrypted.json")
	c.tlsCertPath = path.Join(c.internalPath, "tls_cert.pem")
	c.deviceSubCaPath = path.Join(c.internalPath, "device_sub_ca.pem")
	c.caPath = path.Join(c.internalPath, "ca.pem")

	// Create 'internal' folder if not existing for storage of internal data
	if _, err := os.Stat(c.internalPath); err != nil {
		if err := os.MkdirAll(c.internalPath, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory for internal data '%v': %v", c.internalPath, err)
		}
	}

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

func loadMetadata(dir string) (metadata [][]byte, err error) {
	// Read number of files
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata folder: %v", err)
	}

	// Retrieve the metadata files
	metadata = make([][]byte, 0)
	log.Tracef("Parsing %v metadata files in %v", len(files), dir)
	for i := 0; i < len(files); i++ {
		file := path.Join(dir, files[i].Name())
		if fileInfo, err := os.Stat(file); err == nil {
			if fileInfo.IsDir() {
				log.Tracef("Skipping directory %v", file)
				continue
			}
		}
		log.Tracef("Reading file %v", file)
		data, err := ioutil.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %v: %v", file, err)
		}
		metadata = append(metadata, data)
	}
	return metadata, nil
}

func main() {

	log.SetFormatter(&log.TextFormatter{
		DisableColors:   false,
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02T15:04:05.000",
	})

	log.SetLevel(log.TraceLevel)

	log.Info("Starting cmcd")

	configFile := flag.String("config", "", "configuration file")
	metadataAddr := flag.String("addr", "", "metadata server address")
	flag.Parse()

	if *metadataAddr == "" {
		log.Error("Metadata server address not specified with -addr. Abort")
		return
	}

	if *configFile == "" {
		log.Error("Config file not specified with -config. Abort")
		return
	}
	if _, err := os.Stat(*configFile); err != nil {
		log.Error("Config file '", *configFile, "' does not exist. Abort")
		return
	}
	log.Info("Using Config File ", *configFile)

	// Load the cmcd configuration from the cmdline specified configuration file
	c, err := loadConfig(*configFile)
	if err != nil {
		log.Errorf("failed to load config: %v", err)
		return
	}

	// If configured, fetch device metadata from provisioning server and store it
	// on the local path specified in the cmcd configuration, afterwards load it
	if c.FetchMetadata {
		err = pc.FetchMetadata(*metadataAddr, c.LocalPath)
		if err != nil {
			log.Error("failed to fetch device metadata from provisioning server")
			return
		}
	}
	metadata, err := loadMetadata(c.LocalPath)
	if err != nil {
		log.Errorf("failed to load metadata: %v", err)
		return
	}

	verifyingCerts := make([]byte, 0)
	var tpm *tpmdriver.Tpm
	var snp *snpdriver.Snp
	var sw *swdriver.Sw

	measurements := make([]ar.Measurement, 0)
	var signer ar.Signer

	if c.SigningInterface == "SW" {
		log.Info("Using SW as Signing Interface")
		swConfig := swdriver.Config{
			Url: c.ProvServerAddr,
			Paths: swdriver.Paths{
				Leaf:        c.tlsCertPath,
				DeviceSubCa: c.deviceSubCaPath,
				Ca:          c.caPath,
			},
			Metadata: metadata,
		}
		sw, err = swdriver.NewSwDriver(swConfig)
		if err != nil {
			log.Errorf("failed to create new SW driver: %v", err)
			return
		}

		verifyingCerts = append(verifyingCerts, sw.GetCertChain().Ca...)

		signer = sw
	}

	if c.SigningInterface == "TPM" || contains("TPM", c.MeasurementInterfaces) {
		tpmConfig := &tpmdriver.Config{
			Paths: tpmdriver.Paths{
				Ak:          c.akPath,
				TLSKey:      c.tlsKeyPath,
				AkCert:      c.akCertPath,
				TLSCert:     c.tlsCertPath,
				DeviceSubCa: c.deviceSubCaPath,
				Ca:          c.caPath,
			},
			ServerAddr: c.ProvServerAddr,
			KeyConfig:  c.KeyConfig,
			Metadata:   metadata,
			UseIma:     c.UseIma,
			ImaPcr:     c.ImaPcr,
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
		verifyingCerts = append(verifyingCerts, tpm.GetCertChain().Ca...)
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
		VerifyingCas:          verifyingCerts,
		MeasurementInterfaces: measurements,
		Signer:                signer,
	}

	server := NewServer(serverConfig)

	addr := "127.0.0.1:" + strconv.Itoa(c.Port)
	err = Serve(addr, &server)
	if err != nil {
		log.Error(err)
		return
	}
}
