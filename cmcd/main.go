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
	ServerAddr            string   `json:"provServerAddr"`
	ServerPath            string   `json:"serverPath"`
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
		return nil, fmt.Errorf("Failed to read cmcd config file %v: %v", configFile, err)
	}
	// Default configuration
	c := &config{
		KeyConfig: "EC256",
	}
	// Obtain custom configuration
	err = json.Unmarshal(data, c)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse cmcd config: %v", err)
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
			return nil, fmt.Errorf("Failed to create directory for internal data '%v': %v", c.internalPath, err)
		}
	}

	// Check measurement and signing interface
	for _, m := range c.MeasurementInterfaces {
		if m != "TPM" && m != "SNP" {
			return nil, fmt.Errorf("Measurement interface of type %v not supported", m)
		}
	}
	if c.SigningInterface != "TPM" && c.SigningInterface != "SW" && c.SigningInterface != "" {
		return nil, fmt.Errorf("Signing Interface of type %v not supported", c.SigningInterface)
	}

	printConfig(c)

	return c, nil
}

func loadMetadata(dir string) (metadata [][]byte, err error) {
	// Read number of files
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("Failed to read metadata folder: %v", err)
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
			return nil, fmt.Errorf("Failed to read file %v: %v", file, err)
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

	log.Info("Starting CMC")

	configFile := flag.String("config", "", "configuration file")
	flag.Parse()

	if *configFile == "" {
		log.Error("Config file not specified. Please specify a config file")
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
		log.Errorf("Failed to load config: %v", err)
		return
	}

	// If configured, fetch device metadata from provisioning server and store it
	// on the local path specified in the cmcd configuration, afterwards load it
	if c.FetchMetadata {
		err = pc.FetchMetadata(c.ServerAddr, c.ServerPath, c.LocalPath)
		if err != nil {
			log.Error("Failed to fetch device metadata from provisioning server")
			return
		}
	}
	metadata, err := loadMetadata(c.LocalPath)
	if err != nil {
		log.Errorf("Failed to load metadata: %v", err)
		return
	}

	verifyingCerts := make([]byte, 0)
	var tpm *tpmdriver.Tpm
	var snp *snpdriver.Snp
	var sw *swdriver.Sw

	measurements := make([]ar.Measurement, 0)
	var signer ar.Signer

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
			ServerAddr: c.ServerAddr,
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
		snp, err = snpdriver.NewSnpDriver()
		if err != nil {
			log.Errorf("Failed to create new SNP driver: %v", err)
			return
		}

		measurements = append(measurements, snp)
	}

	if c.SigningInterface == "SW" {
		log.Info("Using SW as Signing Interface")
		sw, err = swdriver.NewSwDriver()
		if err != nil {
			log.Errorf("Failed to create new SW driver: %v", err)
			return
		}

		verifyingCerts = append(verifyingCerts, sw.GetCertChain().Ca...)

		// TODO short hack, remove
		ca := "-----BEGIN CERTIFICATE-----\nMIICSDCCAc2gAwIBAgIUHxAyr1Y3QlrYutGU317Uy5FhdpQwCgYIKoZIzj0EAwMw\nYzELMAkGA1UEBhMCREUxETAPBgNVBAcTCEdhcmNoaW5nMRkwFwYDVQQKExBGcmF1\nbmhvZmVyIEFJU0VDMRAwDgYDVQQLEwdSb290IENBMRQwEgYDVQQDEwtJRFMgUm9v\ndCBDQTAeFw0yMjA0MDQxNTE3MDBaFw0yNzA0MDMxNTE3MDBaMGMxCzAJBgNVBAYT\nAkRFMREwDwYDVQQHEwhHYXJjaGluZzEZMBcGA1UEChMQRnJhdW5ob2ZlciBBSVNF\nQzEQMA4GA1UECxMHUm9vdCBDQTEUMBIGA1UEAxMLSURTIFJvb3QgQ0EwdjAQBgcq\nhkjOPQIBBgUrgQQAIgNiAAQSneAVxZRShdfwEu3HtCcwRnV5b4UtOnxJaVZ/bILS\n4dThZVWpXNm+ikvp6Sk0RlI30mKl2X7fX8aRew+HvvFT08xJw9dGAkm2Fsp+4/c7\nM3rMhiHXyCpu/Xg4OlxAYOajQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E\nBTADAQH/MB0GA1UdDgQWBBTyFTqqlt0/YxJBiCB3WM7lkpqWVjAKBggqhkjOPQQD\nAwNpADBmAjEAizrjlmYQmrMbsEaGaFzouMT02iMu0NLILhm1wkfAl3UUWymcliy8\nf1IAI1nO4448AjEAkd74w4WEaTqvslmkPktxNhDA1cVL55LDLbUNXLcSdzr2UBhp\nK8Vv1j4nATtg1Vkf\n-----END CERTIFICATE-----\n"
		verifyingCerts = append(verifyingCerts, []byte(ca)...)

		signer = sw
	}

	// The verification requires different roles for different certificate chains
	// to avoid impersonation
	// roles := &ar.SignerRoles{
	// 	ManifestSigners:    []string{"developer", "evaluator", "certifier"},
	// 	CompanyDescSigners: []string{"operator", "evaluator", "certifier"},
	// 	ArSigners:          []string{"device"},
	// 	ConnDescSigners:    []string{"operator"},
	// }

	serverConfig := &ServerConfig{
		Metadata: metadata,
		//Roles:    roles,
		// TODO handle more then 1 CA, put this in gRPC verify call
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
