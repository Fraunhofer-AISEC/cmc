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

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	log "github.com/sirupsen/logrus"
)

type config struct {
	Port               int      `json:"port"`
	SigningKey         string   `json:"signingKey"`
	SigningCerts       []string `json:"signingCerts"`
	EstKey             string   `json:"estKey"`
	EstCerts           []string `json:"estCerts"`
	HttpFolder         string   `json:"httpFolder"`
	VerifyEkCert       bool     `json:"verifyEkCert"`
	TpmEkCertDb        string   `json:"tpmEkCertDb,omitempty"`
	VcekOfflineCaching bool     `json:"vcekOfflineCaching,omitempty"`
	VcekCacheFolder    string   `json:"vcekCacheFolder,omitempty"`
	Serialization      string   `json:"serialization"`
}

// Returns either the unmodified absolute path or the absolute path
// retrieved from a path relative to a base path
func getFilePath(p, base string) string {
	if path.IsAbs(p) {
		return p
	}
	ret, _ := filepath.Abs(filepath.Join(base, p))
	return ret
}

func readConfig(configFile string) (*config, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file '%v': %w", configFile, err)
	}
	config := new(config)
	err = json.Unmarshal(data, config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if !config.VerifyEkCert {
		log.Warn("UNSAFE: Verification of EK certificate chain turned off via config")
	}

	printConfig(config, configFile)

	return config, nil
}

func printConfig(c *config, configFile string) {
	log.Infof("Using the configuration loaded from %v:", configFile)
	log.Infof("\tPort                : %v", c.Port)
	log.Infof("\tSigning Key File    : %v", getFilePath(c.SigningKey, filepath.Dir(configFile)))
	log.Infof("\tSigning Certificats :")
	for i, c := range c.SigningCerts {
		log.Infof("\t\tCert %v: %v", i, c)
	}
	log.Infof("\tEST Key File        : %v", getFilePath(c.HttpFolder, filepath.Dir(configFile)))
	log.Infof("\tEST Certificates    : ")
	for i, c := range c.EstCerts {
		log.Infof("\t\tCert %v: %v", i, c)
	}
	log.Infof("\tFolders to be served: %v", getFilePath(c.HttpFolder, filepath.Dir(configFile)))
	log.Infof("\tVerify EK Cert      : %v", c.VerifyEkCert)
	log.Infof("\tTPM EK DB           : %v", getFilePath(c.TpmEkCertDb, filepath.Dir(configFile)))
	log.Infof("\tVCEK Offline Caching: %v", c.VcekOfflineCaching)
	log.Infof("\tVCEK Cache Folder   : %v", getFilePath(c.VcekCacheFolder, filepath.Dir(configFile)))
	log.Infof("\tSerialization       : %v", c.Serialization)
}

func loadCertChain(certChainFiles []string, configFile string) ([]*x509.Certificate, error) {

	certChain := make([]*x509.Certificate, 0)

	if len(certChainFiles) == 0 {
		return nil, errors.New("failed to load certchain: not specified in config file")
	}

	// Load certificate chain
	for _, f := range certChainFiles {
		pem, err := os.ReadFile(getFilePath(f, filepath.Dir(configFile)))
		if err != nil {
			return nil, fmt.Errorf("failed to read file %v: %w", f, err)
		}
		cert, err := internal.LoadCert(pem)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate: %w", err)
		}
		certChain = append(certChain, cert)
	}

	return certChain, nil
}

func getSerializer(s string) (ar.Serializer, error) {
	if strings.EqualFold(s, "JSON") {
		log.Info("Using JSON/JWS as serialization interface")
		return ar.JsonSerializer{}, nil
	} else if strings.EqualFold(s, "CBOR") {
		log.Info("Using CBOR/COSE as serialization interface")
		return ar.CborSerializer{}, nil
	} else {
		return nil, fmt.Errorf("serializer %v not supported (only 'json' and 'cbor')", s)
	}
}
