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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

var (
	logLevels = map[string]log.Level{
		"panic": log.PanicLevel,
		"fatal": log.FatalLevel,
		"error": log.ErrorLevel,
		"warn":  log.WarnLevel,
		"info":  log.InfoLevel,
		"debug": log.DebugLevel,
		"trace": log.TraceLevel,
	}
)

type config struct {
	Port            int      `json:"port"`
	SigningKey      string   `json:"signingKey"`
	SigningCerts    []string `json:"signingCerts"`
	EstKey          string   `json:"estKey"`
	EstCerts        []string `json:"estCerts"`
	HttpFolder      string   `json:"httpFolder"`
	VerifyEkCert    bool     `json:"verifyEkCert"`
	TpmEkCertDb     string   `json:"tpmEkCertDb,omitempty"`
	VcekCacheFolder string   `json:"vcekCacheFolder,omitempty"`
	LogLevel        string   `json:"logLevel"`
	LogFile         string   `json:"logFile,omitempty"`

	signingKey   *ecdsa.PrivateKey
	signingCerts []*x509.Certificate
	estKey       *ecdsa.PrivateKey
	estCerts     []*x509.Certificate
}

const (
	configFlag          = "config"
	portFlag            = "port"
	signingKeyFlag      = "signingkey"
	signingCertsFlag    = "signingcerts"
	estKeyFlag          = "estkey"
	estCertsFlag        = "estcerts"
	httpFolderFlag      = "httpfolder"
	verifyEkCertFlag    = "verifyekcert"
	tpmEkCertDbFlag     = "tpmekcertdb"
	vcekCacheFolderFlag = "vcekcachefolder"
	logLevelFlag        = "loglevel"
	logFileFlag         = "logfile"
)

func getConfig() (*config, error) {
	var ok bool
	var err error

	// Parse given command line flags
	configFile := flag.String(configFlag, "", "configuration file")
	port := flag.Int(portFlag, 0, "Port to listen on")
	signingKey := flag.String(signingKeyFlag, "", "Path to the key used for signing certs")
	signingCerts := flag.String(signingCertsFlag, "", "Path to the signing key cert chain")
	estKey := flag.String(estKeyFlag, "", "TLS key for HTTPS server")
	estCerts := flag.String(estCertsFlag, "", "Certificate chain for TLS key")
	httpFolder := flag.String(httpFolderFlag, "", "Folder to be served")
	verifyEkCert := flag.Bool(verifyEkCertFlag, false,
		"Indicates whether to verify TPM EK certificate chains")
	tpmEkCertDb := flag.String(tpmEkCertDbFlag, "", "Database for EK cert chain verification")
	vcekCacheFolder := flag.String(vcekCacheFolderFlag, "", "Folder to cache AMD SNP VCEKs")
	logLevel := flag.String(logLevelFlag, "",
		fmt.Sprintf("Possible logging: %v", maps.Keys(logLevels)))
	logFile := flag.String(logFileFlag, "", "Optional file to log to instead of stdout/stderr")
	flag.Parse()

	// Create default configuration
	c := &config{
		Port:         9000,
		VerifyEkCert: true,
		LogLevel:     "info",
	}

	// Obtain custom configuration from file if specified
	if internal.FlagPassed(configFlag) {
		data, err := os.ReadFile(*configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file '%v': %w", *configFile, err)
		}
		err = json.Unmarshal(data, c)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal config: %w", err)
		}
	}

	// Overwrite config file configuration with given commandline arguments
	if internal.FlagPassed(portFlag) {
		c.Port = *port
	}
	if internal.FlagPassed(signingKeyFlag) {
		c.SigningKey = *signingKey
	}
	if internal.FlagPassed(signingCertsFlag) {
		c.SigningCerts = strings.Split(*signingCerts, ",")
	}
	if internal.FlagPassed(estKeyFlag) {
		c.EstKey = *estKey
	}
	if internal.FlagPassed(estCertsFlag) {
		c.EstCerts = strings.Split(*estCerts, ",")
	}
	if internal.FlagPassed(httpFolderFlag) {
		c.HttpFolder = *httpFolder
	}
	if internal.FlagPassed(verifyEkCertFlag) {
		c.VerifyEkCert = *verifyEkCert
	}
	if internal.FlagPassed(tpmEkCertDbFlag) {
		c.TpmEkCertDb = *tpmEkCertDb
	}
	if internal.FlagPassed(vcekCacheFolderFlag) {
		c.VcekCacheFolder = *vcekCacheFolder
	}
	if internal.FlagPassed(logFileFlag) {
		c.LogLevel = *logLevel
	}
	if internal.FlagPassed(logFileFlag) {
		c.LogFile = *logFile
	}

	// Configure the logger
	if c.LogFile != "" {
		lf, err := filepath.Abs(*logFile)
		if err != nil {
			log.Fatalf("Failed to get logfile path: %v", err)
		}
		file, err := os.OpenFile(lf, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
		}
		log.SetOutput(file)
	}
	l, ok := logLevels[strings.ToLower(c.LogLevel)]
	if !ok {
		flag.Usage()
		log.Fatalf("LogLevel %v does not exist", c.LogLevel)
	}
	log.SetLevel(l)

	// Convert all paths to absolute paths
	pathsToAbs(c)

	// Print the parsed configuration
	printConfig(c)

	// Load specified files
	c.signingKey, err = loadPrivateKey(c.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	c.signingCerts, err = loadCertChain(c.SigningCerts)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate chain: %w", err)
	}

	c.estKey, err = loadPrivateKey(c.EstKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	c.estCerts, err = loadCertChain(c.EstCerts)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate chain: %w", err)
	}

	if !c.VerifyEkCert {
		log.Warn("UNSAFE: Verification of EK certificate chain turned off via config")
	}

	return c, nil
}

func pathsToAbs(c *config) {
	var err error
	c.SigningKey, err = filepath.Abs(c.SigningKey)
	if err != nil {
		log.Warnf("Failed to get absolute path for %v: %v", c.signingKey, err)
	}

	for i := 0; i < len(c.SigningCerts); i++ {
		c.SigningCerts[i], err = filepath.Abs(c.SigningCerts[i])
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.SigningCerts[i], err)
		}
	}

	c.EstKey, err = filepath.Abs(c.EstKey)
	if err != nil {
		log.Warnf("Failed to get absolute path for %v: %v", c.EstKey, err)
	}

	for i := 0; i < len(c.EstCerts); i++ {
		c.EstCerts[i], err = filepath.Abs(c.EstCerts[i])
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.EstCerts[i], err)
		}
	}

	c.HttpFolder, err = filepath.Abs(c.HttpFolder)
	if err != nil {
		log.Warnf("Failed to get absolute path for %v: %v", c.HttpFolder, err)
	}

	c.TpmEkCertDb, err = filepath.Abs(c.TpmEkCertDb)
	if err != nil {
		log.Warnf("Failed to get absolute path for %v: %v", c.HttpFolder, err)
	}

	if c.VcekCacheFolder != "" {
		c.VcekCacheFolder, err = filepath.Abs(c.VcekCacheFolder)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.HttpFolder, err)
		}
	}
}

func printConfig(c *config) {

	wd, err := os.Getwd()
	if err != nil {
		log.Warnf("Failed to get working directory: %v", err)
	}
	log.Infof("Running estserver from working directory %v", wd)

	log.Debug("Using the following configuration:")
	log.Debugf("\tPort                : %v", c.Port)
	log.Debugf("\tSigning Key File    : %v", c.SigningKey)
	log.Debugf("\tSigning Certificates: %v", strings.Join(c.SigningCerts, ","))
	log.Debugf("\tEST Key File        : %v", c.EstKey)
	log.Debugf("\tEST Certificates    : %v", strings.Join(c.EstCerts, ","))
	log.Debugf("\tFolders to be served: %v", c.HttpFolder)
	log.Debugf("\tVerify EK Cert      : %v", c.VerifyEkCert)
	log.Debugf("\tTPM EK DB           : %v", c.TpmEkCertDb)
	log.Debugf("\tVCEK Cache Folder   : %v", c.VcekCacheFolder)
	log.Debugf("\tLog Level           : %v", c.LogLevel)
}

func loadCertChain(certChainFiles []string) ([]*x509.Certificate, error) {

	certChain := make([]*x509.Certificate, 0)

	if len(certChainFiles) == 0 {
		return nil, errors.New("failed to load certchain: not specified in config file")
	}

	// Load certificate chain
	for _, f := range certChainFiles {
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("failed to get file: %w", err)
		}
		cert, err := internal.ParseCert(pem)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate: %w", err)
		}
		certChain = append(certChain, cert)
	}

	return certChain, nil
}

func loadPrivateKey(caPrivFile string) (*ecdsa.PrivateKey, error) {

	// Read private pem-encoded key and convert it to a private key
	privBytes, err := os.ReadFile(caPrivFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get file: %w", err)
	}

	privPem, _ := pem.Decode(privBytes)

	priv, err := x509.ParseECPrivateKey(privPem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return priv, nil
}
