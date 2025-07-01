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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision"
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
	EstAddr         string   `json:"estAddr"`
	EstCaKey        string   `json:"estCaKey"`
	EstCaChain      []string `json:"estCaChain"`
	TlsKey          string   `json:"tlsKey"`
	TlsCaChain      []string `json:"tlsCaChain"`
	MetadataCas     []string `json:"metadataCas"`
	ClientTlsCas    []string `json:"clientTlsCas"`
	HttpFolder      string   `json:"httpFolder"`
	VerifyEkCert    bool     `json:"verifyEkCert"`
	TpmEkCertDb     string   `json:"tpmEkCertDb,omitempty"`
	VcekCacheFolder string   `json:"vcekCacheFolder,omitempty"`
	LogLevel        string   `json:"logLevel"`
	LogFile         string   `json:"logFile,omitempty"`
	AuthMethods     []string `json:"authMethods,omitempty"`
	TokenPath       string   `json:"tokenPath"`

	estCaKey    *ecdsa.PrivateKey
	estCaChain  []*x509.Certificate
	tlsKey      *ecdsa.PrivateKey
	tlsCaChain  []*x509.Certificate
	metadataCas []*x509.Certificate
	authMethods provision.AuthMethod
}

const (
	configFlag          = "config"
	tokenPathFlag       = "tokenPath"
	estAddrFlag         = "estaddr"
	estCaKeyFlag        = "estcakey"
	estCaChainFlag      = "estcachain"
	tlsKeyFlag          = "tlskey"
	tlsCaChainFlag      = "tlscachain"
	metadataCasFlag     = "metadatacas"
	clientTlsCasFlag    = "clienttlscas"
	httpFolderFlag      = "httpfolder"
	verifyEkCertFlag    = "verifyekcert"
	tpmEkCertDbFlag     = "tpmekcertdb"
	vcekCacheFolderFlag = "vcekcachefolder"
	logLevelFlag        = "loglevel"
	logFileFlag         = "logfile"
	authMethodsFlag     = "authmethods"
)

func getConfig() (*config, error) {
	var ok bool
	var err error

	// Parse given command line flags
	configFile := flag.String(configFlag, "", "configuration file")
	tokenAddr := flag.String(tokenPathFlag, "", "Local address to request tokens")
	estAddr := flag.String(estAddrFlag, "", "EST server address to listen for EST requests")
	estCaKey := flag.String(estCaKeyFlag, "", "Path to the EST CA key for signing CSRs")
	estCaChain := flag.String(estCaChainFlag, "", "Path to the EST CA certificate chain")
	tlsKey := flag.String(tlsKeyFlag, "", "TLS key for EST HTTPS server")
	tlsCaChain := flag.String(tlsCaChainFlag, "", "TLS certificate chain for EST HTTPS server")
	metadataCas := flag.String(metadataCasFlag, "", "Trusted metadata root CAs for attest enroll")
	clientTlsCas := flag.String(clientTlsCasFlag, "", "Trusted root CAs for client authentication if active")
	httpFolder := flag.String(httpFolderFlag, "", "Folder to be served")
	verifyEkCert := flag.Bool(verifyEkCertFlag, false,
		"Indicates whether to verify TPM EK certificate chains")
	tpmEkCertDb := flag.String(tpmEkCertDbFlag, "", "Database for EK cert chain verification")
	vcekCacheFolder := flag.String(vcekCacheFolderFlag, "", "Folder to cache AMD SNP VCEKs")
	logLevel := flag.String(logLevelFlag, "",
		fmt.Sprintf("Possible logging: %v", maps.Keys(logLevels)))
	logFile := flag.String(logFileFlag, "", "Optional file to log to instead of stdout/stderr")
	authMethods := flag.String(authMethodsFlag, "", "Client authentication methods (none,token,certificate,attestation)")
	flag.Parse()

	// Create default configuration
	c := &config{
		EstAddr:      "0.0.0.0:9000",
		VerifyEkCert: true,
		LogLevel:     "info",
		AuthMethods:  []string{"attestation"},
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
	if internal.FlagPassed(tokenPathFlag) {
		c.TokenPath = *tokenAddr
	}
	if internal.FlagPassed(estAddrFlag) {
		c.EstAddr = *estAddr
	}
	if internal.FlagPassed(estCaKeyFlag) {
		c.EstCaKey = *estCaKey
	}
	if internal.FlagPassed(estCaChainFlag) {
		c.EstCaChain = strings.Split(*estCaChain, ",")
	}
	if internal.FlagPassed(tlsKeyFlag) {
		c.TlsKey = *tlsKey
	}
	if internal.FlagPassed(tlsCaChainFlag) {
		c.TlsCaChain = strings.Split(*tlsCaChain, ",")
	}
	if internal.FlagPassed(metadataCasFlag) {
		c.MetadataCas = strings.Split(*metadataCas, ",")
	}
	if internal.FlagPassed(*clientTlsCas) {
		c.ClientTlsCas = strings.Split(*clientTlsCas, ",")
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
	if internal.FlagPassed(logLevelFlag) {
		c.LogLevel = *logLevel
	}
	if internal.FlagPassed(logFileFlag) {
		c.LogFile = *logFile
	}
	if internal.FlagPassed(authMethodsFlag) {
		c.AuthMethods = strings.Split(*authMethods, ",")
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
		log.Warnf("LogLevel %v does not exist Default to info level", c.LogLevel)
		l = log.InfoLevel
	}
	log.SetLevel(l)

	// Convert all paths to absolute paths
	pathsToAbs(c)

	// Load specified files
	c.estCaKey, err = internal.LoadPrivateKey(c.EstCaKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	c.estCaChain, err = internal.ReadCerts(c.EstCaChain)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate chain: %w", err)
	}

	c.tlsKey, err = internal.LoadPrivateKey(c.TlsKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	c.tlsCaChain, err = internal.ReadCerts(c.TlsCaChain)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate chain: %w", err)
	}

	c.metadataCas, err = internal.ReadCerts(c.MetadataCas)
	if err != nil {
		return nil, fmt.Errorf("failed to load trusted metadata CAs: %w", err)
	}

	if !c.VerifyEkCert {
		log.Warn("UNSAFE: Verification of EK certificate chain turned off via config")
	}

	c.authMethods, err = provision.ParseAuthMethods(c.AuthMethods)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authentication methods: %w", err)
	}

	// Print the parsed configuration
	printConfig(c)

	return c, nil
}

func pathsToAbs(c *config) {
	var err error
	c.EstCaKey, err = filepath.Abs(c.EstCaKey)
	if err != nil {
		log.Warnf("Failed to get absolute path for %v: %v", c.EstCaKey, err)
	}

	for i := 0; i < len(c.EstCaChain); i++ {
		c.EstCaChain[i], err = filepath.Abs(c.EstCaChain[i])
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.EstCaChain[i], err)
		}
	}

	c.TlsKey, err = filepath.Abs(c.TlsKey)
	if err != nil {
		log.Warnf("Failed to get absolute path for %v: %v", c.TlsKey, err)
	}

	for i := 0; i < len(c.TlsCaChain); i++ {
		c.TlsCaChain[i], err = filepath.Abs(c.TlsCaChain[i])
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.TlsCaChain[i], err)
		}
	}

	for i := 0; i < len(c.MetadataCas); i++ {
		c.MetadataCas[i], err = filepath.Abs(c.MetadataCas[i])
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.MetadataCas[i], err)
		}
	}

	for i := 0; i < len(c.ClientTlsCas); i++ {
		c.ClientTlsCas[i], err = filepath.Abs(c.ClientTlsCas[i])
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.MetadataCas[i], err)
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
	log.Debugf("\tToken path          : %v", c.TokenPath)
	log.Debugf("\tEST server address  : %v", c.EstAddr)
	log.Debugf("\tEST CA key file     : %v", c.EstCaKey)
	log.Debugf("\tEST CA cert chain   : %v", strings.Join(c.EstCaChain, ","))
	log.Debugf("\tTLS Key File        : %v", c.TlsKey)
	log.Debugf("\tTLS CA cert chain   : %v", strings.Join(c.TlsCaChain, ","))
	log.Debugf("\tMetadata CAs        : %v", strings.Join(c.MetadataCas, ","))
	for _, cca := range c.ClientTlsCas {
		log.Debugf("\tClient TLS CAs:     : %v", cca)
	}
	log.Debugf("\tFolders to be served: %v", c.HttpFolder)
	log.Debugf("\tVerify EK Cert      : %v", c.VerifyEkCert)
	log.Debugf("\tTPM EK DB           : %v", c.TpmEkCertDb)
	log.Debugf("\tVCEK Cache Folder   : %v", c.VcekCacheFolder)
	log.Debugf("\tLog Level           : %v", c.LogLevel)
	log.Debugf("\tAuth Methods        : %v", c.authMethods.String())
	log.Debugf("\tToken Path          : %v", c.TokenPath)
}
