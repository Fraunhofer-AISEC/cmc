// Copyright (c) 2021 - 2026 Fraunhofer AISEC
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
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
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
	EstAddr          string   `json:"estAddr"`
	EstCaKey         string   `json:"estCaKey"`
	EstCaChain       []string `json:"estCaChain"`
	TlsKey           string   `json:"tlsKey"`
	TlsCaChain       []string `json:"tlsCaChain"`
	RootCas          []string `json:"rootCas"`
	AllowSystemCerts bool     `json:"allowSystemCerts"`
	HttpFolder       string   `json:"httpFolder"`
	VerifyEkCert     bool     `json:"verifyEkCert"`
	TpmEkCertDb      string   `json:"tpmEkCertDb,omitempty"`
	VcekCacheFolder  string   `json:"vcekCacheFolder,omitempty"`
	LogLevel         string   `json:"logLevel"`
	LogFile          string   `json:"logFile,omitempty"`
	AuthMethods      []string `json:"authMethods,omitempty"`
	TokenPath        string   `json:"tokenPath"`
	PublishResults   string   `json:"publishResults"`
	PublishOcsf      string   `json:"publishOcsf"`
	PublishNetwork   string   `json:"publishNetwork"`
	PublishFile      string   `json:"publishFile"`
	PublishToken     string   `json:"publishToken"`
	PublishCert      string   `json:"publishCert"`
	PublishKey       string   `json:"publishKey"`
	OmspFolder       string   `json:"omspFolder"`
	OmspKey          string   `json:"omspKey"`
	OmspCaChain      []string `json:"omspCaChain"`
	OmspUrl          string   `json:"omspUrl"`

	estCaKey    crypto.PrivateKey
	estCaChain  []*x509.Certificate
	tlsKey      crypto.PrivateKey
	tlsCaChain  []*x509.Certificate
	rootCas     []*x509.Certificate
	authMethods internal.AuthMethod
	omspKey     crypto.PrivateKey
	omspCaChain []*x509.Certificate
}

const (
	configFlag           = "config"
	tokenPathFlag        = "token-path"
	estAddrFlag          = "est-addr"
	estCaKeyFlag         = "est-ca-key"
	estCaChainFlag       = "est-ca-chain"
	tlsKeyFlag           = "tls-key"
	tlsCaChainFlag       = "tls-ca-chain"
	rootCasFlag          = "root-cas"
	allowSystemCertsFlag = "allow-system-certs"
	httpFolderFlag       = "http-folder"
	verifyEkCertFlag     = "verify-ek-cert"
	tpmEkCertDbFlag      = "tpm-ek-cert-db"
	vcekCacheFolderFlag  = "vcek-cache-folder"
	logLevelFlag         = "log-level"
	logFileFlag          = "log-file"
	authMethodsFlag      = "auth-methods"
	publishResultsFlag   = "publish-results"
	publishOcsfFlag      = "publish-ocsf"
	publishNetworkFlag   = "publish-network"
	publishFileFlag      = "publish-file"
	publishTokenFlag     = "publish-token"
	publishCertFlag      = "publish-cert"
	publishKeyFlag       = "publish-key"
	omspFolderFlag       = "omsp-folder"
	omspKeyFlag          = "omsp-key"
	omspCaChainFlag      = "omsp-ca-chain"
	omspUrlFlag          = "omsp-url"
)

var flags = []cli.Flag{
	&cli.StringFlag{
		Name:  configFlag,
		Usage: "JSON configuration file",
	},
	&cli.StringFlag{
		Name:  tokenPathFlag,
		Usage: "local address to request tokens",
	},
	&cli.StringFlag{
		Name:  estAddrFlag,
		Usage: "EST server address to listen for requests",
	},
	&cli.StringFlag{
		Name:  estCaKeyFlag,
		Usage: "path to the EST CA key for signing CSRs",
	},
	&cli.StringFlag{
		Name:  estCaChainFlag,
		Usage: "comma-separated paths to EST CA certificate chain",
	},
	&cli.StringFlag{
		Name:  tlsKeyFlag,
		Usage: "TLS key for EST HTTPS server",
	},
	&cli.StringFlag{
		Name:  tlsCaChainFlag,
		Usage: "comma-separated paths to TLS certificate chain for EST HTTPS server",
	},
	&cli.StringFlag{
		Name:  rootCasFlag,
		Usage: "comma-separated paths to trusted root CAs",
	},
	&cli.BoolFlag{
		Name:  allowSystemCertsFlag,
		Usage: "allow using the system cert pool as trusted root CAs",
	},
	&cli.StringFlag{
		Name:  httpFolderFlag,
		Usage: "folder to be served via HTTP",
	},
	&cli.BoolFlag{
		Name:  verifyEkCertFlag,
		Usage: "verify TPM EK certificate chains",
	},
	&cli.StringFlag{
		Name:  tpmEkCertDbFlag,
		Usage: "database for EK cert chain verification",
	},
	&cli.StringFlag{
		Name:  vcekCacheFolderFlag,
		Usage: "folder to cache AMD SNP VCEKs",
	},
	&cli.StringFlag{
		Name:  logLevelFlag,
		Usage: fmt.Sprintf("logging level: %v", strings.Join(maps.Keys(logLevels), ",")),
	},
	&cli.StringFlag{
		Name:  logFileFlag,
		Usage: "file to log to instead of stdout/stderr",
	},
	&cli.StringFlag{
		Name:  authMethodsFlag,
		Usage: "client authentication methods (none,token,certificate,attestation)",
	},
	&cli.StringFlag{
		Name:  publishResultsFlag,
		Usage: "HTTP address to publish attestation results to",
	},
	&cli.StringFlag{
		Name:  publishOcsfFlag,
		Usage: "HTTP address to publish OCSF detection findings to",
	},
	&cli.StringFlag{
		Name:  publishNetworkFlag,
		Usage: "HTTP address to publish lightweight network events to",
	},
	&cli.StringFlag{
		Name:  publishFileFlag,
		Usage: "file to publish attestation reports to",
	},
	&cli.StringFlag{
		Name:  publishTokenFlag,
		Usage: "HTTP authorization token for publishing attestation results",
	},
	&cli.StringFlag{
		Name:  publishCertFlag,
		Usage: "client certificate for mTLS authentication when publishing",
	},
	&cli.StringFlag{
		Name:  publishKeyFlag,
		Usage: "client key for mTLS authentication when publishing",
	},
	&cli.StringFlag{
		Name:  omspFolderFlag,
		Usage: "folder with pre-generated revocation status JSON files for SW manifests",
	},
	&cli.StringFlag{
		Name:  omspKeyFlag,
		Usage: "private key for signing OMSP responses",
	},
	&cli.StringFlag{
		Name:  omspCaChainFlag,
		Usage: "comma-separated certificate chain for the OMSP signing key",
	},
	&cli.StringFlag{
		Name:  omspUrlFlag,
		Usage: "URL of the OMSP endpoint",
	},
}

func getConfig(cmd *cli.Command) (*config, error) {
	var ok bool
	var err error

	c := &config{
		EstAddr:      "0.0.0.0:9000",
		VerifyEkCert: true,
		LogLevel:     "info",
		AuthMethods:  []string{"attestation"},
	}

	if cmd.IsSet(configFlag) {
		data, err := os.ReadFile(cmd.String(configFlag))
		if err != nil {
			return nil, fmt.Errorf("failed to read config file '%v': %w", cmd.String(configFlag), err)
		}
		err = json.Unmarshal(data, c)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal config: %w", err)
		}
	}

	if cmd.IsSet(tokenPathFlag) {
		c.TokenPath = cmd.String(tokenPathFlag)
	}
	if cmd.IsSet(estAddrFlag) {
		c.EstAddr = cmd.String(estAddrFlag)
	}
	if cmd.IsSet(estCaKeyFlag) {
		c.EstCaKey = cmd.String(estCaKeyFlag)
	}
	if cmd.IsSet(estCaChainFlag) {
		c.EstCaChain = strings.Split(cmd.String(estCaChainFlag), ",")
	}
	if cmd.IsSet(tlsKeyFlag) {
		c.TlsKey = cmd.String(tlsKeyFlag)
	}
	if cmd.IsSet(tlsCaChainFlag) {
		c.TlsCaChain = strings.Split(cmd.String(tlsCaChainFlag), ",")
	}
	if cmd.IsSet(rootCasFlag) {
		c.RootCas = strings.Split(cmd.String(rootCasFlag), ",")
	}
	if cmd.IsSet(allowSystemCertsFlag) {
		c.AllowSystemCerts = cmd.Bool(allowSystemCertsFlag)
	}
	if cmd.IsSet(httpFolderFlag) {
		c.HttpFolder = cmd.String(httpFolderFlag)
	}
	if cmd.IsSet(verifyEkCertFlag) {
		c.VerifyEkCert = cmd.Bool(verifyEkCertFlag)
	}
	if cmd.IsSet(tpmEkCertDbFlag) {
		c.TpmEkCertDb = cmd.String(tpmEkCertDbFlag)
	}
	if cmd.IsSet(vcekCacheFolderFlag) {
		c.VcekCacheFolder = cmd.String(vcekCacheFolderFlag)
	}
	if cmd.IsSet(logLevelFlag) {
		c.LogLevel = cmd.String(logLevelFlag)
	}
	if cmd.IsSet(logFileFlag) {
		c.LogFile = cmd.String(logFileFlag)
	}
	if cmd.IsSet(authMethodsFlag) {
		c.AuthMethods = strings.Split(cmd.String(authMethodsFlag), ",")
	}
	if cmd.IsSet(publishResultsFlag) {
		c.PublishResults = cmd.String(publishResultsFlag)
	}
	if cmd.IsSet(publishOcsfFlag) {
		c.PublishOcsf = cmd.String(publishOcsfFlag)
	}
	if cmd.IsSet(publishNetworkFlag) {
		c.PublishNetwork = cmd.String(publishNetworkFlag)
	}
	if cmd.IsSet(publishFileFlag) {
		c.PublishFile = cmd.String(publishFileFlag)
	}
	if cmd.IsSet(publishTokenFlag) {
		c.PublishToken = cmd.String(publishTokenFlag)
	}
	if cmd.IsSet(publishCertFlag) {
		c.PublishCert = cmd.String(publishCertFlag)
	}
	if cmd.IsSet(publishKeyFlag) {
		c.PublishKey = cmd.String(publishKeyFlag)
	}
	if cmd.IsSet(omspFolderFlag) {
		c.OmspFolder = cmd.String(omspFolderFlag)
	}
	if cmd.IsSet(omspKeyFlag) {
		c.OmspKey = cmd.String(omspKeyFlag)
	}
	if cmd.IsSet(omspCaChainFlag) {
		c.OmspCaChain = strings.Split(cmd.String(omspCaChainFlag), ",")
	}
	if cmd.IsSet(omspUrlFlag) {
		c.OmspUrl = cmd.String(omspUrlFlag)
	}

	// Configure the logger
	if c.LogFile != "" {
		file, err := os.OpenFile(c.LogFile, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		log.SetOutput(file)
	}
	l, ok := logLevels[strings.ToLower(c.LogLevel)]
	if !ok {
		log.Warnf("LogLevel %v does not exist. Default to info level", c.LogLevel)
		l = log.InfoLevel
	}
	log.SetLevel(l)

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

	c.rootCas, err = internal.ReadCerts(c.RootCas)
	if err != nil {
		return nil, fmt.Errorf("failed to load trusted metadata CAs: %w", err)
	}

	if !c.VerifyEkCert {
		log.Warn("UNSAFE: Verification of EK certificate chain turned off via config")
	}

	c.authMethods, err = internal.ParseAuthMethods(c.AuthMethods)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authentication methods: %w", err)
	}

	c.omspKey, err = internal.LoadPrivateKey(c.OmspKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load private OMSP key: %w", err)
	}

	c.omspCaChain, err = internal.ReadCerts(c.OmspCaChain)
	if err != nil {
		return nil, fmt.Errorf("failed to load OMSP certificate chain: %w", err)
	}

	// Print the parsed configuration
	printConfig(c)

	return c, nil
}

func printConfig(c *config) {

	wd, err := os.Getwd()
	if err != nil {
		log.Warnf("Failed to get working directory: %v", err)
	}
	log.Infof("Running estserver from working directory %v", wd)

	log.Debug("Using the following configuration:")
	log.Debugf("\tEST server address  : %v", c.EstAddr)
	log.Debugf("\tEST CA key file     : %v", c.EstCaKey)
	log.Debugf("\tEST CA cert chain   : %v", strings.Join(c.EstCaChain, ","))
	log.Debugf("\tTLS Key File        : %v", c.TlsKey)
	log.Debugf("\tTLS CA cert chain   : %v", strings.Join(c.TlsCaChain, ","))
	log.Debugf("\tTrusted root CAs    : %v", strings.Join(c.RootCas, ","))
	log.Debugf("\tFolders to be served: %v", c.HttpFolder)
	log.Debugf("\tVerify EK Cert      : %v", c.VerifyEkCert)
	log.Debugf("\tTPM EK DB           : %v", c.TpmEkCertDb)
	log.Debugf("\tVCEK Cache Folder   : %v", c.VcekCacheFolder)
	log.Debugf("\tLog Level           : %v", c.LogLevel)
	log.Debugf("\tAuth Methods        : %v", c.authMethods.String())
	log.Debugf("\tToken Path          : %v", c.TokenPath)
	log.Debugf("\tPublish Results     : %v", c.PublishResults)
	log.Debugf("\tPublish OCSF        : %v", c.PublishOcsf)
	log.Debugf("\tPublish Network     : %v", c.PublishNetwork)
	log.Debugf("\tPublish File        : %v", c.PublishFile)
	log.Debugf("\tPublish Token       : %v", c.PublishToken)
	log.Debugf("\tOMSP folder         : %v", c.OmspFolder)
	log.Debugf("\tOMSP Key File       : %v", c.OmspKey)
	log.Debugf("\tOMSP CA cert chain  : %v", strings.Join(c.OmspCaChain, ","))
	log.Debugf("\tOMSP URL            : %v", c.OmspUrl)
}
