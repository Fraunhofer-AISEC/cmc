// Copyright (c) 2021 - 2024 Fraunhofer AISEC
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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

const (
	timeoutSec = 10
)

var (
	apis = map[string]Api{}

	serializers = map[string]ar.Serializer{
		"json": ar.JsonSerializer{},
		"cbor": ar.CborSerializer{},
	}

	logLevels = map[string]logrus.Level{
		"panic": logrus.PanicLevel,
		"fatal": logrus.FatalLevel,
		"error": logrus.ErrorLevel,
		"warn":  logrus.WarnLevel,
		"info":  logrus.InfoLevel,
		"debug": logrus.DebugLevel,
		"trace": logrus.TraceLevel,
	}

	log = logrus.WithField("service", "cmcctl")
)

type Api interface {
	generate(c *config)
	verify(c *config)
	dial(c *config)
	listen(c *config)
	request(c *config)
	serve(c *config)
	updateMetadata(c *config)
	updateCerts(c *config)
}

type config struct {
	// Generic config
	Addr             string   `json:"addr"`
	ReportFile       string   `json:"report"`
	ResultFile       string   `json:"result"`
	NonceFile        string   `json:"nonce"`
	EstTlsCa         string   `json:"estTlsCa"`
	Mtls             bool     `json:"mtls"`
	Attest           string   `json:"attest"`
	PoliciesFile     string   `json:"policies"`
	Publish          string   `json:"publish"`
	Header           []string `json:"header"`
	Method           string   `json:"method"`
	Data             string   `json:"data"`
	ApiSerializer    string   `json:"apiSerializer"`
	LogLevel         string   `json:"logLevel"`
	LogFile          string   `json:"logFile"`
	TokenStore       string   `json:"tokenStore"`
	PublishTokenFile string   `json:"publishToken"`
	cmc.Config

	identityCas   []*x509.Certificate
	policies      []byte
	api           Api
	apiSerializer ar.Serializer
	attest        atls.AttestSelect
	publishToken  []byte
}

// Defines the testool specic flags. CMC flags are defined in cmc/config.go
const (
	// Generic flags
	configFlag        = "config"
	addrFlag          = "addr"
	reportFlag        = "report"
	resultFlag        = "result"
	nonceFlag         = "nonce"
	estTlsCaFlag      = "esttlsca"
	policiesFlag      = "policies"
	mtlsFlag          = "mtls"
	attestFlag        = "attest"
	publishFlag       = "publish"
	apiSerializerFlag = "apiserializer"
	headerFlag        = "header"
	methodFlag        = "method"
	dataFlag          = "data"
	logLevelFlag      = "loglevel"
	logFileFlag       = "logfile"
	tokenStoreFlag    = "tokenstore"
	publishTokenFlag  = "publishtoken"
)

var (
	configFile   = flag.String(configFlag, "", "JSON Configuration file")
	addr         = flag.String(addrFlag, "", "Address to connect to / listen on via attested tls / https")
	reportFile   = flag.String(reportFlag, "", "Output file for the attestation report")
	resultFile   = flag.String(resultFlag, "", "Output file for the attestation result")
	nonceFile    = flag.String(nonceFlag, "", "Output file for the nonce")
	estTlsCa     = flag.String(estTlsCaFlag, "", "Path to store retrieved CA certificates")
	policiesFile = flag.String(policiesFlag, "", "JSON policies file for custom verification")
	mtls         = flag.Bool(mtlsFlag, false, "Performs mutual TLS")
	attest       = flag.String(attestFlag, "", "Peforms performs remote attestation: mutual, server only,"+
		"client only, or none [mutual, client, server, none]")
	publish       = flag.String(publishFlag, "", "Optional HTTP address to publish attestation results to")
	apiSerializer = flag.String(apiSerializerFlag, "",
		"Serializer to be used for internal socket and CoAP API and aTLS (JSON or CBOR)")
	headers = flag.String(headerFlag, "", "Set header for HTTP POST requests")
	method  = flag.String(methodFlag, "", "Set HTTP request method (GET, POST, PUT, HEADER)")
	data    = flag.String(dataFlag, "",
		"Set aTLS payload for command dial or HTTP body for POST and PUT requests for command request")
	logLevel = flag.String(logLevelFlag, "",
		fmt.Sprintf("Possible logging: %v", strings.Join(maps.Keys(logLevels), ",")))
	logFile      = flag.String(logFileFlag, "", "Optional file to log to instead of stdout/stderr")
	tokenStore   = flag.String(tokenStoreFlag, "", "Path to token store for token mode")
	publishtoken = flag.String(publishTokenFlag, "", "Path to token for backend authorization")
)

func getConfig(cmd string) (*config, error) {
	var ok bool

	os.Args = append([]string{os.Args[0]}, os.Args[2:]...)

	flag.Parse()

	// Initialize configuration with some default values
	c := &config{
		Config: cmc.Config{
			Api: "socket",
		},
		ApiSerializer: "cbor",
		Attest:        "mutual",
	}

	// Obtain configuration from json configuration file
	if internal.FlagPassed(configFlag) {
		files := strings.Split(*configFile, ",")
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				return nil, fmt.Errorf("failed to read cmcctl config file %v: %v", f, err)
			}
			err = json.Unmarshal(data, c)
			if err != nil {
				return nil, fmt.Errorf("failed to parse cmcctl config: %v", err)
			}
		}
	}

	// Overwrite cmc configuration with values passed via command line (only required for libapi)
	err := cmc.GetConfig(&c.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to read cmc config: %v", err)
	}

	// Overwrite cmcctl configuration with values passed via command line
	if internal.FlagPassed(addrFlag) {
		c.Addr = *addr
	}
	if internal.FlagPassed(reportFlag) {
		c.ReportFile = *reportFile
	}
	if internal.FlagPassed(resultFlag) {
		c.ResultFile = *resultFile
	}
	if internal.FlagPassed(nonceFlag) {
		c.NonceFile = *nonceFile
	}
	if internal.FlagPassed(estTlsCaFlag) {
		c.EstTlsCa = *estTlsCa
	}
	if internal.FlagPassed(policiesFlag) {
		c.PoliciesFile = *policiesFile
	}
	if internal.FlagPassed(mtlsFlag) {
		c.Mtls = *mtls
	}
	if internal.FlagPassed(attestFlag) {
		c.Attest = *attest
	}
	if internal.FlagPassed(publishFlag) {
		c.Publish = *publish
	}
	if internal.FlagPassed(apiSerializerFlag) {
		c.ApiSerializer = *apiSerializer
	}
	if internal.FlagPassed(headerFlag) {
		c.Header = strings.Split(*headers, ",")
	}
	if internal.FlagPassed(methodFlag) {
		c.Method = *method
	}
	if internal.FlagPassed(dataFlag) {
		c.Data = *data
	}
	if internal.FlagPassed(logLevelFlag) {
		c.LogLevel = *logLevel
	}
	if internal.FlagPassed(logFileFlag) {
		c.LogFile = *logFile
	}
	if internal.FlagPassed(tokenStoreFlag) {
		c.TokenStore = *tokenStore
	}
	if internal.FlagPassed(publishTokenFlag) {
		c.PublishTokenFile = *publishtoken
	}

	// Configure the logger
	if c.LogFile != "" {
		lf, err := filepath.Abs(*logFile)
		if err != nil {
			return nil, fmt.Errorf("failed to get logfile path: %v", err)
		}
		file, err := os.OpenFile(lf, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
		}
		logrus.SetOutput(file)
	}
	if c.LogLevel != "" {
		l, ok := logLevels[strings.ToLower(c.LogLevel)]
		if !ok {
			log.Warnf("LogLevel %v does not exist. Default to info level", c.LogLevel)
			l = logrus.InfoLevel
		}
		logrus.SetLevel(l)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	// Convert all paths to absolute paths
	pathsToAbs(c)

	// Print the parsed configuration
	c.Print()

	// Get root CA certificate in PEM format if specified
	if cmd == "dial" || cmd == "listen" || cmd == "request" || cmd == "serve" {
		if len(c.IdentityCas) == 0 {
			log.Fatal("Path to read Report CAs must be specified either via config file or commandline")
		}

		for _, ca := range c.IdentityCas {
			ca, err := os.ReadFile(ca)
			if err != nil {
				return nil, fmt.Errorf("failed to read certificate file %v: %v", ca, err)
			}
			cert, err := internal.ParseCert(ca)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate %v: %v", ca, err)
			}
			c.identityCas = append(c.identityCas, cert)
		}

	}

	if (cmd == "cacerts" || cmd == "provision") && c.EstTlsCa == "" {
		log.Fatal("Path to store CA must be specified either via config file or commandline")
	}
	if cmd == "provision" && c.ProvisionToken == "" {
		log.Fatal("Path to store bootstrap token must be specified either via config file or commandline")
	}

	// Add optional policies if specified
	if c.PoliciesFile != "" {
		log.Debug("Adding specified policies")
		c.policies, err = os.ReadFile(c.PoliciesFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read policies file: %w", err)
		}
	}

	if c.PublishTokenFile != "" {
		log.Debugf("Retrieving publish token %v", c.PublishTokenFile)
		c.publishToken, err = os.ReadFile(c.PublishTokenFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read publish token: %w", err)
		}
	}

	// Get Serializer
	log.Debugf("Getting serializer %v", c.ApiSerializer)
	c.apiSerializer, ok = serializers[strings.ToLower(c.ApiSerializer)]
	if !ok {
		flag.Usage()
		return nil, fmt.Errorf("serializer %v is not implemented", c.ApiSerializer)
	}

	// Get API
	c.api, ok = apis[strings.ToLower(c.Api)]
	if !ok {
		flag.Usage()
		return nil, fmt.Errorf("API '%v' is not implemented", c.Api)
	}

	// Get attestation mode
	c.attest, err = GetAttestMode(c.Attest)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation mode: %v", err)
	}

	return c, nil
}

func pathsToAbs(c *config) {
	var err error
	if c.ReportFile != "" {
		c.ReportFile, err = filepath.Abs(c.ReportFile)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.ReportFile, err)
		}
	}
	if c.ResultFile != "" {
		c.ResultFile, err = filepath.Abs(c.ResultFile)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.ResultFile, err)
		}
	}
	if c.NonceFile != "" {
		c.NonceFile, err = filepath.Abs(c.NonceFile)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.NonceFile, err)
		}
	}
	if c.Storage != "" {
		c.Storage, err = filepath.Abs(c.Storage)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.Storage, err)
		}
	}
	if c.Cache != "" {
		c.Cache, err = filepath.Abs(c.Cache)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.Cache, err)
		}
	}
	if c.EstTlsCa != "" {
		c.EstTlsCa, err = filepath.Abs(c.EstTlsCa)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.EstTlsCa, err)
		}
	}
	if c.ProvisionToken != "" {
		c.ProvisionToken, err = filepath.Abs(c.ProvisionToken)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.ProvisionToken, err)
		}
	}
	if c.TokenStore != "" {
		c.TokenStore, err = filepath.Abs(c.TokenStore)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.TokenStore, err)
		}
	}
	if c.PeerCache != "" {
		c.PeerCache, err = filepath.Abs(c.PeerCache)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.PeerCache, err)
		}
	}
	for i := range c.IdentityCas {
		c.IdentityCas[i], err = filepath.Abs(c.IdentityCas[i])
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.IdentityCas[i], err)
		}
	}
}

func GetAttestMode(attest string) (atls.AttestSelect, error) {
	var selection atls.AttestSelect
	switch attest {
	case "mutual":
		selection = atls.Attest_Mutual
	case "client":
		selection = atls.Attest_Client
	case "server":
		selection = atls.Attest_Server
	case "none":
		selection = atls.Attest_None
	default:
		return 0, fmt.Errorf("unknown mode %v", attest)
	}
	return selection, nil
}

func (c *config) Print() {
	wd, err := os.Getwd()
	if err != nil {
		log.Warnf("Failed to get working directory: %v", err)
	}
	log.Infof("Running cmcctl from working directory %v", wd)

	log.Debugf("Using the following configuration:")
	log.Debugf("\tAddress                  : %v", c.Addr)
	log.Debugf("\tCMC API Address          : %v", c.CmcAddr)
	log.Debugf("\tReportFile               : %v", c.ReportFile)
	log.Debugf("\tResultFile               : %v", c.ResultFile)
	log.Debugf("\tNonceFile                : %v", c.NonceFile)
	log.Debugf("\tIdentity CAs             : %v", strings.Join(c.IdentityCas, ","))
	log.Debugf("\tEstCa                    : %v", c.EstTlsCa)
	log.Debugf("\tMtls                     : %v", c.Mtls)
	log.Debugf("\tLogLevel                 : %v", c.LogLevel)
	log.Debugf("\tAttest                   : %v", c.Attest)
	log.Debugf("\tAPI Serializer           : %v", c.ApiSerializer)
	log.Debugf("\tPublish                  : %v", c.Publish)
	log.Debugf("\tApi                      : %v", c.Api)
	log.Debugf("\tTLS / HTTP Payload       : %v", c.Data)
	log.Debugf("\tHTTP Header              : %v", c.Header)
	log.Debugf("\tHTTP Method              : %v", c.Method)
	log.Debugf("\tToken Store              : %v", c.TokenStore)
	log.Debugf("\tBackend Token            : %v", c.PublishTokenFile)
	if c.PoliciesFile != "" {
		log.Debugf("\tPoliciesFile            : %v", c.PoliciesFile)
	}
	if strings.EqualFold(c.Api, "libapi") {
		c.Config.Print()
	}
}
