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
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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

	log = logrus.WithField("service", "testtool")
)

type Api interface {
	cacerts(c *config)
	generate(c *config)
	verify(c *config)
	measure(c *config)
	dial(c *config)
	listen(c *config)
	request(c *config)
	serve(c *config)
	iothub(c *config)
}

type config struct {
	// Generic config
	Mode          string   `json:"mode"`
	Addr          []string `json:"addr"`
	ReportFile    string   `json:"report"`
	ResultFile    string   `json:"result"`
	NonceFile     string   `json:"nonce"`
	CaFile        string   `json:"ca"`
	Mtls          bool     `json:"mtls"`
	Attest        string   `json:"attest"`
	PoliciesFile  string   `json:"policies"`
	Publish       string   `json:"publish"`
	IntervalStr   string   `json:"interval"`
	Header        []string `json:"header"`
	Method        string   `json:"method"`
	Data          string   `json:"data"`
	ApiSerializer string   `json:"apiSerializer"`
	LogLevel      string   `json:"logLevel"`
	cmc.Config
	// Only to test cmcd measure API
	CtrName   string `json:"ctrName"`
	CtrRootfs string `json:"ctrRootfs"`
	CtrConfig string `json:"ctrConfig"`

	ca            []byte
	policies      []byte
	api           Api
	interval      time.Duration
	apiSerializer ar.Serializer
	attest        atls.AttestSelect
}

// Defines the testool specic flags. CMC flags are defined in cmc/config.go
const (
	// Generic flags
	configFlag        = "config"
	modeFlag          = "mode"
	addrFlag          = "addr"
	reportFlag        = "report"
	resultFlag        = "result"
	nonceFlag         = "nonce"
	caFlag            = "ca"
	policiesFlag      = "policies"
	mtlsFlag          = "mtls"
	attestFlag        = "attest"
	logFlag           = "log"
	publishFlag       = "publish"
	intervalFlag      = "interval"
	apiSerializerFlag = "apiserializer"
	headerFlag        = "header"
	methodFlag        = "method"
	dataFlag          = "data"
	logLevelFlag      = "loglevel"
	// Only to test cmcd measure API
	ctrNameFlag   = "ctrname"
	ctrRootfsFlag = "ctrrootfs"
	ctrConfigFlag = "ctrconfig"
)

var (
	configFile = flag.String(configFlag, "", "JSON Configuration file")
	mode       = flag.String(modeFlag, "",
		fmt.Sprintf("Commands the testtol can run: %v", maps.Keys(cmds)))
	addr = flag.String(addrFlag, "",
		"Address to connect to / listen on via attested tls / https")
	reportFile   = flag.String(reportFlag, "", "Output file for the attestation report")
	resultFile   = flag.String(resultFlag, "", "Output file for the attestation result")
	nonceFile    = flag.String(nonceFlag, "", "Output file for the nonce")
	caFile       = flag.String(caFlag, "", "Certificate Authorities to be trusted in PEM format")
	policiesFile = flag.String(policiesFlag, "", "JSON policies file for custom verification")
	mtls         = flag.Bool(mtlsFlag, false, "Performs mutual TLS")
	attest       = flag.String(attestFlag, "", "Peforms performs remote attestation: mutual, server only,"+
		"client only, or none [mutual, client, server, none]")
	publish  = flag.String(publishFlag, "", "Optional HTTP address to publish attestation results to")
	interval = flag.String(intervalFlag, "",
		"Interval at which connectors will be attested. If set to '0s', attestation will only be"+
			" done once")
	apiSerializer = flag.String(apiSerializerFlag, "",
		"Serializer to be used for internal socket and CoAP API and aTLS (JSON or CBOR)")
	headers  = flag.String(headerFlag, "", "Set header for HTTP POST requests")
	method   = flag.String(methodFlag, "", "Set HTTP request method (GET, POST, PUT, HEADER)")
	data     = flag.String(dataFlag, "", "Set HTTP body for POST and PUT requests")
	logLevel = flag.String(logLevelFlag, "",
		fmt.Sprintf("Possible logging: %v", strings.Join(maps.Keys(logLevels), ",")))
	//  Only to test cmcd measure API
	ctrName   = flag.String(ctrNameFlag, "", "Specifies name of container to be measured")
	ctrRootfs = flag.String(ctrRootfsFlag, "", "Specifies rootfs path of the container to be measured")
	ctrConfig = flag.String(ctrConfigFlag, "", "Specifies config path of the container to be measured")
)

func getConfig() *config {
	var ok bool

	flag.Parse()

	// Initialize configuration with some default values
	c := &config{
		ApiSerializer: "cbor",
		Attest:        "mutual",
		IntervalStr:   "0s",
	}

	// Obtain configuration from json configuration file
	if internal.FlagPassed(configFlag) {
		files := strings.Split(*configFile, ",")
		for _, f := range files {
			log.Infof("Loading config from file %v", f)
			data, err := os.ReadFile(f)
			if err != nil {
				log.Fatalf("Failed to read testtool config file %v: %v", f, err)
			}
			err = json.Unmarshal(data, c)
			if err != nil {
				log.Fatalf("Failed to parse testtool config: %v", err)
			}
		}
	}

	// Overwrite cmc configuration with values passed via command line (only required for libapi)
	err := cmc.GetConfig(&c.Config)
	if err != nil {
		log.Fatalf("Failed to read cmc config: %v", err)
	}

	// Overwrite testtool configuration with values passed via command line
	if internal.FlagPassed(modeFlag) {
		c.Mode = *mode
	}
	if internal.FlagPassed(addrFlag) {
		c.Addr = strings.Split(*addr, ",")
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
	if internal.FlagPassed(caFlag) {
		c.CaFile = *caFile
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
	if internal.FlagPassed(logFlag) {
		c.LogLevel = *logLevel
	}
	if internal.FlagPassed(publishFlag) {
		c.Publish = *publish
	}
	if internal.FlagPassed(intervalFlag) {
		c.IntervalStr = *interval
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
	//  Only to test cmcd measure API
	if internal.FlagPassed(ctrNameFlag) {
		c.CtrName = *ctrName
	}
	if internal.FlagPassed(ctrRootfsFlag) {
		c.CtrRootfs = *ctrRootfs
	}
	if internal.FlagPassed(ctrConfigFlag) {
		c.CtrConfig = *ctrConfig
	}

	// Configure the logger
	l, ok := logLevels[strings.ToLower(c.LogLevel)]
	if !ok {
		log.Warnf("LogLevel %v does not exist. Default to info level", c.LogLevel)
		l = logrus.InfoLevel
	}
	log.Infof("Configuring logger for log level %v", c.LogLevel)
	logrus.SetLevel(l)

	intervalDuration, err := time.ParseDuration(c.IntervalStr)
	if err != nil {
		log.Fatalf("Failed to parse monitoring interval: %v", err)
	}
	c.interval = intervalDuration

	// Basic sanity checks
	if _, ok := cmds[c.Mode]; !ok {
		flag.Usage()
		log.Fatalf("Unknown mode '%v' specified", c.Mode)
	}

	// Convert all paths to absolute paths
	pathsToAbs(c)

	// Print the parsed configuration
	c.Print()

	// Get root CA certificate in PEM format if specified
	if c.Mode != "generate" && c.Mode != "cacerts" && c.Mode != "measure" {
		if c.CaFile != "" {
			c.ca, err = os.ReadFile(c.CaFile)
			if err != nil {
				log.Fatalf("Failed to read certificate file %v: %v", *caFile, err)
			}
		} else {
			log.Fatal("Path to read CA certificate file must be specified either via config file or commandline")
		}
	}

	if c.Mode == "cacerts" && c.CaFile == "" {
		log.Fatal("Path to store CA file must be specified either via config file or commandline")
	}

	// Add optional policies if specified
	if c.PoliciesFile != "" {
		log.Debug("Adding specified policies")
		c.policies, err = os.ReadFile(c.PoliciesFile)
		if err != nil {
			log.Fatalf("Failed to read policies file: %v", err)
		}
	}

	// Get Serializer
	log.Tracef("Getting serializer %v", c.ApiSerializer)
	c.apiSerializer, ok = serializers[strings.ToLower(c.ApiSerializer)]
	if !ok {
		flag.Usage()
		log.Fatalf("Serializer %v is not implemented", c.ApiSerializer)
	}

	// Get API
	c.api, ok = apis[strings.ToLower(c.Api)]
	if !ok {
		flag.Usage()
		log.Fatalf("API '%v' is not implemented", c.Api)
	}

	// Get attestation mode
	c.attest, err = GetAttestMode(c.Attest)
	if err != nil {
		log.Fatalf("failed to get attestation mode: %v", err)
	}

	return c
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
	if c.CaFile != "" {
		c.CaFile, err = filepath.Abs(c.CaFile)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.CaFile, err)
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
	if c.PeerCache != "" {
		c.PeerCache, err = filepath.Abs(c.PeerCache)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.PeerCache, err)
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
	log.Infof("Running testtool from working directory %v", wd)

	log.Debugf("Using the following configuration:")
	log.Debugf("\tMode                     : %v", c.Mode)
	log.Debugf("\tAddress                  : %v", c.Addr)
	log.Debugf("\tInterval                 : %v", c.interval)
	log.Debugf("\tCMC API Address          : %v", c.CmcAddr)
	log.Debugf("\tReportFile               : %v", c.ReportFile)
	log.Debugf("\tResultFile               : %v", c.ResultFile)
	log.Debugf("\tNonceFile                : %v", c.NonceFile)
	log.Debugf("\tCaFile                   : %v", c.CaFile)
	log.Debugf("\tMtls                     : %v", c.Mtls)
	log.Debugf("\tLogLevel                 : %v", c.LogLevel)
	log.Debugf("\tAttest                   : %v", c.Attest)
	log.Debugf("\tAPI Serializer           : %v", c.ApiSerializer)
	log.Debugf("\tPublish                  : %v", c.Publish)
	log.Debugf("\tApi                      : %v", c.Api)
	if strings.EqualFold(c.Mode, "request") {
		log.Debugf("\tHTTP Data                : %v", c.Data)
		log.Debugf("\tHTTP Header              : %v", c.Header)
		log.Debugf("\tHTTP Method              : %v", c.Method)
	}
	if c.PoliciesFile != "" {
		log.Debugf("\tPoliciesFile            : %v", c.PoliciesFile)
	}
	if strings.EqualFold(c.Api, "libapi") {
		c.Config.Print()
	}
}
