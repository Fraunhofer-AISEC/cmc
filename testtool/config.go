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
	generate(c *config)
	verify(c *config)
	dial(c *config)
	listen(c *config)
	iothub(c *config)
	cacerts(c *config)
	request(c *config)
	serve(c *config)
}

type config struct {
	Mode           string   `json:"mode"`
	Addr           []string `json:"addr"`
	CmcAddr        string   `json:"cmc"`
	ReportFile     string   `json:"report"`
	ResultFile     string   `json:"result"`
	NonceFile      string   `json:"nonce"`
	CaFile         string   `json:"ca"`
	Mtls           bool     `json:"mtls"`
	Attest         string   `json:"attest"`
	PoliciesFile   string   `json:"policies"`
	Api            string   `json:"api"`
	Network        string   `json:"network"`
	LogLevel       string   `json:"logLevel"`
	Publish        string   `json:"publish"`
	IntervalStr    string   `json:"interval"`
	ProvAddr       string   `json:"provServerAddr"`
	Metadata       []string `json:"metadata"`
	Drivers        []string `json:"drivers"`
	Storage        string   `json:"storage"`
	Cache          string   `json:"cache"`
	MeasurementLog bool     `json:"measurementLog"`
	Header         []string `json:"header"`
	Method         string   `json:"method"`
	Data           string   `json:"data"`

	ca       []byte
	policies []byte
	api      Api
	interval time.Duration
}

const (
	configFlag         = "config"
	modeFlag           = "mode"
	addrFlag           = "addr"
	cmcFlag            = "cmc"
	reportFlag         = "report"
	resultFlag         = "result"
	nonceFlag          = "nonce"
	caFlag             = "ca"
	policiesFlag       = "policies"
	apiFlag            = "api"
	networkFlag        = "network"
	mtlsFlag           = "mtls"
	attestFlag         = "attest"
	logFlag            = "log"
	publishFlag        = "publish"
	intervalFlag       = "interval"
	provAddrFlag       = "prov"
	metadataFlag       = "metadata"
	driversFlag        = "drivers"
	storageFlag        = "storage"
	cacheFlag          = "cache"
	measurementLogFlag = "measurementLog"
	headerFlag         = "header"
	methodFlag         = "method"
	dataFlag           = "data"
)

func getConfig() *config {
	var err error
	var ok bool

	// Parse given command line flags
	configFile := flag.String(configFlag, "", "Configuration file")
	mode := flag.String(modeFlag, "", fmt.Sprintf("Possible modes: %v", maps.Keys(cmds)))
	addr := flag.String(addrFlag, "", "Server ip:port to connect to / listen on via attested tls")
	cmcAddr := flag.String(cmcFlag, "", "TCP address to connect to the cmcd API")
	reportFile := flag.String(reportFlag, "", "Output file for the attestation report")
	resultFile := flag.String(resultFlag, "", "Output file for the attestation result")
	nonceFile := flag.String(nonceFlag, "", "Output file for the nonce")
	caFile := flag.String(caFlag, "", "Certificate Authorities to be trusted in PEM format")
	policiesFile := flag.String(policiesFlag, "", "JSON policies file for custom verification")
	api := flag.String(apiFlag, "", fmt.Sprintf("APIs for cmcd. Possible: %v", maps.Keys(apis)))
	network := flag.String(networkFlag, "", "Network for socket API [unix tcp]")
	mtls := flag.Bool(mtlsFlag, false, "Performs mutual TLS")
	attest := flag.String(attestFlag, "", "Peforms performs remote attestation: mutual, server only,"+
		"client only, or none [mutual, server, client, none]")
	logLevel := flag.String(logFlag, "",
		fmt.Sprintf("Possible logging: %v", maps.Keys(logLevels)))
	publish := flag.String(publishFlag, "", "HTTP address to publish attestation results to")
	interval := flag.String(intervalFlag, "",
		"Interval at which connectors will be attested. If set to <=0, attestation will only be"+
			" done once")
	// Lib API flags
	provAddr := flag.String(provAddrFlag, "",
		"Address of the provisioning server (only for libapi)")
	metadata := flag.String(metadataFlag, "", "List of locations with metadata, starting either "+
		"with file:// for local locations or https:// for remote locations (can be mixed)"+
		"(only for libapi)")
	driversList := flag.String(driversFlag, "",
		fmt.Sprintf("Drivers (comma separated list). Only for libapi. Possible: %v",
			strings.Join(maps.Keys(cmc.GetDrivers()), ",")))
	storage := flag.String(storageFlag, "",
		"Optional folder to store internal CMC data in (only for libapi)")
	cache := flag.String(cacheFlag, "",
		"Optional folder to cache metadata for offline backup (only for libapi)")
	measurementLog := flag.Bool(measurementLogFlag, false, "Indicates whether to include measured events in measurement and validation report")
	headers := flag.String(headerFlag, "", "Set header for HTTP POST requests")
	method := flag.String(methodFlag, "", "Set HTTP request method (GET, POST, PUT, HEADER)")
	data := flag.String(dataFlag, "", "Set HTTP body for POST and PUT requests")

	flag.Parse()

	// Create default configuration
	c := &config{
		Mode:        "generate",
		Addr:        []string{"0.0.0.0:4443"},
		CmcAddr:     "127.0.0.1:9955",
		ReportFile:  "attestation-report",
		ResultFile:  "attestation-result.json",
		NonceFile:   "nonce",
		Api:         "grpc",
		LogLevel:    "info",
		IntervalStr: "0s",
		Method:      "GET",
	}

	// Obtain custom configuration from file if specified
	if internal.FlagPassed(configFlag) {
		log.Infof("Loading config from file %v", *configFile)
		data, err := os.ReadFile(*configFile)
		if err != nil {
			log.Fatalf("Failed to read testtool config file %v: %v", *configFile, err)
		}
		err = json.Unmarshal(data, c)
		if err != nil {
			log.Fatalf("Failed to parse testtool config: %v", err)
		}
	}

	// Overwrite config file configuration with given command line arguments
	if internal.FlagPassed(modeFlag) {
		c.Mode = *mode
	}
	if internal.FlagPassed(addrFlag) {
		c.Addr = strings.Split(*addr, ",")
	}
	if internal.FlagPassed(cmcFlag) {
		c.CmcAddr = *cmcAddr
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
	if internal.FlagPassed(apiFlag) {
		c.Api = *api
	}
	if internal.FlagPassed(networkFlag) {
		c.Network = *network
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
	// Lib API flags
	if internal.FlagPassed(provAddrFlag) {
		c.ProvAddr = *provAddr
	}
	if internal.FlagPassed(metadataFlag) {
		c.Metadata = strings.Split(*metadata, ",")
	}
	if internal.FlagPassed(driversFlag) {
		c.Drivers = strings.Split(*driversList, ",")
	}
	if internal.FlagPassed(storageFlag) {
		c.Storage = *storage
	}
	if internal.FlagPassed(cacheFlag) {
		c.Cache = *cache
	}
	if internal.FlagPassed(measurementLogFlag) {
		c.MeasurementLog = *measurementLog
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

	intervalDuration, err := time.ParseDuration(c.IntervalStr)
	if err != nil {
		log.Fatalf("Failed to parse monitoring interval: %v", err)
	}
	c.interval = intervalDuration

	// Configure the logger
	l, ok := logLevels[strings.ToLower(c.LogLevel)]
	if !ok {
		flag.Usage()
		log.Fatalf("LogLevel %v does not exist", c.LogLevel)
	}
	logrus.SetLevel(l)

	// Convert all paths to absolute paths
	pathsToAbs(c)

	// Print the parsed configuration
	printConfig(c)

	// Get root CA certificate in PEM format if specified
	if c.Mode != "generate" && c.Mode != "cacerts" {
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

	// Get API
	c.api, ok = apis[strings.ToLower(c.Api)]
	if !ok {
		flag.Usage()
		log.Fatalf("API %v is not implemented\n", c.Api)
	}

	return c
}

func pathsToAbs(c *config) {
	var err error
	if c.CmcAddr != "" && strings.EqualFold(c.Api, "socket") && strings.EqualFold(c.Network, "unix") {
		c.CmcAddr, err = filepath.Abs(c.CmcAddr)
		if err != nil {
			log.Warnf("Failed to get absolute path for %v: %v", c.CmcAddr, err)
		}
	}

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
}

func printConfig(c *config) {
	wd, err := os.Getwd()
	if err != nil {
		log.Warnf("Failed to get working directory: %v", err)
	}
	log.Infof("Running testtool from working directory %v", wd)

	log.Debugf("Using the following configuration:")
	log.Debugf("\tMode		 : %v", c.Mode)
	log.Debugf("\tAddr        	 : %v", c.Addr)
	log.Debugf("\tInterval    	 : %v", c.interval)
	log.Debugf("\tCmcAddr     	 : %v", c.CmcAddr)
	log.Debugf("\tReportFile  	 : %v", c.ReportFile)
	log.Debugf("\tResultFile  	 : %v", c.ResultFile)
	log.Debugf("\tNonceFile   	 : %v", c.NonceFile)
	log.Debugf("\tCaFile      	 : %v", c.CaFile)
	log.Debugf("\tMtls        	 : %v", c.Mtls)
	log.Debugf("\tAttest      	 : %v", c.Attest)
	log.Debugf("\tEvent Information  : %v", c.MeasurementLog)
	if c.PoliciesFile != "" {
		log.Debugf("\tPoliciesFile : %v", c.PoliciesFile)
	}
	if strings.EqualFold(c.Api, "socket") {
		log.Debugf("\tApi (Network): %v (%v)", c.Api, c.Network)
	} else {
		log.Debugf("\tApi          : %v", c.Api)
	}
	log.Debugf("\tLogLevel     : %v", c.LogLevel)
}
