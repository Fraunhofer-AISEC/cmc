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
	"path/filepath"
	"runtime/debug"
	"strings"

	"encoding/json"
	"flag"

	// local modules

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

type config struct {
	Addr                  string   `json:"addr"`
	ProvServerAddr        string   `json:"provServerAddr"`
	MetadataAddr          string   `json:"metadataAddr"`
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
	LogLevel              string   `json:"logLevel"`

	serializer         ar.Serializer
	policyEngineSelect ar.PolicyEngineSelect
	configDir          string
}

var (
	logLevels = map[string]logrus.Level{
		"panic": logrus.PanicLevel,
		"fatal": logrus.FatalLevel,
		"error": logrus.ErrorLevel,
		"warn":  logrus.WarnLevel,
		"info":  logrus.InfoLevel,
		"debug": logrus.DebugLevel,
		"trace": logrus.TraceLevel,
	}

	serializers = map[string]ar.Serializer{
		"json": ar.JsonSerializer{},
		"cbor": ar.CborSerializer{},
	}

	policyEngines = map[string]ar.PolicyEngineSelect{
		"js":      ar.PolicyEngineSelect_JS,
		"duktape": ar.PolicyEngineSelect_DukTape,
	}

	log = logrus.WithField("service", "cmcd")
)

const (
	configFlag        = "config"
	metadataAddrFlag  = "metadata"
	cmcAddrFlag       = "cmc"
	provAddrFlag      = "prov"
	localPathFlag     = "storage"
	fetchMetadataFlag = "fetch"
	measurementsFlag  = "measurements"
	signerFlag        = "signer"
	imaFlag           = "ima"
	imaPcrFlag        = "pcr"
	keyConfigFlag     = "algo"
	serializationFlag = "serializer"
	apiFlag           = "api"
	policyEngineFlag  = "policies"
	logFlag           = "log"
)

func getConfig() (*config, error) {
	var err error
	var ok bool

	//
	// Parse configuration from commandline flags and configuration file if
	// specified. Commandline flags supersede configuration file options
	//

	// Parse given command line flags
	configFile := flag.String(configFlag, "", "configuration file")
	metadataAddr := flag.String(metadataAddrFlag, "", "metadata server address")
	cmcAddr := flag.String(cmcAddrFlag, "", "Address the CMC is serving under")
	provAddr := flag.String(provAddrFlag, "", "Address of the provisioning server")
	localPath := flag.String(localPathFlag, "", "Path for CMC internal storage")
	fetchMetadata := flag.Bool(fetchMetadataFlag, false,
		"Indicates whether to fetch metadata")
	measurements := flag.String(measurementsFlag, "",
		"Measurement Interfaces (comma separated list)")
	signer := flag.String(signerFlag, "", "Signing Interface")
	ima := flag.Bool(imaFlag, false,
		"Indicates whether to use Integrity Measurement Architecture (IMA)")
	pcr := flag.Int(imaPcrFlag, 0, "IMA PCR")
	keyConfig := flag.String(keyConfigFlag, "", "Key configuration")
	serialization := flag.String(serializationFlag, "",
		fmt.Sprintf("Possible serializers: %v", maps.Keys(serializers)))
	api := flag.String(apiFlag, "", "API")
	policyEngine := flag.String(policyEngineFlag, "",
		fmt.Sprintf("Possible policy engines: %v", maps.Keys(policyEngines)))
	logLevel := flag.String(logFlag, "",
		fmt.Sprintf("Possible logging: %v", maps.Keys(logLevels)))
	flag.Parse()

	// Create default configuration
	c := &config{
		KeyConfig:     "EC256",
		Serialization: "json",
		Api:           "grpc",
		LogLevel:      "trace",
	}

	// Obtain custom configuration from file if specified
	if internal.FlagPassed(configFlag) {
		log.Infof("Loading config from file %v", *configFile)
		data, err := os.ReadFile(*configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read cmcd config file %v: %v", *configFile, err)
		}
		err = json.Unmarshal(data, c)
		if err != nil {
			return nil, fmt.Errorf("failed to parse cmcd config: %v", err)
		}
		c.configDir = filepath.Dir(*configFile)
	}

	// Overwrite config file configuration with given command line arguments
	if internal.FlagPassed(metadataAddrFlag) {
		c.MetadataAddr = *metadataAddr
	}
	if internal.FlagPassed(cmcAddrFlag) {
		c.Addr = *cmcAddr
	}
	if internal.FlagPassed(provAddrFlag) {
		c.ProvServerAddr = *provAddr
	}
	if internal.FlagPassed(localPathFlag) {
		c.LocalPath = *localPath
	}
	if internal.FlagPassed(fetchMetadataFlag) {
		c.FetchMetadata = *fetchMetadata
	}
	if internal.FlagPassed(measurementsFlag) {
		c.MeasurementInterfaces = strings.Split(*measurements, ",")
	}
	if internal.FlagPassed(signerFlag) {
		c.SigningInterface = *signer
	}
	if internal.FlagPassed(imaFlag) {
		c.UseIma = *ima
	}
	if internal.FlagPassed(imaPcrFlag) {
		c.ImaPcr = int32(*pcr)
	}
	if internal.FlagPassed(keyConfigFlag) {
		c.KeyConfig = *keyConfig
	}
	if internal.FlagPassed(serializationFlag) {
		c.Serialization = *serialization
	}
	if internal.FlagPassed(apiFlag) {
		c.Api = *api
	}
	if internal.FlagPassed(policyEngineFlag) {
		c.PolicyEngine = *policyEngine
	}
	if internal.FlagPassed(logFlag) {
		c.LogLevel = *logLevel
	}

	// Configure the logger
	l, ok := logLevels[strings.ToLower(c.LogLevel)]
	if !ok {
		flag.Usage()
		log.Fatalf("LogLevel %v does not exist", c.LogLevel)
	}
	logrus.SetLevel(l)

	// Print the parsed configuration
	printConfig(c)

	//
	// Perform custom config actions
	//

	// Transform local file path
	c.LocalPath, err = internal.GetFilePath(c.LocalPath, &c.configDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get local storage path: %w", err)
	}

	// Get serializer
	c.serializer, ok = serializers[strings.ToLower(c.Serialization)]
	if !ok {
		return nil, fmt.Errorf("serialization Interface %v not implemented", c.Serialization)
	}

	// Get policy engine
	c.policyEngineSelect, ok = policyEngines[strings.ToLower(c.PolicyEngine)]
	if !ok {
		log.Tracef("No optional policy engine selected or %v not implemented", c.PolicyEngine)
	}

	return c, nil
}

func printConfig(c *config) {
	log.Debugf("Using the following configuration:")
	log.Debugf("\tCMC Listen Address       : %v", c.Addr)
	log.Debugf("\tProvisioning Server URL  : %v", c.ProvServerAddr)
	log.Debugf("\tMetadata Server Address  : %v", c.MetadataAddr)
	log.Debugf("\tLocal Storage Path       : %v", c.LocalPath)
	log.Debugf("\tFetch Metadata           : %v", c.FetchMetadata)
	log.Debugf("\tUse IMA                  : %v", c.UseIma)
	log.Debugf("\tIMA PCR                  : %v", c.ImaPcr)
	log.Debugf("\tSerialization            : %v", c.Serialization)
	log.Debugf("\tAPI                      : %v", c.Api)
	log.Debugf("\tPolicy Engine            : %v", c.PolicyEngine)
	log.Debugf("\tKey Config               : %v", c.KeyConfig)
	log.Debugf("\tLogging Level            : %v", c.LogLevel)
	log.Debug("\tMeasurement Interfaces   : ")
	for i, m := range c.MeasurementInterfaces {
		log.Debugf("\t\t%v: %v", i, m)
	}
	log.Debugf("\tSigning Interface        : %v", c.SigningInterface)
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
