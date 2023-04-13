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
	"runtime/debug"
	"strings"

	"encoding/json"
	"flag"

	// local modules

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/snpdriver"
	"github.com/Fraunhofer-AISEC/cmc/swdriver"
	"github.com/Fraunhofer-AISEC/cmc/tpmdriver"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

type config struct {
	Addr           string   `json:"addr"`
	ProvServerAddr string   `json:"provServerAddr"`
	Metadata       []string `json:"metadata"`
	Drivers        []string `json:"drivers"`                // TPM, SNP
	UseIma         bool     `json:"useIma"`                 // TRUE, FALSE
	ImaPcr         int32    `json:"imaPcr"`                 // 10-15
	KeyConfig      string   `json:"keyConfig,omitempty"`    // RSA2048 RSA4096 EC256 EC384 EC521
	Serialization  string   `json:"serialization"`          // JSON, CBOR
	Api            string   `json:"api"`                    // gRPC, CoAP, Socket
	Network        string   `json:"network,omitempty"`      // unix, socket
	PolicyEngine   string   `json:"policyEngine,omitempty"` // JS, DUKTAPE
	LogLevel       string   `json:"logLevel,omitempty"`
	Storage        string   `json:"storage,omitempty"`
	Cache          string   `json:"cache,omitempty"`

	serializer         ar.Serializer
	policyEngineSelect ar.PolicyEngineSelect
	drivers            []ar.Driver
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

	drivers = map[string]ar.Driver{
		"tpm": &tpmdriver.Tpm{},
		"snp": &snpdriver.Snp{},
		"sw":  &swdriver.Sw{},
	}

	log = logrus.WithField("service", "cmcd")
)

const (
	configFlag        = "config"
	metadataFlag      = "metadata"
	cmcAddrFlag       = "cmc"
	provAddrFlag      = "prov"
	driversFlag       = "drivers"
	imaFlag           = "ima"
	imaPcrFlag        = "pcr"
	keyConfigFlag     = "algo"
	serializationFlag = "serializer"
	apiFlag           = "api"
	networkFlag       = "network"
	policyEngineFlag  = "policies"
	logFlag           = "log"
	storageFlag       = "storage"
	cacheFlag         = "cache"
)

func getConfig() (*config, error) {

	//
	// Parse configuration from commandline flags and configuration file if
	// specified. Commandline flags supersede configuration file options
	//

	// Parse given command line flags
	configFile := flag.String(configFlag, "", "configuration file")
	metadata := flag.String(metadataFlag, "", "List of locations with metadata, starting either "+
		"with file:// for local locations or https:// for remote locations (can be mixed)")
	cmcAddr := flag.String(cmcAddrFlag, "", "Address the CMC is serving under")
	provAddr := flag.String(provAddrFlag, "", "Address of the provisioning server")
	driversList := flag.String(driversFlag, "",
		fmt.Sprintf("Drivers (comma separated list). Possible: %v",
			strings.Join(maps.Keys(drivers), ",")))
	ima := flag.Bool(imaFlag, false,
		"Indicates whether to use Integrity Measurement Architecture (IMA)")
	pcr := flag.Int(imaPcrFlag, 0, "IMA PCR")
	keyConfig := flag.String(keyConfigFlag, "", "Key configuration")
	serialization := flag.String(serializationFlag, "",
		fmt.Sprintf("Possible serializers: %v", strings.Join(maps.Keys(serializers), ",")))
	api := flag.String(apiFlag, "", "API")
	network := flag.String(networkFlag, "", "Network for socket API [unix tcp]")
	policyEngine := flag.String(policyEngineFlag, "",
		fmt.Sprintf("Possible policy engines: %v", strings.Join(maps.Keys(policyEngines), ",")))
	logLevel := flag.String(logFlag, "",
		fmt.Sprintf("Possible logging: %v", strings.Join(maps.Keys(logLevels), ",")))
	storage := flag.String(storageFlag, "", "Optional folder to store internal CMC data in")
	cache := flag.String(cacheFlag, "", "Optional folder to cache metadata for offline backup")
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
	}

	// Overwrite config file configuration with given command line arguments
	if internal.FlagPassed(metadataFlag) {
		c.Metadata = strings.Split(*metadata, ",")
	}
	if internal.FlagPassed(cmcAddrFlag) {
		c.Addr = *cmcAddr
	}
	if internal.FlagPassed(provAddrFlag) {
		c.ProvServerAddr = *provAddr
	}
	if internal.FlagPassed(driversFlag) {
		c.Drivers = strings.Split(*driversList, ",")
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
	if internal.FlagPassed(networkFlag) {
		c.Network = *network
	}
	if internal.FlagPassed(policyEngineFlag) {
		c.PolicyEngine = *policyEngine
	}
	if internal.FlagPassed(logFlag) {
		c.LogLevel = *logLevel
	}
	if internal.FlagPassed(storageFlag) {
		c.Storage = *storage
	}
	if internal.FlagPassed(cacheFlag) {
		c.Cache = *cache
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

	// Get drivers
	for _, driver := range c.Drivers {
		d, ok := drivers[strings.ToLower(driver)]
		if !ok {
			return nil,
				fmt.Errorf("measurement interface %v not implemented", c.Drivers)
		}
		c.drivers = append(c.drivers, d)
	}

	return c, nil
}

func printConfig(c *config) {
	log.Debugf("Using the following configuration:")
	log.Debugf("\tCMC Listen Address       : %v", c.Addr)
	log.Debugf("\tProvisioning Server URL  : %v", c.ProvServerAddr)
	log.Debugf("\tMetadata Locations       : %v", strings.Join(c.Metadata, ","))
	log.Debugf("\tUse IMA                  : %v", c.UseIma)
	log.Debugf("\tIMA PCR                  : %v", c.ImaPcr)
	log.Debugf("\tSerialization            : %v", c.Serialization)
	log.Debugf("\tAPI                      : %v", c.Api)
	log.Debugf("\tNetwork                  : %v", c.Network)
	log.Debugf("\tPolicy Engine            : %v", c.PolicyEngine)
	log.Debugf("\tKey Config               : %v", c.KeyConfig)
	log.Debugf("\tLogging Level            : %v", c.LogLevel)
	log.Debugf("\tDrivers                  : %v", strings.Join(c.Drivers, ","))
	if c.Storage != "" {
		log.Debugf("\tInternal storage path    : %v", c.Storage)
	}
	if c.Cache != "" {
		log.Debugf("\tMetadata cache path      : %v", c.Cache)
	}
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
