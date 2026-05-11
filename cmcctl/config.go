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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/internal/cmcflags"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

var serializers map[string]ar.Serializer

func init() {
	serializers = make(map[string]ar.Serializer)

	jsonSer, err := ar.NewJsonSerializer()
	if err != nil {
		panic(fmt.Sprintf("failed to create JSON serializer: %v", err))
	}
	serializers["json"] = jsonSer

	cborSer, err := ar.NewCborSerializer()
	if err != nil {
		panic(fmt.Sprintf("failed to create CBOR serializer: %v", err))
	}
	serializers["cbor"] = cborSer
}

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

	log = logrus.WithField("service", "cmcctl")
)

type config struct {
	Addr             string   `json:"addr"`
	ReportFile       string   `json:"report"`
	ResultFile       string   `json:"result"`
	NonceFile        string   `json:"nonce"`
	KeyIdFile        string   `json:"keyId"`
	KeyType          string   `json:"keyType"`
	KeyConfig        string   `json:"keyConfig"`
	CaStorePath      string   `json:"caStorePath"`
	Mtls             bool     `json:"mtls"`
	Attest           string   `json:"attest"`
	PoliciesFile     string   `json:"policies"`
	PublishResults   string   `json:"publishResults"`
	PublishOcsf      string   `json:"publishOcsf"`
	PublishNetwork   string   `json:"publishNetwork"`
	Header           []string `json:"header"`
	Method           string   `json:"method"`
	Data             string   `json:"data"`
	Serialization    string   `json:"serialization"`
	LogLevel         string   `json:"logLevel"`
	LogFile          string   `json:"logFile"`
	TokenStore       string   `json:"tokenStore"`
	PublishTokenFile string   `json:"publishToken"`
	PublishCert      string   `json:"publishCert"`
	PublishKey       string   `json:"publishKey"`
	TlsCn            string   `json:"tlsCn"`
	TlsDnsNames      []string `json:"tlsDnsNames"`
	TlsIpAddresses   []string `json:"tlsIpAddresses"`
	cmc.Config

	rootCas           []*x509.Certificate
	policies          []byte
	api               Api
	serializer        ar.Serializer
	attest            atls.AttestSelect
	publishToken      []byte
	publishClientCert *tls.Certificate
	keyId             string
}

const (
	configFlag         = "config"
	addrFlag           = "addr"
	reportFlag         = "report"
	resultFlag         = "result"
	nonceFlag          = "nonce"
	keyidFlag          = "key-id"
	keyTypeFlag        = "key-type"
	keyConfigFlag      = "key-config"
	caStorePathFlag    = "ca-store-path"
	policiesFlag       = "policies"
	mtlsFlag           = "mtls"
	attestFlag         = "attest"
	publishResultsFlag = "publish-results"
	publishOcsfFlag    = "publish-ocsf"
	publishNetworkFlag = "publish-network"
	serializationFlag  = "serialization"
	headerFlag         = "header"
	methodFlag         = "method"
	dataFlag           = "data"
	logLevelFlag       = "log-level"
	logFileFlag        = "log-file"
	tokenStoreFlag     = "token-store"
	publishTokenFlag   = "publish-token"
	publishCertFlag    = "publish-cert"
	publishKeyFlag     = "publish-key"
	tlsCnFlag          = "tls-cn"
	tlsDnsNamesFlag    = "tls-dns-names"
	tlsIpAddressesFlag = "tls-ip-addresses"
)

var flags = append([]cli.Flag{
	&cli.StringFlag{
		Name:  configFlag,
		Usage: "JSON configuration file(s), comma-separated",
	},
	&cli.StringFlag{
		Name:  addrFlag,
		Usage: "address to connect to / listen on via attested TLS / HTTPS",
	},
	&cli.StringFlag{
		Name:  reportFlag,
		Usage: "output file for the attestation report",
	},
	&cli.StringFlag{
		Name:  resultFlag,
		Usage: "output file for the attestation result",
	},
	&cli.StringFlag{
		Name:  nonceFlag,
		Usage: "output file for the nonce",
	},
	&cli.StringFlag{
		Name:  keyidFlag,
		Usage: "file to store the key ID of the (hardware-backed) TLS key",
	},
	&cli.StringFlag{
		Name:  keyTypeFlag,
		Usage: "CMC key/certificate type [tpm, snp, sw]",
	},
	&cli.StringFlag{
		Name:  keyConfigFlag,
		Usage: "key configuration [EC256, EC384, EC512, RSA2048, RSA4096]",
	},
	&cli.StringFlag{
		Name:  caStorePathFlag,
		Usage: "path to store CA certs retrieved with provision command",
	},
	&cli.StringFlag{
		Name:  policiesFlag,
		Usage: "JSON policies file for custom verification",
	},
	&cli.BoolFlag{
		Name:  mtlsFlag,
		Usage: "perform mutual TLS",
	},
	&cli.StringFlag{
		Name:  attestFlag,
		Usage: "remote attestation mode [mutual, client, server, none]",
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
		Name:  serializationFlag,
		Usage: "serialization for requests and attestation reports [json, cbor]",
	},
	&cli.StringFlag{
		Name:  headerFlag,
		Usage: "comma-separated headers for HTTP requests",
	},
	&cli.StringFlag{
		Name:  methodFlag,
		Usage: "HTTP request method (GET, POST, PUT, HEAD)",
	},
	&cli.StringFlag{
		Name:  dataFlag,
		Usage: "aTLS payload for dial or HTTP body for POST/PUT requests",
	},
	&cli.StringFlag{
		Name:  logLevelFlag,
		Usage: fmt.Sprintf("logging level: %v", strings.Join(logLevelKeys(), ",")),
	},
	&cli.StringFlag{
		Name:  logFileFlag,
		Usage: "file to log to instead of stdout/stderr",
	},
	&cli.StringFlag{
		Name:  tokenStoreFlag,
		Usage: "path to token store for token mode",
	},
	&cli.StringFlag{
		Name:  publishTokenFlag,
		Usage: "path to token for backend authorization",
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
		Name:  tlsCnFlag,
		Usage: "common name for TLS certificate created via enroll-key",
	},
	&cli.StringFlag{
		Name:  tlsDnsNamesFlag,
		Usage: "comma-separated DNS SANs for TLS certificate created via enroll-key",
	},
	&cli.StringFlag{
		Name:  tlsIpAddressesFlag,
		Usage: "comma-separated IP SANs for TLS certificate created via enroll-key",
	},
}, cmcflags.Flags...)

func logLevelKeys() []string {
	keys := make([]string, 0, len(logLevels))
	for k := range logLevels {
		keys = append(keys, k)
	}
	return keys
}

func getConfig(cmd *cli.Command) (*config, error) {
	var ok bool

	c := &config{
		Config: cmc.Config{
			Api: "socket",
		},
		Serialization: "cbor",
		Attest:        "mutual",
	}

	if cmd.IsSet(configFlag) {
		files := strings.Split(cmd.String(configFlag), ",")
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

	err := cmcflags.Override(cmd, &c.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to read cmc config: %v", err)
	}

	if cmd.IsSet(addrFlag) {
		c.Addr = cmd.String(addrFlag)
	}
	if cmd.IsSet(reportFlag) {
		c.ReportFile = cmd.String(reportFlag)
	}
	if cmd.IsSet(resultFlag) {
		c.ResultFile = cmd.String(resultFlag)
	}
	if cmd.IsSet(nonceFlag) {
		c.NonceFile = cmd.String(nonceFlag)
	}
	if cmd.IsSet(keyidFlag) {
		c.KeyIdFile = cmd.String(keyidFlag)
	}
	if cmd.IsSet(keyTypeFlag) {
		c.KeyType = cmd.String(keyTypeFlag)
	}
	if cmd.IsSet(keyConfigFlag) {
		c.KeyConfig = cmd.String(keyConfigFlag)
	}
	if cmd.IsSet(caStorePathFlag) {
		c.CaStorePath = cmd.String(caStorePathFlag)
	}
	if cmd.IsSet(policiesFlag) {
		c.PoliciesFile = cmd.String(policiesFlag)
	}
	if cmd.IsSet(mtlsFlag) {
		c.Mtls = cmd.Bool(mtlsFlag)
	}
	if cmd.IsSet(attestFlag) {
		c.Attest = cmd.String(attestFlag)
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
	if cmd.IsSet(serializationFlag) {
		c.Serialization = cmd.String(serializationFlag)
	}
	if cmd.IsSet(headerFlag) {
		c.Header = strings.Split(cmd.String(headerFlag), ",")
	}
	if cmd.IsSet(methodFlag) {
		c.Method = cmd.String(methodFlag)
	}
	if cmd.IsSet(dataFlag) {
		c.Data = cmd.String(dataFlag)
	}
	if cmd.IsSet(logLevelFlag) {
		c.LogLevel = cmd.String(logLevelFlag)
	}
	if cmd.IsSet(logFileFlag) {
		c.LogFile = cmd.String(logFileFlag)
	}
	if cmd.IsSet(tokenStoreFlag) {
		c.TokenStore = cmd.String(tokenStoreFlag)
	}
	if cmd.IsSet(publishTokenFlag) {
		c.PublishTokenFile = cmd.String(publishTokenFlag)
	}
	if cmd.IsSet(publishCertFlag) {
		c.PublishCert = cmd.String(publishCertFlag)
	}
	if cmd.IsSet(publishKeyFlag) {
		c.PublishKey = cmd.String(publishKeyFlag)
	}
	if cmd.IsSet(tlsCnFlag) {
		c.TlsCn = cmd.String(tlsCnFlag)
	}
	if cmd.IsSet(tlsDnsNamesFlag) {
		c.TlsDnsNames = strings.Split(cmd.String(tlsDnsNamesFlag), ",")
	}
	if cmd.IsSet(tlsIpAddressesFlag) {
		c.TlsIpAddresses = strings.Split(cmd.String(tlsIpAddressesFlag), ",")
	}

	// Configure the logger
	if c.LogFile != "" {
		lf, err := filepath.Abs(c.LogFile)
		if err != nil {
			return nil, fmt.Errorf("failed to get logfile path: %v", err)
		}
		file, err := os.OpenFile(lf, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
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

	c.Print()

	// Parse root CAs
	for _, ca := range c.RootCas {
		data, err := os.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate file %v: %v", ca, err)
		}
		cert, err := internal.ParseCert(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate %v: %v", ca, err)
		}
		c.rootCas = append(c.rootCas, cert)
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

	if c.PublishCert != "" && c.PublishKey != "" {
		log.Debugf("Loading publish client key %v and certificate %v", c.PublishKey, c.PublishCert)
		cert, err := tls.LoadX509KeyPair(c.PublishCert, c.PublishKey)
		if err == nil {
			c.publishClientCert = &cert
		} else {
			log.Warnf("failed to load publish client cert: %v. Will not use client authentication for publishing",
				err)
		}
	}

	// Get Serializer
	log.Debugf("Getting serializer %v", c.Serialization)
	c.serializer, ok = serializers[strings.ToLower(c.Serialization)]
	if !ok {
		return nil, fmt.Errorf("serializer %v is not implemented", c.Serialization)
	}

	// Get API
	c.api, ok = apis[strings.ToLower(c.Api)]
	if !ok {
		return nil, fmt.Errorf("API '%v' is not implemented", c.Api)
	}

	// Get attestation mode
	c.attest, err = atls.ParseAttestMode(c.Attest)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation mode: %v", err)
	}

	// Check if there is an existing key ID file, if not, create it
	if c.KeyIdFile != "" {
		if _, err := os.Stat(c.KeyIdFile); err == nil {
			data, err := os.ReadFile(c.KeyIdFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read key ID file: %w", err)
			}
			c.keyId = string(data)
			log.Tracef("Read TLS key id %q", c.keyId)
		} else {
			err := os.MkdirAll(filepath.Dir(c.KeyIdFile), 0755)
			if err != nil {
				return nil, fmt.Errorf("failed to create key id file path: %w", err)
			}
		}
	}

	return c, nil
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
	log.Debugf("\tKey ID File              : %v", c.KeyIdFile)
	log.Debugf("\tKey Tye                  : %v", c.KeyType)
	log.Debugf("\tKey config               : %v", c.KeyConfig)
	log.Debugf("\tTrusted root CA          : %v", strings.Join(c.RootCas, ","))
	log.Debugf("\tProvision CA store path  : %v", c.CaStorePath)
	log.Debugf("\tMtls                     : %v", c.Mtls)
	log.Debugf("\tLogLevel                 : %v", c.LogLevel)
	log.Debugf("\tAttest                   : %v", c.Attest)
	log.Debugf("\tAPI Serializer           : %v", c.Serialization)
	log.Debugf("\tPublish Results          : %v", c.PublishResults)
	log.Debugf("\tPublish OCSF             : %v", c.PublishOcsf)
	log.Debugf("\tPublish Network          : %v", c.PublishNetwork)
	log.Debugf("\tApi                      : %v", c.Api)
	log.Debugf("\tTLS / HTTP Payload       : %v", c.Data)
	log.Debugf("\tHTTP Header              : %v", c.Header)
	log.Debugf("\tHTTP Method              : %v", c.Method)
	log.Debugf("\tToken Store              : %v", c.TokenStore)
	log.Debugf("\tBackend Token            : %v", c.PublishTokenFile)
	log.Debugf("\tTLS Cert Common Name     : %v", c.TlsCn)
	log.Debugf("\tTLS Cert DNS Names       : %v", c.TlsDnsNames)
	log.Debugf("\tTLS Cert IP addresses    : %v", c.TlsIpAddresses)
	if c.PoliciesFile != "" {
		log.Debugf("\tPoliciesFile            : %v", c.PoliciesFile)
	}
	if strings.EqualFold(c.Api, "libapi") {
		c.Config.Print()
	}
}
