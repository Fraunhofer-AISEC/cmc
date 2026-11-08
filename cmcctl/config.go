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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/internal/config"
	"github.com/Fraunhofer-AISEC/cmc/internal/config/sections"
)

const (
	timeoutSec = 10
)

var (
	apis = map[string]Api{}

	serializers = map[string]ar.Serializer{}

	log = logrus.WithField("service", "cmcctl")
)

func init() {
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

// apiConfig configures how cmcctl reaches the CMC.
type apiConfig struct {
	Endpoint      string `json:"endpoint"      flag:"cmc" default:"socket://127.0.0.1:9955" usage:"CMC API in the form <api>://<address>, e.g. socket:///run/cmc/cmc.sock, socket://127.0.0.1:9955, grpc://127.0.0.1:9955, or libapi"`
	Serialization string `json:"serialization" flag:"serialization" default:"cbor" enum:"json,cbor" usage:"serialization for requests and attestation reports"`
}

// atlsConfig configures the attested TLS connection.
type atlsConfig struct {
	Addr                 string `json:"addr"   flag:"addr"   usage:"address to connect to / listen on via attested TLS / HTTPS"`
	Mtls                 bool   `json:"mtls"   flag:"mtls"   usage:"perform mutual TLS"`
	Attest               string `json:"attest" flag:"attest" default:"mutual" enum:"mutual,client,server,none" usage:"remote attestation mode"`
	AttestationOnlyTrust bool   `json:"attestationOnlyTrust" flag:"attestation-only-trust" usage:"establish trust in the peer through its attestation report only, without validating its TLS certificate chain, e.g. if the peer uses a self-signed certificate. Requires the peer to be attested"`
}

// httpsConfig configures attested HTTPS requests.
type httpsConfig struct {
	Method string   `json:"method" flag:"method" default:"GET" enum:"GET,POST,PUT,HEAD" usage:"HTTP request method"`
	Header []string `json:"header" flag:"header" usage:"comma-separated headers for HTTP requests"`
	Data   string   `json:"data"   flag:"data"   usage:"aTLS payload for dial or HTTP body for POST/PUT requests"`
}

// identityConfig confgures cmcctl's TLS identity.
type identityConfig struct {
	KeyId       string   `json:"keyId"       flag:"key-id"     path:"true" usage:"file to store the key ID of the (hardware-backed) TLS key"`
	KeyType     string   `json:"keyType"     flag:"key-type"   enum:"tpm,sw" usage:"CMC key/certificate type"`
	KeyConfig   string   `json:"keyConfig"   flag:"key-config" default:"ec256" enum:"ec256,ec384,ec521,rsa2048,rsa4096" usage:"key configuration"`
	Cn          string   `json:"cn"          flag:"tls-cn"     usage:"common name for the TLS certificate"`
	DnsNames    []string `json:"dnsNames"    flag:"tls-dns-names" usage:"comma-separated DNS SANs for the TLS certificate"`
	IpAddresses []string `json:"ipAddresses" flag:"tls-ip-addresses" usage:"comma-separated IP SANs for the TLS certificate"`
}

// publishConfig configures what cmcctl writes and publishes.
type publishConfig struct {
	Report         string `json:"report"   flag:"report"        path:"true" usage:"output file for the attestation report"`
	Nonce          string `json:"nonce"    flag:"nonce"         path:"true" usage:"output file for the nonce"`
	Result         string `json:"result"   flag:"result"        path:"true" usage:"output file for the attestation result"`
	CaStore        string `json:"caStore"  flag:"ca-store-path" path:"true" usage:"file to store the CA certs retrieved by the provision command"`
	ProvisionToken string `json:"provisionToken" flag:"provision-token-out" path:"true" usage:"file to store the bootstrap token created by the token subcommand or retrieved by the provision subcommand"`
	Policies       string `json:"policies" flag:"policies"      path:"true" usage:"JSON policies file for custom verification"`
	Results        string `json:"results" flag:"publish-results" usage:"HTTP address to publish attestation results to"`
	Ocsf           string `json:"ocsf"    flag:"publish-ocsf"    usage:"HTTP address to publish OCSF detection findings to"`
	Network        string `json:"network" flag:"publish-network" usage:"HTTP address to publish lightweight network events to"`
	Token          string `json:"token"   flag:"publish-token"   path:"true" usage:"file with the token for backend authorization"`
	Cert           string `json:"cert"    flag:"publish-cert"    path:"true" usage:"client certificate for mTLS authentication when publishing"`
	Key            string `json:"key"     flag:"publish-key"     path:"true" usage:"client key for mTLS authentication when publishing"`
}

// tokenConfig configures the creation of EST bootstrap tokens.
type tokenConfig struct {
	Store   string `json:"store"   flag:"token-store"     path:"true" usage:"path to token store for token mode"`
	MaxUses int    `json:"maxUses" flag:"token-max-uses"  usage:"maximum number of times a newly created token may be redeemed (0 = unlimited)"`
	Subject string `json:"subject" flag:"token-subject"   usage:"restrict a newly created token to this subject; leave empty for no restriction"`
}

// kubeprovConfig configures Kubernetes node provisioning over attested TLS.
type kubeprovConfig struct {
	KubeadmPath string `json:"kubeadmPath" flag:"kubeadm-path" default:"kubeadm" usage:"path to kubeadm binary"`
	Count       int    `json:"count"       flag:"count"        usage:"number of workers to serve before exiting (0 = unlimited)"`
	DryRun      bool   `json:"dryRun"      flag:"dry-run"      usage:"print join info without executing kubeadm"`
}

// Config is the cmcctl configuration.
type Config struct {
	Log      sections.Log   `json:"log"`
	Api      apiConfig      `json:"api"`
	Trust    sections.Trust `json:"trust"`
	Atls     atlsConfig     `json:"atls"`
	Request  httpsConfig    `json:"request"`
	Identity identityConfig `json:"identity"`
	Publish  publishConfig  `json:"publish"`
	Token    tokenConfig    `json:"token"`
	Kubeprov kubeprovConfig `json:"kubeprov"`

	// embedded cmc config, only required in libapi mode.
	Cmc cmc.Config `json:"cmc" category:"EMBEDDED CMC"`

	// Values derived from the configuration above by resolve.
	rootCas           []*x509.Certificate
	policies          []byte
	apiName           string
	cmcAddr           string
	api               Api
	serializer        ar.Serializer
	attest            atls.AttestSelect
	publishToken      []byte
	publishClientCert *tls.Certificate
	keyId             string
}

// Validate checks the rules that span more than one option. The sections of
// the embedded CMC check their own rules, which config.Load picks up wherever
// the section is used.
func (c *Config) Validate(r *config.Report) {

	// The set of APIs depends on the build tags, so it cannot be an enum tag
	name, _, err := internal.ParseApiEndpoint(c.Api.Endpoint)
	switch {
	case err != nil:
		r.Errorf("api.endpoint", "%v", err)
	case apis[name] == nil:
		r.Errorf("api.endpoint", "API %q is not implemented, available: %v",
			name, strings.Join(availableApis(), ", "))
	case name == "libapi":
		// Only with an embedded CMC does cmcctl need something to attest with
		// and something to attest against
		if len(c.Cmc.Attestation.Drivers) == 0 {
			r.Missing("cmc.attestation.drivers", "drivers")
		}
		if len(c.Cmc.Metadata.Locations) == 0 {
			r.Missing("cmc.metadata.locations", "metadata")
		}
	}

	if c.Atls.AttestationOnlyTrust && c.Atls.Attest != "server" && c.Atls.Attest != "mutual" {
		r.Errorf("atls.attestationOnlyTrust",
			"requires the peer to be attested, but atls.attest is %q", c.Atls.Attest)
	}
}

// globalFlags are registered on the root command. urfave applies them to
// every subcommand as persistent flags, so they work both before and after
// the subcommand name.
//
// The options of the embedded CMC are always accepted, but only listed in
// --help when a CMC is actually going to run in this process. They would
// otherwise bury the options of the subcommand at hand, and there are more
// of them than of everything else put together.
func globalFlags(libapi bool) []cli.Flag {

	c := &Config{}
	flags := append([]cli.Flag{config.FileFlag()},
		config.Flags(c, &c.Log, &c.Api, &c.Trust)...)

	if libapi {
		return append(flags, config.Flags(c, &c.Cmc)...)
	}
	return append(flags, config.HiddenFlags(c, &c.Cmc)...)
}

// libapiSelected reports whether the CMC is going to run inside this process.
// The command line has to be read before urfave parses it, as a flag must
// know whether to show itself in --help before parsing happens. Only the
// sources that select the API are looked at, and every error is ignored:
// this decides what --help prints, and a real problem with the command line
// or a config file is reported by the regular configuration loading.
func libapiSelected(args []string) bool {

	endpoint := ""
	for _, file := range config.SplitList(argValue(args, config.FileFlagName)) {
		if e := apiEndpointOf(file); e != "" {
			endpoint = e
		}
	}
	if e := argValue(args, "cmc"); e != "" {
		endpoint = e
	}

	name, _, err := internal.ParseApiEndpoint(endpoint)
	return err == nil && name == "libapi"
}

// argValue returns the value of --name or -name, given either as a separate
// argument or after an equals sign.
func argValue(args []string, name string) string {
	for i, a := range args {
		for _, prefix := range []string{"--" + name, "-" + name} {
			if a == prefix && i+1 < len(args) {
				return args[i+1]
			}
			if v, found := strings.CutPrefix(a, prefix+"="); found {
				return v
			}
		}
	}
	return ""
}

// apiEndpointOf reads api.endpoint out of a config file.
func apiEndpointOf(file string) string {

	data, err := os.ReadFile(file)
	if err != nil {
		return ""
	}

	var c struct {
		Api struct {
			Endpoint string `json:"endpoint"`
		} `json:"api"`
	}
	if json.Unmarshal(data, &c) != nil {
		return ""
	}
	return c.Api.Endpoint
}

// flags returns the command line flags of the sections a subcommand uses.
// The global ones are deliberately not repeated here: a local flag of the
// same name shadows the inherited one, which would make it unusable before
// the subcommand name. A fresh set is built per call, as a flag carries the
// state of the command it is parsed for and must not be shared between
// commands.
func flags(pick ...section) []cli.Flag {
	if len(pick) == 0 {
		return nil
	}

	c := &Config{}
	selected := make([]any, 0, len(pick))
	for _, p := range pick {
		selected = append(selected, p(c))
	}

	return config.Flags(c, selected...)
}

// section selects one section of a configuration. Flags are generated from a
// fresh configuration per command, so a subcommand names its sections by
// where they sit in the struct rather than by value.
type section func(*Config) any

var (
	withAtls     section = func(c *Config) any { return &c.Atls }
	withRequest  section = func(c *Config) any { return &c.Request }
	withIdentity section = func(c *Config) any { return &c.Identity }
	withPublish  section = func(c *Config) any { return &c.Publish }
	withToken    section = func(c *Config) any { return &c.Token }
	withKubeprov section = func(c *Config) any { return &c.Kubeprov }

	// allSections is used by the config subcommand, which inspects the whole
	// configuration rather than what one subcommand needs
	allSections = []section{withAtls, withRequest, withIdentity, withPublish, withToken,
		withKubeprov}
)

// loadConfig loads the configuration and everything it points to, as the
// subcommands that actually do something need it.
func loadConfig(cmd *cli.Command) (*Config, error) {

	c, err := config.New[Config](cmd)
	if err != nil {
		return nil, err
	}
	if err := c.Log.Setup(); err != nil {
		return nil, err
	}
	config.LogEffective("cmcctl", c)
	if err := c.resolve(); err != nil {
		return nil, err
	}
	return c, nil
}

// resolve loads the certificates, policies and credentials the validated
// configuration points to. Unlike loading and validating, this touches the
// file system.
func (c *Config) resolve() error {

	var err error

	// The endpoint and the serializer are validated as part of the configuration
	c.apiName, c.cmcAddr, _ = internal.ParseApiEndpoint(c.Api.Endpoint)
	c.api = apis[c.apiName]
	c.serializer = serializers[strings.ToLower(c.Api.Serialization)]

	c.attest, err = atls.ParseAttestMode(c.Atls.Attest)
	if err != nil {
		return fmt.Errorf("failed to get attestation mode: %w", err)
	}

	c.rootCas, err = internal.ReadCerts(c.Trust.RootCas)
	if err != nil {
		return fmt.Errorf("failed to read trusted root CAs: %w", err)
	}

	if c.Publish.Policies != "" {
		log.Debug("Adding specified policies")
		c.policies, err = os.ReadFile(c.Publish.Policies)
		if err != nil {
			return fmt.Errorf("failed to read policies file: %w", err)
		}
	}

	if c.Publish.Token != "" {
		log.Debugf("Retrieving publish token %v", c.Publish.Token)
		token, err := os.ReadFile(c.Publish.Token)
		if err != nil {
			log.Warnf("failed to read publish token: %v", err)
		} else {
			c.publishToken = bytes.TrimSpace(token)
		}
	}

	if c.Publish.Cert != "" && c.Publish.Key != "" {
		log.Debugf("Loading publish client key %v and certificate %v", c.Publish.Key, c.Publish.Cert)
		cert, err := tls.LoadX509KeyPair(c.Publish.Cert, c.Publish.Key)
		if err == nil {
			c.publishClientCert = &cert
		} else {
			log.Warnf("failed to load publish client cert: %v. Will not use client authentication for publishing",
				err)
		}
	}

	// Check if there is an existing key ID file, if not, create its folder
	if c.Identity.KeyId != "" {
		if _, err := os.Stat(c.Identity.KeyId); err == nil {
			data, err := os.ReadFile(c.Identity.KeyId)
			if err != nil {
				return fmt.Errorf("failed to read key ID file: %w", err)
			}
			c.keyId = strings.TrimSpace(string(data))
			log.Tracef("Read TLS key id %q", c.keyId)
		} else {
			if err := os.MkdirAll(filepath.Dir(c.Identity.KeyId), 0755); err != nil {
				return fmt.Errorf("failed to create key id file path: %w", err)
			}
		}
	}

	return nil
}
