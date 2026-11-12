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
	"fmt"
	"os"
	"slices"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/internal/config"
	"github.com/Fraunhofer-AISEC/cmc/internal/config/sections"
	"github.com/Fraunhofer-AISEC/cmc/provision/est"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
)

func init() {
	// The available policy engines depend on the build tags of the binary
	config.RegisterEnum("policyengines", verifier.PolicyEngines)
}

type estConfig struct {
	Address      string     `toml:"address"       flag:"est-addr"     default:"0.0.0.0:9000" usage:"EST server address to listen for requests"`
	CaKey        string     `toml:"ca_key"        flag:"est-ca-key"   default:"{data}/ca-key.pem" path:"true" usage:"path to the EST CA key for signing CSRs"`
	CaChain      []string   `toml:"ca_chain"      flag:"est-ca-chain" default:"{data}/ca-chain.pem" path:"true" usage:"comma-separated paths to EST CA certificate chain"`
	TlsKey       string     `toml:"tls_key"       flag:"tls-key"      default:"{data}/tls-key.pem" path:"true" usage:"TLS key for EST HTTPS server"`
	TlsCaChain   []string   `toml:"tls_ca_chain"  flag:"tls-ca-chain" default:"{data}/tls-chain.pem" path:"true" usage:"comma-separated paths to TLS certificate chain for EST HTTPS server"`
	CertValidity string     `toml:"cert_validity" flag:"cert-validity" default:"4320h" usage:"lifetime of enrolled certificates as a Go duration string, e.g. 4320h"`
	TokenPath    string     `toml:"token_path"    flag:"token-path"   default:"{data}/tokens" path:"true" usage:"token store for verifying bootstrap tokens"`
	Auth         authConfig `toml:"auth"`
}

// authConfig holds the client authentication methods per enrollment endpoint. A request is
// served if any of the configured methods succeeds. An empty list disables the endpoint
type authConfig struct {
	SimpleEnroll      []string `toml:"simpleenroll"      flag:"auth-simpleenroll"      default:"token"       enum:"none,token,certificate"             usage:"comma-separated authentication methods for /simpleenroll, empty disables the endpoint"`
	TpmActivateEnroll []string `toml:"tpmactivateenroll" flag:"auth-tpmactivateenroll" default:"token"       enum:"none,token,certificate"             usage:"comma-separated authentication methods for /tpmactivateenroll, empty disables the endpoint"`
	TpmCertifyEnroll  []string `toml:"tpmcertifyenroll"  flag:"auth-tpmcertifyenroll"  default:"attestation" enum:"none,token,certificate,attestation" usage:"comma-separated authentication methods for /tpmcertifyenroll, empty disables the endpoint"`
	AttestEnroll      []string `toml:"attestenroll"      flag:"auth-attestenroll"      default:"attestation" enum:"none,token,certificate,attestation" usage:"comma-separated authentication methods for /attestenroll, empty disables the endpoint"`
}

// endpointAuth is the authentication configuration of a single enrollment endpoint
type endpointAuth struct {
	endpoint string
	key      string
	methods  []string
}

func (a *authConfig) endpoints() []endpointAuth {
	return []endpointAuth{
		{est.EnrollEndpoint, "simpleenroll", a.SimpleEnroll},
		{est.TpmActivateEnrollEndpoint, "tpmactivateenroll", a.TpmActivateEnroll},
		{est.TpmCertifyEnrollEndpoint, "tpmcertifyenroll", a.TpmCertifyEnroll},
		{est.AttestEnrollEndpoint, "attestenroll", a.AttestEnroll},
	}
}

// Validate rejects none combined with other methods, as it would make them meaningless
func (a *authConfig) Validate(r *config.Report) {
	for _, e := range a.endpoints() {
		if len(e.methods) > 1 && slices.Contains(e.methods, "none") {
			r.Errorf(e.key, "none cannot be combined with other methods")
		}
	}
}

// attestationConfig configures the verification of attestation reports of enrollment requests
type attestationConfig struct {
	Policies        string `toml:"policies"         flag:"policies"         path:"true" usage:"JSON policies file for custom verification of attestation reports"`
	PolicyEngine    string `toml:"policy_engine"    flag:"policy-engine"    enum:"@policyengines" usage:"policy engine for the policies file"`
	PolicyOverwrite bool   `toml:"policy_overwrite" flag:"policy-overwrite" usage:"allow the policies to overwrite attestation result properties"`
	AcceptWarn      bool   `toml:"accept_warn"      flag:"accept-warn"      usage:"accept attestation results with status warn"`
}

type httpConfig struct {
	Folder string `toml:"folder" flag:"http-folder" default:"{data}/http" path:"true" usage:"folder to be served via HTTP"`
}

type tpmConfig struct {
	VerifyEkCert bool   `toml:"verify_ek_cert" flag:"verify-ek-cert" default:"true" usage:"verify TPM EK certificate chains"`
	EkCertDb     string `toml:"ek_cert_db"     flag:"tpm-ek-cert-db" default:"{data}/ek-cert-db" path:"true" usage:"database for EK cert chain verification"`
}

type intelPcsConfig struct {
	Url     string   `toml:"url"      flag:"intel-pcs-url"       usage:"URL of the upstream Intel PCS or PCCS to proxy TDX/SGX collateral from"`
	RootCas []string `toml:"root_cas" flag:"intel-pcs-root-cas" path:"true" usage:"comma-separated paths to root CAs of the upstream Intel PCS or PCCS"`
}

type omspConfig struct {
	Folder  string   `toml:"folder"   flag:"omsp-folder"   path:"true" usage:"folder with pre-generated revocation status JSON files for SW manifests"`
	Key     string   `toml:"key"      flag:"omsp-key"      path:"true" usage:"private key for signing OMSP responses"`
	CaChain []string `toml:"ca_chain" flag:"omsp-ca-chain" path:"true" usage:"comma-separated certificate chain for the OMSP signing key"`
	Url     string   `toml:"url"      flag:"omsp-url"      usage:"URL of the OMSP endpoint"`
}

type publishConfig struct {
	Results string `toml:"results" flag:"publish-results" usage:"HTTP address to publish attestation results to"`
	Ocsf    string `toml:"ocsf"    flag:"publish-ocsf"    usage:"HTTP address to publish OCSF detection findings to"`
	Network string `toml:"network" flag:"publish-network" usage:"HTTP address to publish lightweight network events to"`
	File    string `toml:"file"    flag:"publish-file"    path:"true" usage:"file to publish attestation reports to"`
	Token   string `toml:"token"   flag:"publish-token"   path:"true" usage:"file with the HTTP authorization token for publishing attestation results"`
	Cert    string `toml:"cert"    flag:"publish-cert"    path:"true" usage:"client certificate for mTLS authentication when publishing"`
	Key     string `toml:"key"     flag:"publish-key"     path:"true" usage:"client key for mTLS authentication when publishing"`
}

type storageConfig struct {
	VendorCache string `toml:"vendor_cache" flag:"vendor-cache" default:"{data}/vendor-cache" path:"true" usage:"folder for caching hardware vendor collateral (SNP VCEK/CA, TDX/SGX collateral)"`
}

type Config struct {
	Log         sections.Log      `toml:"log"`
	Trust       sections.Trust    `toml:"trust"`
	Est         estConfig         `toml:"est"       category:"EST"`
	Attestation attestationConfig `toml:"attestation"`
	Http        httpConfig        `toml:"http"`
	Tpm         tpmConfig         `toml:"tpm"       category:"TPM"`
	IntelPcs    intelPcsConfig    `toml:"intel_pcs" category:"INTEL PCS"`
	Omsp        omspConfig        `toml:"omsp"      category:"OMSP"`
	Publish     publishConfig     `toml:"publish"`
	Storage     storageConfig     `toml:"storage"`

	// Values derived from the configuration above by resolve
	estCaKey        crypto.PrivateKey
	estCaChain      []*x509.Certificate
	tlsKey          crypto.PrivateKey
	tlsCaChain      []*x509.Certificate
	rootCas         []*x509.Certificate
	intelPcsRootCas []*x509.Certificate
	auth            map[string]internal.AuthMethod
	omspKey         crypto.PrivateKey
	omspCaChain     []*x509.Certificate
	certValidity    time.Duration
	policies        []byte
	policyEngine    verifier.PolicyEngineSelect
}

// Validate checks the rules that span more than one option. It is called by
// config.Load after the checks derived from the struct tags.
func (c *Config) Validate(r *config.Report) {

	d, err := time.ParseDuration(c.Est.CertValidity)
	switch {
	case err != nil:
		r.Errorf("est.cert_validity", "%q is not a duration, e.g. 4320h", c.Est.CertValidity)
	case d <= 0:
		r.Errorf("est.cert_validity", "must be positive, got %v", d)
	}

	if (c.Attestation.Policies == "") != (c.Attestation.PolicyEngine == "") {
		r.Errorf("attestation.policies", "attestation.policies and attestation.policy_engine "+
			"must be set together")
	}

	// OMSP is optional. If any OMSP option is set, require all of them
	type option struct {
		path string
		set  bool
	}
	omsp := []option{
		{"omsp.url", c.Omsp.Url != ""},
		{"omsp.key", c.Omsp.Key != ""},
		{"omsp.folder", c.Omsp.Folder != ""},
		{"omsp.ca_chain", len(c.Omsp.CaChain) > 0},
	}
	if slices.ContainsFunc(omsp, func(o option) bool { return o.set }) {
		for _, o := range omsp {
			if !o.set {
				r.Errorf(o.path, "incomplete OMSP configuration: omsp.url, omsp.key, omsp.folder "+
					"and omsp.ca_chain must all be set to enable OMSP")
			}
		}
	}
}

// resolve loads the keys, certificates and other collateral the validated
// configuration points to. Unlike loading and validating, this touches the
// file system.
func (c *Config) resolve() error {

	var err error

	c.estCaKey, err = internal.LoadPrivateKey(c.Est.CaKey)
	if err != nil {
		return fmt.Errorf("est.ca_key: failed to load EST CA key: %w", err)
	}

	c.estCaChain, err = internal.ReadCerts(c.Est.CaChain)
	if err != nil {
		return fmt.Errorf("est.ca_chain: failed to load EST CA chain: %w", err)
	}

	c.tlsKey, err = internal.LoadPrivateKey(c.Est.TlsKey)
	if err != nil {
		return fmt.Errorf("est.tls_key: failed to load TLS key: %w", err)
	}

	c.tlsCaChain, err = internal.ReadCerts(c.Est.TlsCaChain)
	if err != nil {
		return fmt.Errorf("est.tls_ca_chain: failed to load TLS certificate chain: %w", err)
	}

	c.rootCas, err = internal.ReadCerts(c.Trust.RootCas)
	if err != nil {
		return fmt.Errorf("trust.root_cas: failed to load trusted root CAs: %w", err)
	}

	// The Intel PCS proxy is optional, and so are its root CAs: the Intel PCS
	// itself is a production service under a global CA
	if len(c.IntelPcs.RootCas) > 0 {
		c.intelPcsRootCas, err = internal.ReadCerts(c.IntelPcs.RootCas)
		if err != nil {
			return fmt.Errorf("failed to load Intel PCS root CAs: %w", err)
		}
	}
	if c.IntelPcs.Url == "" {
		log.Info("Intel PCS not configured, TDX/SGX collateral requests will not be served")
	}

	if !c.Tpm.VerifyEkCert {
		log.Warn("UNSAFE: Verification of EK certificate chain turned off via config")
	}

	if err := c.resolveAuth(); err != nil {
		return err
	}

	// Policies are optional, and validated to be configured together with the engine
	if c.Attestation.Policies != "" {
		c.policies, err = os.ReadFile(c.Attestation.Policies)
		if err != nil {
			return fmt.Errorf("attestation.policies: failed to read policies: %w", err)
		}
		c.policyEngine, err = verifier.ParsePolicyEngine(c.Attestation.PolicyEngine)
		if err != nil {
			return fmt.Errorf("attestation.policy_engine: %w", err)
		}
	}
	if c.Attestation.AcceptWarn {
		log.Warn("Accepting attestation results with status warn")
	}

	// OMSP is optional, and validated to be either complete or absent
	if c.Omsp.Url != "" {
		c.omspKey, err = internal.LoadPrivateKey(c.Omsp.Key)
		if err != nil {
			return fmt.Errorf("failed to load private OMSP key: %w", err)
		}
		c.omspCaChain, err = internal.ReadCerts(c.Omsp.CaChain)
		if err != nil {
			return fmt.Errorf("failed to load OMSP certificate chain: %w", err)
		}
	} else {
		log.Info("OMSP not configured, OMSP requests will not be served")
	}

	// Validated as part of the configuration
	c.certValidity, _ = time.ParseDuration(c.Est.CertValidity)

	return nil
}

// resolveAuth parses the authentication methods of the enabled enrollment endpoints
func (c *Config) resolveAuth() error {
	c.auth = map[string]internal.AuthMethod{}
	for _, e := range c.Est.Auth.endpoints() {
		if len(e.methods) == 0 {
			log.Infof("Endpoint %v disabled", e.endpoint)
			continue
		}
		methods, err := internal.ParseAuthMethods(e.methods)
		if err != nil {
			return fmt.Errorf("est.auth.%v: %w", e.key, err)
		}
		if methods.Has(internal.AuthNone) {
			log.Warnf("UNSAFE: Endpoint %v issues certificates without client authentication", e.endpoint)
		} else {
			log.Infof("Endpoint %v requires authentication via %v", e.endpoint, methods)
		}
		c.auth[e.endpoint] = methods
	}
	return nil
}
