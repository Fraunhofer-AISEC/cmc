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
	"slices"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/internal/config"
	"github.com/Fraunhofer-AISEC/cmc/internal/config/sections"
)

type estConfig struct {
	Address      string   `json:"address"      flag:"est-addr"     default:"0.0.0.0:9000" usage:"EST server address to listen for requests"`
	CaKey        string   `json:"caKey"        flag:"est-ca-key"   path:"true" usage:"path to the EST CA key for signing CSRs"`
	CaChain      []string `json:"caChain"      flag:"est-ca-chain" path:"true" usage:"comma-separated paths to EST CA certificate chain"`
	TlsKey       string   `json:"tlsKey"       flag:"tls-key"      path:"true" usage:"TLS key for EST HTTPS server"`
	TlsCaChain   []string `json:"tlsCaChain"   flag:"tls-ca-chain" path:"true" usage:"comma-separated paths to TLS certificate chain for EST HTTPS server"`
	CertValidity string   `json:"certValidity" flag:"cert-validity" usage:"lifetime of enrolled certificates as a Go duration string, e.g. 4320h"`
	Auth         []string `json:"auth"         flag:"auth-methods" default:"attestation" enum:"none,token,certificate,attestation" usage:"client authentication methods, certificate applies to all endpoints of the server"`
	TokenPath    string   `json:"tokenPath"    flag:"token-path"   path:"true" usage:"token store for verifying bootstrap tokens"`
}

type httpConfig struct {
	Folder string `json:"folder" flag:"http-folder" path:"true" usage:"folder to be served via HTTP"`
}

type tpmConfig struct {
	VerifyEkCert bool   `json:"verifyEkCert" flag:"verify-ek-cert" default:"true" usage:"verify TPM EK certificate chains"`
	EkCertDb     string `json:"ekCertDb"     flag:"tpm-ek-cert-db" path:"true" usage:"database for EK cert chain verification"`
}

type intelPcsConfig struct {
	Url     string   `json:"url"     flag:"intel-pcs-url"       usage:"URL of the upstream Intel PCS or PCCS to proxy TDX/SGX collateral from"`
	RootCas []string `json:"rootCas" flag:"intel-pcs-root-cas" path:"true" usage:"comma-separated paths to root CAs of the upstream Intel PCS or PCCS"`
}

type omspConfig struct {
	Folder  string   `json:"folder"  flag:"omsp-folder"   path:"true" usage:"folder with pre-generated revocation status JSON files for SW manifests"`
	Key     string   `json:"key"     flag:"omsp-key"      path:"true" usage:"private key for signing OMSP responses"`
	CaChain []string `json:"caChain" flag:"omsp-ca-chain" path:"true" usage:"comma-separated certificate chain for the OMSP signing key"`
	Url     string   `json:"url"     flag:"omsp-url"      usage:"URL of the OMSP endpoint"`
}

type publishConfig struct {
	Results string `json:"results" flag:"publish-results" usage:"HTTP address to publish attestation results to"`
	Ocsf    string `json:"ocsf"    flag:"publish-ocsf"    usage:"HTTP address to publish OCSF detection findings to"`
	Network string `json:"network" flag:"publish-network" usage:"HTTP address to publish lightweight network events to"`
	File    string `json:"file"    flag:"publish-file"    path:"true" usage:"file to publish attestation reports to"`
	Token   string `json:"token"   flag:"publish-token"   path:"true" usage:"file with the HTTP authorization token for publishing attestation results"`
	Cert    string `json:"cert"    flag:"publish-cert"    path:"true" usage:"client certificate for mTLS authentication when publishing"`
	Key     string `json:"key"     flag:"publish-key"     path:"true" usage:"client key for mTLS authentication when publishing"`
}

type storageConfig struct {
	VendorCache string `json:"vendorCache" flag:"vendor-cache" path:"true" usage:"folder for caching hardware vendor collateral (SNP VCEK/CA, TDX/SGX collateral)"`
}

type Config struct {
	Log      sections.Log   `json:"log"`
	Trust    sections.Trust `json:"trust"`
	Est      estConfig      `json:"est"      category:"EST"`
	Http     httpConfig     `json:"http"`
	Tpm      tpmConfig      `json:"tpm"      category:"TPM"`
	IntelPcs intelPcsConfig `json:"intelPcs" category:"INTEL PCS"`
	Omsp     omspConfig     `json:"omsp"     category:"OMSP"`
	Publish  publishConfig  `json:"publish"`
	Storage  storageConfig  `json:"storage"`

	// Values derived from the configuration above by resolve
	estCaKey        crypto.PrivateKey
	estCaChain      []*x509.Certificate
	tlsKey          crypto.PrivateKey
	tlsCaChain      []*x509.Certificate
	rootCas         []*x509.Certificate
	intelPcsRootCas []*x509.Certificate
	authMethods     internal.AuthMethod
	omspKey         crypto.PrivateKey
	omspCaChain     []*x509.Certificate
	certValidity    time.Duration
}

// Validate checks the rules that span more than one option. It is called by
// config.Load after the checks derived from the struct tags.
func (c *Config) Validate(r *config.Report) {

	if c.Est.CaKey == "" {
		r.Missing("est.caKey", "est-ca-key")
	}
	if len(c.Est.CaChain) == 0 {
		r.Missing("est.caChain", "est-ca-chain")
	}
	if c.Est.TlsKey == "" {
		r.Missing("est.tlsKey", "tls-key")
	}
	if len(c.Est.TlsCaChain) == 0 {
		r.Missing("est.tlsCaChain", "tls-ca-chain")
	}

	if c.Est.CertValidity != "" {
		d, err := time.ParseDuration(c.Est.CertValidity)
		switch {
		case err != nil:
			r.Errorf("est.certValidity", "%q is not a duration, e.g. 4320h", c.Est.CertValidity)
		case d <= 0:
			r.Errorf("est.certValidity", "must be positive, got %v", d)
		}
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
		{"omsp.caChain", len(c.Omsp.CaChain) > 0},
	}
	if slices.ContainsFunc(omsp, func(o option) bool { return o.set }) {
		for _, o := range omsp {
			if !o.set {
				r.Errorf(o.path, "incomplete OMSP configuration: omsp.url, omsp.key, omsp.folder "+
					"and omsp.caChain must all be set to enable OMSP")
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
		return fmt.Errorf("failed to load private key: %w", err)
	}

	c.estCaChain, err = internal.ReadCerts(c.Est.CaChain)
	if err != nil {
		return fmt.Errorf("failed to load certificate chain: %w", err)
	}

	c.tlsKey, err = internal.LoadPrivateKey(c.Est.TlsKey)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	c.tlsCaChain, err = internal.ReadCerts(c.Est.TlsCaChain)
	if err != nil {
		return fmt.Errorf("failed to load certificate chain: %w", err)
	}

	c.rootCas, err = internal.ReadCerts(c.Trust.RootCas)
	if err != nil {
		return fmt.Errorf("failed to load trusted metadata CAs: %w", err)
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

	c.authMethods, err = internal.ParseAuthMethods(c.Est.Auth)
	if err != nil {
		return fmt.Errorf("failed to parse authentication methods: %w", err)
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

	if c.Est.CertValidity != "" {
		c.certValidity, err = time.ParseDuration(c.Est.CertValidity)
		if err != nil {
			return fmt.Errorf("failed to parse certValidity %q: %w", c.Est.CertValidity, err)
		}
	}

	return nil
}
