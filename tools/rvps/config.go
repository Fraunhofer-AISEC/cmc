// Copyright (c) 2026 Fraunhofer AISEC
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

	log "github.com/sirupsen/logrus"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/internal/config"
	"github.com/Fraunhofer-AISEC/cmc/internal/config/sections"
)

type httpConfig struct {
	Address    string   `toml:"address"      flag:"addr"         default:"localhost:8081" usage:"HTTPS listen address"`
	TlsKey     string   `toml:"tls_key"      flag:"tls-key"      default:"{data}/tls-key.pem" path:"true" usage:"TLS key for the RVPS HTTPS server"`
	TlsCaChain []string `toml:"tls_ca_chain" flag:"tls-ca-chain" default:"{data}/tls-chain.pem" path:"true" usage:"comma-separated paths to TLS certificate chain for the RVPS HTTPS server"`
}

// Validate requires the TLS key and certificate chain, as there is no plain HTTP mode
func (h *httpConfig) Validate(r *config.Report) {
	if h.TlsKey == "" {
		r.Missing("tls_key", "tls-key")
	}
	if len(h.TlsCaChain) == 0 {
		r.Missing("tls_ca_chain", "tls-ca-chain")
	}
}

type trustConfig struct {
	RootCas []string `toml:"root_cas" flag:"root-cas" default:"{data}/ca.pem" path:"true" usage:"comma-separated paths to trusted metadata root CA certificates (PEM or DER). All certificates of all files are trusted individually, they do not have to form a chain"`
}

// Validate requires the metadata CAs, as metadata is never stored unverified
func (t *trustConfig) Validate(r *config.Report) {
	if len(t.RootCas) == 0 {
		r.Missing("root_cas", "root-cas")
	}
}

type storageConfig struct {
	Db    string `toml:"db"    flag:"db"    default:"{data}/rvps.db" path:"true" usage:"SQLite3 index database path, contents are considered trusted"`
	Blobs string `toml:"blobs" flag:"blobs" default:"{data}/blobs"   path:"true" usage:"directory of the metadata blob store, contents are considered trusted"`
}

// Validate requires both stores, as there is no mode of operation without them
func (s *storageConfig) Validate(r *config.Report) {
	if s.Db == "" {
		r.Missing("db", "db")
	}
	if s.Blobs == "" {
		r.Missing("blobs", "blobs")
	}
}

type Config struct {
	Log     sections.Log  `toml:"log"`
	Http    httpConfig    `toml:"http" category:"HTTP"`
	Trust   trustConfig   `toml:"trust"`
	Storage storageConfig `toml:"storage"`

	// Values derived from the configuration above by resolve
	metadataCas []*x509.Certificate
	tlsKey      crypto.PrivateKey
	tlsCaChain  []*x509.Certificate
}

// resolve loads the keys and certificates the validated configuration points to.
// Unlike loading and validating, this touches the file system.
func (c *Config) resolve() error {

	var err error

	// Every certificate of every file is loaded as an individual trust anchor
	c.metadataCas, err = internal.ReadCerts(c.Trust.RootCas)
	if err != nil {
		return fmt.Errorf("trust.root_cas: failed to load metadata root CAs: %w", err)
	}
	for _, ca := range c.metadataCas {
		log.Infof("Trusting metadata CA %v", ca.Subject)
	}

	c.tlsKey, err = internal.LoadPrivateKey(c.Http.TlsKey)
	if err != nil {
		return fmt.Errorf("http.tls_key: failed to load TLS key: %w", err)
	}

	c.tlsCaChain, err = internal.ReadCerts(c.Http.TlsCaChain)
	if err != nil {
		return fmt.Errorf("http.tls_ca_chain: failed to load TLS certificate chain: %w", err)
	}

	return nil
}
