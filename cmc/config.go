// Copyright (c) 2021 -2024 Fraunhofer AISEC
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

package cmc

import (
	"path/filepath"
	"strings"
)

// Subfolders of the storage folder
const (
	metadataCacheDir = "metadata-cache"
	peerCacheDir     = "peer-cache"
	vendorCacheDir   = "vendor-cache"
)

type Config struct {
	// Cmc is the CMC API and the address it is served on or connected to, in the form
	// <api>://<address>, e.g. socket:///run/cmc/cmc.sock or grpc://127.0.0.1:9955
	Cmc            string   `json:"cmc,omitempty"`
	ProvisionToken string   `json:"provisionToken,omitempty"`
	ProvisionAuth  []string `json:"provisionAuth,omitempty"`
	// Endorsement is the mode used to fetch driver certificates and collateral, optionally
	// followed by the address of the endorsement server, e.g. est:https://localhost:9000
	Endorsement string `json:"endorsement,omitempty"`
	// Enrollment is the mode used to enroll certificates, optionally followed by the address
	// of the enrollment server, e.g. est:https://localhost:9000, or self for self-signed
	// certificates
	Enrollment       string   `json:"enrollment,omitempty"`
	MetadataLocation []string `json:"metadata,omitempty"`
	Drivers          []string `json:"drivers,omitempty"`
	ExcludePcrs      []int    `json:"excludePcrs,omitempty"`
	HashAlg          string   `json:"hashAlg,omitempty"`
	PolicyEngine     string   `json:"policyEngine,omitempty"`
	PolicyOverwrite  bool     `json:"policyOverwrite,omitempty"`
	// Storage is the folder for all data the CMC persists, including the caches
	Storage         string `json:"storage,omitempty"`
	MeasurementLogs bool   `json:"measurementLogs,omitempty"`
	// CtrDriver is the driver used to measure containers. An empty value disables container
	// measurements
	CtrDriver        string   `json:"ctrDriver,omitempty"`
	CtrLog           string   `json:"ctrLog,omitempty"`
	RootCas          []string `json:"rootCas,omitempty"`
	AllowSystemCerts bool     `json:"allowSystemCerts"`
	Vmpl             int      `json:"vmpl,omitempty"`
	TpmKeyAlg        string   `json:"tpmKeyAlg,omitempty"`
	UseOmsp          bool     `json:"useOmsp,omitempty"`
	OmspFormat       string   `json:"omspFormat,omitempty"`
	AppendEbsEvent   bool     `json:"appendEbsEvent,omitempty"`
}

// MetadataCacheDir is the folder metadata is cached in for offline backup
func (c *Config) MetadataCacheDir() string { return c.cacheDir(metadataCacheDir) }

// PeerCacheDir is the folder peer metadata is cached in to reduce attestation report size
func (c *Config) PeerCacheDir() string { return c.cacheDir(peerCacheDir) }

// VendorCacheDir is the folder hardware vendor collateral (SNP VCEK/CA, TDX/SGX collateral)
// is cached in
func (c *Config) VendorCacheDir() string { return c.cacheDir(vendorCacheDir) }

// cacheDir returns a cache subfolder of the storage folder, or an empty string if no
// storage folder is configured, which disables caching
func (c *Config) cacheDir(name string) string {
	if c.Storage == "" {
		return ""
	}
	return filepath.Join(c.Storage, name)
}

func (c *Config) Print() {

	log.Debugf("Using the following cmc configuration:")
	log.Debugf("\tCMC API endpoint               : %v", c.Cmc)
	log.Debugf("\tProvision authentication       : %v", strings.Join(c.ProvisionAuth, ","))
	if c.ProvisionToken != "" {
		log.Debugf("\tProvisioning token             : %v", c.ProvisionToken)
	}
	log.Debugf("\tEndorsement                    : %v", c.Endorsement)
	log.Debugf("\tEnrollment                     : %v", c.Enrollment)
	log.Debugf("\tMetadata locations             : %v", strings.Join(c.MetadataLocation, ","))
	if len(c.ExcludePcrs) > 0 {
		log.Debugf("\tExclude TPM PCRs               : %v", c.ExcludePcrs)
	}
	if c.AppendEbsEvent {
		log.Debugf("\tAppend ExitBootServices events : %v", c.AppendEbsEvent)
	}
	log.Debugf("\tPolicy engine                  : %v", c.PolicyEngine)
	log.Debugf("\tPolicy overwrite enabled       : %v", c.PolicyOverwrite)
	log.Debugf("\tHash algorithm                 : %v", c.HashAlg)
	log.Debugf("\tDrivers                        : %v", strings.Join(c.Drivers, ","))
	log.Debugf("\tMeasurement log                : %v", c.MeasurementLogs)
	if c.CtrDriver != "" {
		log.Debugf("\tContainer driver               : %v", c.CtrDriver)
		log.Debugf("\tContainer measurements         : %v", c.CtrLog)
	} else {
		log.Debugf("\tMeasure containers             : false")
	}
	if c.Storage != "" {
		log.Debugf("\tStorage path                   : %v", c.Storage)
	}
	log.Debugf("\tMetadata root CA paths         : %v", strings.Join(c.RootCas, ","))
	log.Debugf("\tAllow system root CAs:         : %v", c.AllowSystemCerts)
	log.Debugf("\tTPM AK key algorithm           : %v", c.TpmKeyAlg)
	log.Debugf("\tSupport manifest revocation    : %v", c.UseOmsp)
	if c.OmspFormat != "" {
		log.Debugf("\tFormat for revocation info     : %v", c.OmspFormat)
	}
}
