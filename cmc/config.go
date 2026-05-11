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
	"strings"
)

type Config struct {
	CmcAddr          string   `json:"cmcAddr,omitempty"`
	ProvisionToken   string   `json:"provisionToken,omitempty"`
	ProvisionAuth    []string `json:"provisionAuth,omitempty"`
	EndorsementMode  string   `json:"endorsementMode,omitempty"`
	EndorsementAddr  string   `json:"endorsementAddr,omitempty"`
	EnrollmentMode   string   `json:"enrollmentMode,omitempty"`
	EnrollmentAddr   string   `json:"enrollmentAddr,omitempty"`
	MetadataLocation []string `json:"metadata,omitempty"`
	Drivers          []string `json:"drivers,omitempty"`
	ExcludePcrs      []int    `json:"excludePcrs,omitempty"`
	HashAlg          string   `json:"hashAlg,omitempty"`
	Api              string   `json:"api,omitempty"`
	PolicyEngine     string   `json:"policyEngine,omitempty"`
	PolicyOverwrite  bool     `json:"policyOverwrite,omitempty"`
	Storage          string   `json:"storage,omitempty"`
	Cache            string   `json:"cache,omitempty"`
	PeerCache        string   `json:"peerCache,omitempty"`
	MeasurementLogs  bool     `json:"measurementLogs,omitempty"`
	Ctr              bool     `json:"ctr,omitempty"`
	CtrDriver        string   `json:"ctrDriver,omitempty"`
	CtrLog           string   `json:"ctrLog,omitempty"`
	RootCas          []string `json:"rootCas,omitempty"`
	AllowSystemCerts bool     `json:"allowSystemCerts"`
	Vmpl             int      `json:"vmpl,omitempty"`
	SnpCache         string   `json:"snpCache,omitempty"`
	TpmKeyAlg        string   `json:"tpmKeyAlg,omitempty"`
}

func (c *Config) Print() {

	log.Debugf("Using the following cmc configuration:")
	log.Debugf("\tCMC listen address             : %v", c.CmcAddr)
	log.Debugf("\tProvision authentication       : %v", strings.Join(c.ProvisionAuth, ","))
	if c.ProvisionToken != "" {
		log.Debugf("\tProvisioning token             : %v", c.ProvisionToken)
	}
	log.Debugf("\tEndorsement mode               : %v", c.EndorsementMode)
	log.Debugf("\tEndorsement server URL         : %v", c.EndorsementAddr)
	log.Debugf("\tEnrollment mode                : %v", c.EnrollmentMode)
	log.Debugf("\tEnrollment server URL          : %v", c.EnrollmentAddr)
	log.Debugf("\tMetadata locations             : %v", strings.Join(c.MetadataLocation, ","))
	if len(c.ExcludePcrs) > 0 {
		log.Debugf("\tExclude TPM PCRs               : %v", c.ExcludePcrs)
	}
	log.Debugf("\tAPI                            : %v", c.Api)
	log.Debugf("\tPolicy engine                  : %v", c.PolicyEngine)
	log.Debugf("\tPolicy overwrite enabled       : %v", c.PolicyOverwrite)
	log.Debugf("\tHash algorithm                 : %v", c.HashAlg)
	log.Debugf("\tDrivers                        : %v", strings.Join(c.Drivers, ","))
	log.Debugf("\tMeasurement log                : %v", c.MeasurementLogs)
	log.Debugf("\tMeasure containers             : %v", c.Ctr)
	if c.Ctr {
		log.Debugf("\tContainer driver               : %v", c.CtrDriver)
		log.Debugf("\tContainer measurements         : %v", c.CtrLog)
	}
	if c.Storage != "" {
		log.Debugf("\tInternal storage path          : %v", c.Storage)
	}
	if c.Cache != "" {
		log.Debugf("\tMetadata cache path            : %v", c.Cache)
	}
	if c.PeerCache != "" {
		log.Debugf("\tPeer cache path                : %v", c.PeerCache)
	}
	log.Debugf("\tMetadata root CA paths         : %v", strings.Join(c.RootCas, ","))
	log.Debugf("\tAllow system root CAs:         : %v", c.AllowSystemCerts)
	log.Debugf("\tSNP VCEK and CA cache folder   : %v", c.SnpCache)
	log.Debugf("\tTPM AK key algorithm           : %v", c.TpmKeyAlg)

}
