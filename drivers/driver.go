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

package drivers

import (
	"crypto"
	"crypto/x509"

	"github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// DriverConfig contains all configuration values required for the different drivers
type DriverConfig struct {
	StoragePath      string
	HashAlg          crypto.Hash
	ExcludePcrs      []int
	MeasurementLogs  bool
	Ctr              bool
	CtrPcr           int
	CtrLog           string
	ExtCtrLog        bool
	CtrDriver        string
	EstTlsCas        []*x509.Certificate
	UseSystemRootCas bool
	Vmpl             int
	Endorsers        EndorserProvider
}

// Driver is an interface representing a driver for a hardware trust anchor,
// capable of providing attestation evidence and signing data. This can be
// e.g. a Trusted Platform Module (TPM), AMD SEV-SNP, or the ARM PSA
// Initial Attestation Service (IAS). The driver must be capable of
// performing measurements, i.e. retrieving attestation evidence, such as
// a TPM Quote or an SNP attestation report, as well as signing data.
// For measurements, the driver must provide handles for attestation keys.
// For signing, the driver provides handles for identity keys.
type Driver interface {
	Init(c *DriverConfig) error
	GetEvidence(nonce []byte) ([]attestationreport.Evidence, error)
	GetCollateral() ([]attestationreport.Collateral, error)
	Name() string
	UpdateCerts() error
}
