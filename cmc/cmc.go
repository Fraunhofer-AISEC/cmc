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

package cmc

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	drv "github.com/Fraunhofer-AISEC/cmc/drivers"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/keymgr"
	"github.com/Fraunhofer-AISEC/cmc/peercache"
	"github.com/Fraunhofer-AISEC/cmc/provision"
	"github.com/Fraunhofer-AISEC/cmc/provision/estclient"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
)

var (
	log = logrus.WithField("service", "cmc")

	policyEngines = map[string]verifier.PolicyEngineSelect{
		"js":      verifier.PolicyEngineSelect_JS,
		"duktape": verifier.PolicyEngineSelect_DukTape,
	}

	drivers = map[string]drv.Driver{}
)

type Cmc struct {
	PeerCache          *peercache.Cache
	PolicyEngineSelect verifier.PolicyEngineSelect
	PolicyOverwrite    bool
	Drivers            []drv.Driver
	HashAlg            crypto.Hash
	KeyMgr             *keymgr.KeyMgr
	RootCas            []*x509.Certificate
	OmspHashes         []string //stores keys for retrieving OmspResponses from metadata map
	OmspSerializer     ar.Serializer
	*Config

	metadata      map[string][]byte
	metadataMutex sync.RWMutex
}

func (cmc *Cmc) GetMetadata() map[string][]byte {
	cmc.metadataMutex.RLock()
	defer cmc.metadataMutex.RUnlock()

	copy := make(map[string][]byte, len(cmc.metadata))
	for k, v := range cmc.metadata {
		copy[k] = v
	}
	return copy
}

func (cmc *Cmc) UpdateMetadata(metadata map[string][]byte) {
	cmc.metadataMutex.Lock()
	defer cmc.metadataMutex.Unlock()
	cmc.metadata = metadata
}

func GetDrivers() map[string]drv.Driver {
	return drivers
}

func GetPolicyEngines() map[string]verifier.PolicyEngineSelect {
	return policyEngines
}

func NewCmc(c *Config) (*Cmc, error) {

	// Read trusted root CAs
	rootCas, err := internal.ReadCerts(c.RootCas)
	if err != nil {
		return nil, fmt.Errorf("failed to read trusted root CA certificates: %w", err)
	}

	alg, err := internal.HashFromString(c.HashAlg)
	if err != nil {
		return nil, fmt.Errorf("configured hash alg %q is unsupported: %w", c.HashAlg, err)
	}

	cmc := &Cmc{
		HashAlg: alg,
		RootCas: rootCas,
		Config:  c,
	}

	// Read metadata from the file system
	metadata, err := GetMetadata(c.MetadataLocation, c.Cache, rootCas, c.AllowSystemCerts, cmc.HashAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata: %v", err)
	}

	// Request and cache revocation status of all used manifests (if CMC is configured to use OMSP)
	if cmc.UseOmsp {
		switch c.OmspFormat {
		case "json":
			cmc.OmspSerializer, err = ar.NewJsonSerializer()
			if err != nil {
				return nil, fmt.Errorf("failed to generate JSON serializer: %v", err)
			}
		case "cbor":
			cmc.OmspSerializer, err = ar.NewCborSerializer()
			if err != nil {
				return nil, fmt.Errorf("failed to generate CBOR serializer: %v", err)
			}
		default:
			return nil, fmt.Errorf("OMSP serializer type %v not supported", c.OmspFormat)
		}
		metadata, cmc.OmspHashes, err = AddOmspToMetadata(metadata, cmc.OmspSerializer, cmc.RootCas, alg)
		if err != nil {
			return nil, fmt.Errorf("failed to get omsp responses: %v", err)
		}
	}

	cmc.UpdateMetadata(metadata)

	// Create endorser, which is used to fetch vendor certificate chains,
	// such as the AMD SNP VCEK or Intel TDX PCK chain
	endorser, err := createEndorser(c, rootCas)
	if err != nil {
		return nil, fmt.Errorf("failed to create endorser: %w", err)
	}

	// Create driver configuration
	driverConf := &drv.DriverConfig{
		HashAlg:         alg,
		KeyAlg:          c.TpmKeyAlg,
		ExcludePcrs:     c.ExcludePcrs,
		MeasurementLogs: c.MeasurementLogs,
		CtrLog:          c.CtrLog,
		CtrDriver:       c.CtrDriver,
		Ctr:             c.Ctr,
		Vmpl:            c.Vmpl,
		Endorsers:       endorser,
		StoragePath:     c.Storage,
	}

	// Initialize drivers
	usedDrivers := make([]drv.Driver, 0)
	for _, driver := range c.Drivers {
		d, ok := drivers[strings.ToLower(driver)]
		if !ok {
			return nil, fmt.Errorf("driver %v not implemented", driver)
		}

		err = d.Init(driverConf)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize driver: %w", err)
		}
		usedDrivers = append(usedDrivers, d)
	}
	cmc.Drivers = usedDrivers

	// Check container driver
	if c.Ctr {
		if !internal.Contains(c.CtrDriver, c.Drivers) {
			return nil, fmt.Errorf("cannot use %v as container driver: driver not configured",
				c.CtrDriver)
		}
	}

	// Create provisioner for key manager, which is used to enroll certificates for created keys,
	// e.g. via EST or ACME protocol
	provisioner, err := createEnroller(c, rootCas)
	if err != nil {
		return nil, fmt.Errorf("failed to create enroller: %w", err)
	}

	// Create key manager
	keyMgr, err := keymgr.NewKeyMgr(path.Join(c.Storage, "tls_key_store"), cmc.Drivers, provisioner)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize key manager: %w", err)
	}
	cmc.KeyMgr = keyMgr

	// Get policy engine and overwrite policies
	sel, ok := policyEngines[strings.ToLower(c.PolicyEngine)]
	if !ok {
		log.Tracef("No optional policy engine selected or %v not implemented", c.PolicyEngine)
	}
	cmc.PolicyEngineSelect = sel
	cmc.PolicyOverwrite = c.PolicyOverwrite

	// Load cached metadata from known peers
	cmc.PeerCache, err = peercache.Load(c.PeerCache)
	if err != nil {
		return nil, fmt.Errorf("failed to load peer cache: %w", err)
	}

	return cmc, nil
}

func createEndorser(c *Config, rootCas []*x509.Certificate) (drv.EndorserProvider, error) {
	var err error

	authMethods, err := internal.ParseAuthMethods(c.ProvisionAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authentication methods: %w", err)
	}

	switch c.EndorsementMode {
	case "est":
		var token []byte
		if authMethods.Has(internal.AuthToken) {
			token, err = os.ReadFile(c.ProvisionToken)
			if err != nil {
				return nil, fmt.Errorf("failed to read token: %v", err)
			}
		}
		estclient, err := estclient.New(c.EndorsementAddr, rootCas, c.AllowSystemCerts, token)
		if err != nil {
			return nil, fmt.Errorf("failed to create EST client: %w", err)
		}
		return estclient, nil
	case "direct":
		return provision.NewDirectProvider(c.SnpCache), nil
	default:
		return nil, fmt.Errorf("unknown endorser type %q", c.EndorsementMode)
	}
}

func createEnroller(c *Config, rootCas []*x509.Certificate) (keymgr.Enroller, error) {
	var err error

	authMethods, err := internal.ParseAuthMethods(c.ProvisionAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authentication methods: %w", err)
	}

	switch c.EnrollmentMode {
	case "est":
		var token []byte
		if authMethods.Has(internal.AuthToken) {
			token, err = os.ReadFile(c.ProvisionToken)
			if err != nil {
				return nil, fmt.Errorf("failed to read token: %v", err)
			}
		}
		estclient, err := estclient.New(c.EnrollmentAddr, rootCas, c.AllowSystemCerts, token)
		if err != nil {
			return nil, fmt.Errorf("failed to create EST client: %w", err)
		}
		return estclient, nil
	case "acme":
		return nil, fmt.Errorf("ACME provisioning not yet implemented")
	default:
		return nil, fmt.Errorf("unknown provisioner %q", c.EnrollmentMode)
	}
}
