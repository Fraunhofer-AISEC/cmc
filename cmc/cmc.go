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

	"github.com/sirupsen/logrus"

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
	EstTlsCas          []*x509.Certificate
	IdentityCas        []*x509.Certificate
	MetadataCas        []*x509.Certificate
	Metadata           map[string][]byte
	PeerCache          *peercache.Cache
	PolicyEngineSelect verifier.PolicyEngineSelect
	PolicyOverwrite    bool
	Drivers            []drv.Driver
	HashAlg            crypto.Hash
	KeyMgr             *keymgr.KeyMgr
	*Config
}

func GetDrivers() map[string]drv.Driver {
	return drivers
}

func GetPolicyEngines() map[string]verifier.PolicyEngineSelect {
	return policyEngines
}

func NewCmc(c *Config) (*Cmc, error) {

	// Read trusted root CAs for EST server TLS authentication, IKs and metadata
	estTlsCas, err := internal.ReadCerts(c.EstTlsCas)
	if err != nil {
		return nil, fmt.Errorf("failed to read EST TLS CA certificates: %w", err)
	}
	identityCas, err := internal.ReadCerts(c.IdentityCas)
	if err != nil {
		return nil, fmt.Errorf("failed to read trusted identity root CAs: %w", err)
	}
	metadataCas, err := internal.ReadCerts(c.MetadataCas)
	if err != nil {
		return nil, fmt.Errorf("failed to read trusted metadata root CAs: %w", err)
	}

	alg, err := internal.HashFromString(c.HashAlg)
	if err != nil {
		return nil, fmt.Errorf("configured hash alg %q is unsupported: %w", c.HashAlg, err)
	}

	cmc := &Cmc{
		EstTlsCas:   estTlsCas,
		IdentityCas: identityCas,
		MetadataCas: metadataCas,
		HashAlg:     alg,
		Config:      c,
	}

	// Read metadata from the file system
	metadata, err := GetMetadata(c.MetadataLocation, c.Cache, estTlsCas, c.EstTlsSysRoots, cmc.HashAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata: %v", err)
	}
	cmc.Metadata = metadata

	// Create endorser, which is used to fetch vendor certificate chains,
	// such as the AMD SNP VCEK or Intel TDX PCK chain
	endorser, err := createEndorser(c, estTlsCas)
	if err != nil {
		return nil, fmt.Errorf("failed to create endorser: %w", err)
	}

	// Create driver configuration
	driverConf := &drv.DriverConfig{
		HashAlg:          alg,
		ExcludePcrs:      c.ExcludePcrs,
		MeasurementLogs:  c.MeasurementLogs,
		CtrLog:           c.CtrLog,
		CtrDriver:        c.CtrDriver,
		Ctr:              c.Ctr,
		EstTlsCas:        estTlsCas,
		UseSystemRootCas: c.EstTlsSysRoots,
		Vmpl:             c.Vmpl,
		Endorsers:        endorser,
		StoragePath:      c.Storage,
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
	provisioner, err := createEnroller(c, estTlsCas)
	if err != nil {
		return nil, fmt.Errorf("failed to create provioner: %w", err)
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

func createEndorser(c *Config, estTlsCas []*x509.Certificate) (drv.EndorserProvider, error) {
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
		estclient, err := estclient.New(c.EndorsementAddr, estTlsCas, c.EstTlsSysRoots, token)
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

func createEnroller(c *Config, estTlsCas []*x509.Certificate) (keymgr.Enroller, error) {
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
		estclient, err := estclient.New(c.EnrollmentAddr, estTlsCas, c.EstTlsSysRoots, token)
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
