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
	"github.com/Fraunhofer-AISEC/cmc/provision/endorser"
	estenroller "github.com/Fraunhofer-AISEC/cmc/provision/enroller"
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
	LocalRole          string
	Drivers            []drv.Driver
	HashAlg            crypto.Hash
	KeyMgr             *keymgr.KeyMgr
	RootCas            []*x509.Certificate
	AllowSystemCerts   bool
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

// NewCmc creates a CMC from its configuration and the trust anchors of the
// caller. The root CAs are passed in rather than configured here, as a binary
// that runs a CMC needs the same anchors for TLS and has already read them.
func NewCmc(c *Config, rootCas []*x509.Certificate, allowSystemCerts bool) (*Cmc, error) {

	alg, err := internal.HashFromString(c.Attestation.HashAlg)
	if err != nil {
		return nil, fmt.Errorf("configured hash alg %q is unsupported: %w", c.Attestation.HashAlg, err)
	}

	cmc := &Cmc{
		HashAlg:          alg,
		RootCas:          rootCas,
		AllowSystemCerts: allowSystemCerts,
		Config:           c,
	}

	// Read metadata from the file system
	metadata, err := GetMetadata(c.Metadata.Locations, c.MetadataCacheDir(), rootCas, allowSystemCerts, cmc.HashAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata: %v", err)
	}

	// Request and cache revocation status of all used manifests (if CMC is configured to use OMSP)
	if cmc.Metadata.Omsp.Enabled {
		switch c.Metadata.Omsp.Format {
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
			return nil, fmt.Errorf("OMSP serializer type %v not supported", c.Metadata.Omsp.Format)
		}
		metadata, cmc.OmspHashes, err = AddOmspToMetadata(metadata, cmc.OmspSerializer, cmc.RootCas, alg)
		if err != nil {
			return nil, fmt.Errorf("failed to get omsp responses: %v", err)
		}
	}

	cmc.UpdateMetadata(metadata)

	// Create endorser, which is used to fetch vendor certificate chains,
	// such as the AMD SNP VCEK or Intel TDX PCK chain
	endorser, err := createEndorser(c, rootCas, allowSystemCerts)
	if err != nil {
		return nil, fmt.Errorf("failed to create endorser: %w", err)
	}

	// Create driver configuration
	driverConf := &drv.DriverConfig{
		HashAlg:         alg,
		KeyAlg:          c.Attestation.Tpm.KeyAlg,
		ExcludePcrs:     c.Attestation.Tpm.ExcludePcrs,
		MeasurementLogs: c.Attestation.MeasurementLogs,
		CtrLog:          c.Attestation.Containers.Log,
		CtrDriver:       c.Attestation.Containers.Driver,
		Vmpl:            c.Attestation.Snp.Vmpl,
		Endorsers:       endorser,
		StoragePath:     c.Storage.Data,
		AppendEbsEvent:  c.Attestation.Tpm.AppendEbsEvent,
	}

	// Initialize drivers
	usedDrivers := make([]drv.Driver, 0)
	for _, driver := range c.Attestation.Drivers {
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
	if c.Attestation.Containers.Driver != "" {
		if !internal.Contains(c.Attestation.Containers.Driver, c.Attestation.Drivers) {
			return nil, fmt.Errorf("cannot use %v as container driver: driver not configured",
				c.Attestation.Containers.Driver)
		}
	}

	// Create provisioner for key manager, which is used to enroll certificates for created keys,
	// e.g. via EST or ACME protocol. In enrollment mode "self", TLS certificates are self-signed
	// and no enrollment protocol and thus no provisioner is required
	enrollmentMode, _ := internal.ParseModeAddr(c.Provisioning.Enrollment)
	selfSigned := enrollmentMode == "self"
	var provisioner keymgr.Enroller
	if !selfSigned {
		provisioner, err = createEnroller(c, rootCas, allowSystemCerts)
		if err != nil {
			return nil, fmt.Errorf("failed to create enroller: %w", err)
		}
	}

	// Create key manager
	keyMgr, err := keymgr.NewKeyMgr(path.Join(c.Storage.Data, "tls_key_store"), cmc.Drivers, provisioner,
		selfSigned)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize key manager: %w", err)
	}
	cmc.KeyMgr = keyMgr

	// Get policy engine and overwrite policies
	if c.Policies.Engine != "" {
		sel, ok := policyEngines[strings.ToLower(c.Policies.Engine)]
		if !ok {
			return nil, fmt.Errorf("policy engine %v not implemented", c.Policies.Engine)
		}
		cmc.PolicyEngineSelect = sel
		cmc.PolicyOverwrite = c.Policies.AllowOverwrite
	}

	// Extract the local role for optional peer authorization from our own image description
	cmc.LocalRole = deriveLocalRole(metadata)

	// Load cached metadata from known peers
	cmc.PeerCache, err = peercache.Load(c.PeerCacheDir())
	if err != nil {
		return nil, fmt.Errorf("failed to load peer cache: %w", err)
	}

	return cmc, nil
}

// deriveLocalRole extracts the local image description name from the loaded metadata. Returns ""
// if no image description is present
func deriveLocalRole(metadata map[string][]byte) string {
	found := ""
	for _, raw := range metadata {
		s, err := ar.DetectSerialization(raw)
		if err != nil {
			continue
		}
		payload, err := s.GetPayload(raw)
		if err != nil {
			continue
		}
		var m ar.Metadata
		if err := s.Unmarshal(payload, &m); err != nil {
			continue
		}
		if m.Type != ar.TYPE_IMAGE_DESCRIPTION || m.Name == "" {
			continue
		}
		if found != "" && found != m.Name {
			log.Warnf("Multiple local image descriptions present (%q, %q); set localRole explicitly", found, m.Name)
			return ""
		}
		found = m.Name
	}
	return found
}

func createEndorser(c *Config, rootCas []*x509.Certificate, allowSystemCerts bool) (drv.EndorserProvider, error) {
	var err error

	authMethods, err := internal.ParseAuthMethods(c.Provisioning.Auth)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authentication methods: %w", err)
	}

	mode, addr := internal.ParseModeAddr(c.Provisioning.Endorsement)

	switch mode {
	case "est":
		// TPM-only attestation must use EST endorsement mode as credential activation is mandatory
		if addr == "" {
			return nil, fmt.Errorf("est endorsement requires an address (endorsement: est:<url>)")
		}
		var token []byte
		if authMethods.Has(internal.AuthToken) {
			token, err = os.ReadFile(c.Provisioning.Token)
			if err != nil {
				return nil, fmt.Errorf("failed to read token: %v", err)
			}
		}
		endorser, err := endorser.NewEstEndorser(addr, rootCas, allowSystemCerts, token)
		if err != nil {
			return nil, fmt.Errorf("failed to create EST client: %w", err)
		}
		return endorser, nil
	case "direct":
		// Direct endorsement supports TDX (Intel PCS) and SNP (AMD KDS)
		return endorser.NewDirectProvider(c.VendorCacheDir())
	case "cps":
		// CPS endorsement supports TDX (PCCS) and SNP (custom caching proxy service)
		if addr == "" {
			return nil, fmt.Errorf("cps endorsement requires an address (endorsement: cps:<url>)")
		}
		return endorser.NewCpsProvider(c.VendorCacheDir(), addr, rootCas, allowSystemCerts)
	case "host":
		// Host endorsement supports SNP via the SNP_GET_EXT_REPORT API
		return endorser.NewSnpHostEndorser()
	default:
		return nil, fmt.Errorf(
			"unknown endorsement %q: expected direct, host, est:<url> or cps:<url>", c.Provisioning.Endorsement)
	}
}

func createEnroller(c *Config, rootCas []*x509.Certificate, allowSystemCerts bool) (keymgr.Enroller, error) {
	var err error

	authMethods, err := internal.ParseAuthMethods(c.Provisioning.Auth)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authentication methods: %w", err)
	}

	mode, addr := internal.ParseModeAddr(c.Provisioning.Enrollment)

	switch mode {
	case "est":
		if addr == "" {
			return nil, fmt.Errorf("est enrollment requires an address (enrollment: est:<url>)")
		}
		var token []byte
		if authMethods.Has(internal.AuthToken) {
			token, err = os.ReadFile(c.Provisioning.Token)
			if err != nil {
				return nil, fmt.Errorf("failed to read token: %v", err)
			}
		}
		enroller, err := estenroller.New(addr, rootCas, allowSystemCerts, token)
		if err != nil {
			return nil, fmt.Errorf("failed to create EST client: %w", err)
		}
		return enroller, nil
	case "acme":
		return nil, fmt.Errorf("ACME provisioning not yet implemented")
	default:
		return nil, fmt.Errorf("unknown enrollment %q: expected self or est:<url>", c.Provisioning.Enrollment)
	}
}
