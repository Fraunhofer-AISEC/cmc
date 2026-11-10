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
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"slices"
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

// resolveDrivers returns the names of the drivers to use without duplicates.
// The value auto expands to all drivers whose hardware is detected.
func resolveDrivers(names []string) ([]string, error) {
	if len(names) == 0 {
		log.Info("No drivers configured, running as verifier only")
		return nil, nil
	}
	resolved := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.ToLower(name)
		if name == autoDriver {
			detected := detectDrivers()
			log.Infof("Automatically detected drivers: %v", detected)
			for _, d := range detected {
				if !slices.Contains(resolved, d) {
					resolved = append(resolved, d)
				}
			}
			continue
		}
		if _, ok := drivers[name]; !ok {
			return nil, fmt.Errorf("driver %v not implemented", name)
		}
		if !slices.Contains(resolved, name) {
			resolved = append(resolved, name)
		}
	}
	if len(resolved) == 0 {
		return nil, errors.New("no drivers configured or detected")
	}
	return resolved, nil
}

// detectDrivers returns the sorted names of the compiled-in drivers whose
// hardware is present
func detectDrivers() []string {
	detected := make([]string, 0)
	for _, name := range slices.Sorted(maps.Keys(drivers)) {
		if d, ok := drivers[name].(drv.Detector); ok && d.Detect() {
			detected = append(detected, name)
		}
	}
	return detected
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

	// Create driver configuration
	driverConf := &drv.DriverConfig{
		HashAlg:         alg,
		KeyAlg:          c.Attestation.Tpm.KeyAlg,
		ExcludePcrs:     c.Attestation.Tpm.ExcludePcrs,
		MeasurementLogs: c.Attestation.MeasurementLogs,
		CtrLog:          c.Attestation.Containers.Log,
		CtrTrustAnchor:  c.Attestation.Containers.TrustAnchor,
		Vmpl:            c.Attestation.Snp.Vmpl,
		StoragePath:     c.Storage.Data,
		AppendEbsEvent:  c.Attestation.Tpm.AppendEbsEvent,
	}
	if err := addEndorsers(driverConf, c, rootCas, allowSystemCerts); err != nil {
		return nil, err
	}

	// Initialize drivers
	driverNames, err := resolveDrivers(c.Attestation.Drivers)
	if err != nil {
		return nil, err
	}
	if mode, _ := internal.ParseModeAddr(c.Attestation.Tpm.Endorsement); mode == "self" &&
		slices.Contains(driverNames, "tpm") && !slices.ContainsFunc(driverNames, isCcDriver) {
		return nil, fmt.Errorf("tpm endorsement self requires the snp or tdx driver, drivers: %v",
			driverNames)
	}
	usedDrivers := make([]drv.Driver, 0, len(driverNames))
	for _, name := range driverNames {
		err = drivers[name].Init(driverConf)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize %v driver: %w", name, err)
		}
		usedDrivers = append(usedDrivers, drivers[name])
	}
	cmc.Drivers = usedDrivers

	if len(cmc.Drivers) > 0 && len(metadata) == 0 {
		log.Warn("No metadata configured: generated attestation reports carry no reference values " +
			"and fail verification by a CMC")
	}

	// Check container trust anchor
	if t := c.Attestation.Containers.TrustAnchor; t != "" && !slices.Contains(driverNames, t) {
		return nil, fmt.Errorf("container trust anchor %v requires the %v driver", t, t)
	}

	// Create provisioner for key manager, which is used to enroll certificates for created keys,
	// e.g. via EST or ACME protocol. In enrollment mode "self", TLS certificates are self-signed
	// and no enrollment protocol and thus no provisioner is required. Without enrollment, keys
	// cannot be enrolled
	enrollmentMode, _ := internal.ParseModeAddr(c.Provisioning.Enrollment)
	selfSigned := enrollmentMode == "self"
	var provisioner keymgr.Enroller
	if enrollmentMode != "" && !selfSigned {
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

// addEndorsers creates the endorsers of all trust anchors with a configured
// endorsement. They fetch vendor certificate chains and collateral, such as the
// AMD SNP VCEK or the Intel TDX collateral, or enroll the TPM AK
func addEndorsers(d *drv.DriverConfig, c *Config, rootCas []*x509.Certificate, allowSystemCerts bool) error {
	var err error

	if c.Attestation.Tpm.Endorsement != "" {
		d.TpmEndorser, err = createTpmEndorser(c, rootCas, allowSystemCerts)
		if err != nil {
			return fmt.Errorf("failed to create TPM endorser: %w", err)
		}
	}
	if c.Attestation.Snp.Endorsement != "" {
		d.SnpEndorser, err = createSnpEndorser(c, rootCas, allowSystemCerts)
		if err != nil {
			return fmt.Errorf("failed to create SNP endorser: %w", err)
		}
	}
	if c.Attestation.Tdx.Endorsement != "" {
		d.TdxEndorser, err = createTdxEndorser(c, rootCas, allowSystemCerts)
		if err != nil {
			return fmt.Errorf("failed to create TDX endorser: %w", err)
		}
	}
	return nil
}

func createTpmEndorser(c *Config, rootCas []*x509.Certificate, allowSystemCerts bool) (drv.TpmEndorser, error) {

	mode, addr := internal.ParseModeAddr(c.Attestation.Tpm.Endorsement)
	switch mode {
	case "est":
		// Credential activation of the AK against the EST server
		if addr == "" {
			return nil, fmt.Errorf("est endorsement requires an address (est:<url>)")
		}
		authMethods, err := internal.ParseAuthMethods(c.Provisioning.Auth)
		if err != nil {
			return nil, fmt.Errorf("failed to parse authentication methods: %w", err)
		}
		var token []byte
		if authMethods.Has(internal.AuthToken) {
			token, err = os.ReadFile(c.Provisioning.Token)
			if err != nil {
				return nil, fmt.Errorf("failed to read token: %w", err)
			}
		}
		e, err := endorser.NewEstEndorser(addr, rootCas, allowSystemCerts, token)
		if err != nil {
			return nil, err
		}
		return e, nil
	case "self":
		// Self-signed AK of a vTPM bound to the CC trust anchor
		return &endorser.VtpmEndorser{}, nil
	default:
		return nil, fmt.Errorf("unknown endorsement %q: expected est:<url> or self",
			c.Attestation.Tpm.Endorsement)
	}
}

func createSnpEndorser(c *Config, rootCas []*x509.Certificate, allowSystemCerts bool) (drv.SnpEndorser, error) {

	mode, addr := internal.ParseModeAddr(c.Attestation.Snp.Endorsement)
	switch mode {
	case "direct":
		// The AMD KDS is a production service under a global CA, so the
		// system root store is used regardless of the CMC trust pool
		e, err := endorser.NewSnpEndorser(endorser.AmdKdsUrl, c.VendorCacheDir(), nil, true)
		if err != nil {
			return nil, err
		}
		return e, nil
	case "cps":
		if addr == "" {
			return nil, fmt.Errorf("cps endorsement requires an address (cps:<url>)")
		}
		e, err := endorser.NewSnpEndorser(addr, c.VendorCacheDir(), rootCas, allowSystemCerts)
		if err != nil {
			return nil, err
		}
		return e, nil
	case "host":
		e, err := endorser.NewSnpHostEndorser(c.Attestation.Snp.Vmpl)
		if err != nil {
			return nil, err
		}
		return e, nil
	default:
		return nil, fmt.Errorf("unknown endorsement %q: expected direct, host or cps:<url>",
			c.Attestation.Snp.Endorsement)
	}
}

func createTdxEndorser(c *Config, rootCas []*x509.Certificate, allowSystemCerts bool) (drv.TdxEndorser, error) {

	mode, addr := internal.ParseModeAddr(c.Attestation.Tdx.Endorsement)
	switch mode {
	case "direct":
		// The Intel PCS is a production service under a global CA, so the
		// system root store is used regardless of the CMC trust pool
		e, err := endorser.NewTdxEndorser(endorser.PcsUrl, c.VendorCacheDir(), nil, true)
		if err != nil {
			return nil, err
		}
		return e, nil
	case "cps":
		// The root CA CRL is also fetched from the proxy, so that the CVM does
		// not require internet access
		if addr == "" {
			return nil, fmt.Errorf("cps endorsement requires an address (cps:<url>)")
		}
		e, err := endorser.NewTdxEndorser(addr, c.VendorCacheDir(), rootCas, allowSystemCerts,
			endorser.WithProxiedRootCaCrl())
		if err != nil {
			return nil, err
		}
		return e, nil
	default:
		return nil, fmt.Errorf("unknown endorsement %q: expected direct or cps:<url>",
			c.Attestation.Tdx.Endorsement)
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
