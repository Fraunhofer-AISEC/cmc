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

package cmc

import (
	"path/filepath"
	"slices"

	"golang.org/x/exp/maps"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/internal/config"
)

// Subfolders of the storage folder
const (
	metadataCacheDir = "metadata-cache"
	peerCacheDir     = "peer-cache"
	vendorCacheDir   = "vendor-cache"
)

// autoDriver is the drivers value that selects all drivers whose hardware is
// detected. Software based drivers and drivers that cannot be detected
// reliably (azure, sgx) must be configured explicitly.
const autoDriver = "auto"

func init() {
	// The available drivers and policy engines depend on the build tags of the
	// binary, so the enums behind them are resolved at validation time
	config.RegisterEnum("drivers", func() []string { return append(maps.Keys(drivers), autoDriver) })
	config.RegisterEnum("policyengines", func() []string { return maps.Keys(policyEngines) })
}

// Tpm configures the TPM attestation driver.
type Tpm struct {
	KeyAlg         string `toml:"key_alg"          flag:"tpm-key-alg" default:"ec256" enum:"ec256,rsa2048" usage:"TPM AK key algorithm"`
	ExcludePcrs    []int  `toml:"exclude_pcrs"     flag:"exclude-pcrs" usage:"comma-separated list of TPM PCRs to exclude from the quote"`
	AppendEbsEvent bool   `toml:"append_ebs_event" flag:"append-ebs" usage:"reconstruct the ExitBootServices EV_EFI_ACTION events for PCR 5. Only required for TPM 2.0 with legacy event log format v1, which cannot carry the EFI_TCG2_FINAL_EVENTS_TABLE and therefore never logs those events, making PCR 5 impossible to replay"`
}

// Snp configures the AMD SEV-SNP attestation driver.
type Snp struct {
	Vmpl int `toml:"vmpl" flag:"vmpl" usage:"SNP Virtual Machine Privilege Level (VMPL)"`
}

// Containers configures container measurements, which are disabled if no
// trust anchor is given.
type Containers struct {
	TrustAnchor string `toml:"trust_anchor" flag:"ctr-trust-anchor" enum:"tpm,sw,azure" usage:"trust anchor for container measurements: tpm and azure extend them into a (v)TPM PCR, sw signs them with the sw driver key, empty to not measure containers"`
	Log         string `toml:"log"          flag:"ctr-log"          default:"{run}/container-measurements" path:"true" usage:"container runtime measurements path, only used if a container trust anchor is set"`
}

// Attestation configures what evidence is collected and how it is bound
// together into an attestation report.
type Attestation struct {
	Drivers         []string   `toml:"drivers"          flag:"drivers" default:"auto" enum:"@drivers" usage:"comma-separated list of attestation report drivers, auto selects all detected hardware drivers (tpm, snp, tdx)"`
	HashAlg         string     `toml:"hash_alg"         flag:"hash-alg" default:"sha256" enum:"sha256,sha384,sha512" usage:"hash algorithm for attestation report integrity"`
	MeasurementLogs bool       `toml:"measurement_logs" flag:"measurement-logs" default:"true" usage:"include measured events in measurement and validation report"`
	Tpm             Tpm        `toml:"tpm"`
	Snp             Snp        `toml:"snp"`
	Containers      Containers `toml:"containers"`
}

// Validate checks the rules that span more than one option of the section.
// It is called by config.Load wherever the section is used, after the checks
// derived from the struct tags, and must not touch the file system.
func (a *Attestation) Validate(r *config.Report) {

	// The driver providing the container trust anchor must be configured. Auto
	// can only provide the tpm, whose presence is checked when the CMC starts
	if t := a.Containers.TrustAnchor; t != "" && !slices.Contains(a.Drivers, t) &&
		!(t == "tpm" && slices.Contains(a.Drivers, autoDriver)) {
		r.Errorf("containers.trust_anchor", "%q requires the %v driver in %v %v", t, t,
			r.Path("drivers"), a.Drivers)
	}
}

// Omsp configures the use of revocation information for manifests, which is
// why it is part of the metadata section.
type Omsp struct {
	Enabled bool   `toml:"enabled" flag:"use-omsp"    usage:"use revocation information for manifests"`
	Format  string `toml:"format"  flag:"omsp-format" default:"json" enum:"json,cbor" usage:"serialization format of the revocation information for manifests"`
}

// Metadata configures where manifests and descriptions are loaded from, and
// how their revocation status is obtained.
type Metadata struct {
	Locations []string `toml:"locations" flag:"metadata" path:"uri" usage:"comma-separated list of metadata locations [file:// https:// blob://]"`
	Omsp      Omsp     `toml:"omsp"`
}

// Provisioning configures how driver certificates and collateral are obtained
// (endorsement) and how certificates are enrolled (enrollment).
type Provisioning struct {
	Auth  []string `toml:"auth"  flag:"provision-auth"  default:"attestation" enum:"none,token,certificate,attestation" usage:"provisioning authentication methods"`
	Token string   `toml:"token" flag:"provision-token" default:"{data}/provision-token" path:"true" usage:"bootstrap token for EST client authentication, only read with token authentication"`
	// Endorsement is the mode used to fetch driver certificates and collateral,
	// optionally followed by the address of the endorsement server
	Endorsement string `toml:"endorsement" flag:"endorsement" usage:"endorsement mode for fetching driver certs and collateral, with the server address for the modes that require one [direct host est:<url> cps:<url>]:\n\t\tdirect\n\t\t\tSNP: fetch AMD SNP VCEK/CA directly from AMD KDS (rate-limited: 10s per request)\n\t\t\tTDX: fetch TDX collateral directly from Intel PCS\n\t\t\tTPM: Noop endorser. Requires tdx/snp driver (vtpm acts as secondary trust anchor)\n\t\tcps:<url>\n\t\t\tSNP: Fetch AMD SNP VCEK/CA from custom caching proxy service (CPS)\n\t\t\tTDX: Fetch TDX collateral from Provisioning Certification Caching Service (PCCS)\n\t\t\tTPM: Noop endorser. Requires tdx/snp driver (vtpm acts as secondary trust anchor)\n\t\thost\n\t\t\tSNP: Fetch AMD SNP VCEK/CA from the local hypervisor via SNP_GET_EXT_REPORT\n\t\test:<url>\n\t\t\tTPM: Enroll TPM EK certificate via Enrollment over Secure Transport (EST) server"`
	// Enrollment is the mode used to enroll certificates, optionally followed
	// by the address of the enrollment server, or self for self-signed certificates
	Enrollment string `toml:"enrollment" flag:"enrollment" usage:"enrollment mode, with the address of the enrollment server for the modes that require one [self est:<url>]"`
}

// Validate checks the modes of the endorsement and enrollment options, which
// carry an optional address and can therefore not be an enum tag. An unset
// option is reported by the binary that requires it, as what the embedded CMC
// needs depends on how it is used.
func (p *Provisioning) Validate(r *config.Report) {

	if p.Endorsement != "" {
		mode, addr := internal.ParseModeAddr(p.Endorsement)
		switch mode {
		case "direct", "host":
		case "est", "cps":
			if addr == "" {
				r.Errorf("endorsement",
					"%v endorsement requires an address, e.g. %v:https://localhost:9000", mode, mode)
			}
		default:
			r.Errorf("endorsement",
				"unknown mode %q, expected direct, host, est:<url> or cps:<url>", mode)
		}
	}

	if p.Enrollment != "" {
		mode, addr := internal.ParseModeAddr(p.Enrollment)
		switch mode {
		case "self":
		case "est":
			if addr == "" {
				r.Errorf("enrollment",
					"est enrollment requires an address, e.g. est:https://localhost:9000")
			}
		default:
			r.Errorf("enrollment", "unknown mode %q, expected self or est:<url>", mode)
		}
	}
}

// Policies configures the optional policy engine applied to attestation results.
type Policies struct {
	Engine         string `toml:"engine"          flag:"policy-engine"    enum:"@policyengines" usage:"policy engine for custom verification"`
	AllowOverwrite bool   `toml:"allow_overwrite" flag:"policy-overwrite" usage:"allow attestation policies to overwrite attestation result properties"`
}

// Storage configures the folder the CMC persists data in.
type Storage struct {
	Data string `toml:"data" flag:"storage" default:"{data}" path:"true" usage:"folder for all data the CMC persists, such as keys, the metadata cache, the peer cache and the hardware vendor collateral cache"`
}

// Config is the configuration of an embedded CMC. It is required for embedding the CMC as a libary
// into other tools (libapi).
type Config struct {
	Attestation  Attestation  `toml:"attestation"`
	Metadata     Metadata     `toml:"metadata"`
	Provisioning Provisioning `toml:"provisioning"`
	Policies     Policies     `toml:"policies"`
	Storage      Storage      `toml:"storage"`
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
	if c.Storage.Data == "" {
		return ""
	}
	return filepath.Join(c.Storage.Data, name)
}
