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

//go:build linux && cgo && (!nodefaults || nvidia)

package nvidiadriver

import "C"

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/fxamacker/cbor/v2"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

// certCacheFile is the name of the device certificate chain cache within the configured
// CMC storage folder.
const certCacheFile = "nvidia_certs.json"

// architectureHopper is the only GPU architecture this driver supports. It selects
// the signature length and measurement layout in the verifier.
const architectureHopper = "HOPPER"

var log = logrus.WithField("service", "nvidiadriver")

type Nvidia struct {
	*drivers.DriverConfig
	gpuinfos []GPUInfo

	// Cache implementation fields
	mu                sync.RWMutex
	cachedCollaterals []ar.Collateral
	earliestExpiry    time.Time

	// Collateral caches, guarded by collateralMu and initialized in Init, see collateral.go
	collateralMu   sync.RWMutex
	rimsCacheDir   string
	deviceCacheDir string
	driverRims     map[string]string
	vbiosRims      map[string]string
	ocsps          map[string][]string
	certOcsps      map[string]string
}

// GPUInfo holds the queried fields for a single GPU.
type GPUInfo struct {
	Index         uint
	DeviceName    string
	DeviceUUID    string
	DriverVersion string
	VBIOSVersion  string
	certs         string
}

// PersistentCertCache defines the file format structure for saving to disk.
type PersistentCertCache struct {
	Certs map[string]string `json:"certs"` // Maps DeviceUUID -> Raw or Base64 Cert string
}

func (nvidia *Nvidia) Name() string {
	return "Nvidia driver"
}

// Local helpers to load and store certificates between application runs. Without a
// configured storage folder, the certificates are queried from the hardware on every start.
func (nvidia *Nvidia) loadPersistentCerts() map[string]string {
	if nvidia.StoragePath == "" {
		return make(map[string]string)
	}
	data, err := os.ReadFile(filepath.Join(nvidia.StoragePath, certCacheFile))
	if err != nil {
		return make(map[string]string) // Return empty if cache does not exist yet
	}
	var cache PersistentCertCache
	if err := json.Unmarshal(data, &cache); err != nil {
		log.Warnf("Failed to parse persistent cert cache: %v. Starting fresh.", err)
		return make(map[string]string)
	}
	return cache.Certs
}

func (nvidia *Nvidia) savePersistentCerts(certs map[string]string) {
	if nvidia.StoragePath == "" {
		return
	}

	cache := PersistentCertCache{Certs: certs}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		log.Errorf("Failed to marshal cert cache: %v", err)
		return
	}

	file := filepath.Join(nvidia.StoragePath, certCacheFile)
	if err := os.WriteFile(file, data, 0644); err != nil {
		log.Errorf("Failed to write cert cache to %v: %v", file, err)
	}
}

func (nvidia *Nvidia) Init(c *drivers.DriverConfig) error {
	var err error

	if err := nvmlLoad(); err != nil {
		return fmt.Errorf("failed to initialize NVML: %w", err)
	}

	nvidia.DriverConfig = c

	if c.StoragePath != "" {
		if _, err := os.Stat(c.StoragePath); err != nil {
			if err := os.MkdirAll(c.StoragePath, 0755); err != nil {
				return fmt.Errorf("failed to create local storage '%v': %w", c.StoragePath, err)
			}
		}
	}

	if err := nvidia.initCollateralCache(); err != nil {
		return fmt.Errorf("failed to initialize collateral cache: %w", err)
	}

	nvidia.gpuinfos, err = QueryGPUs()
	if err != nil {
		return fmt.Errorf("failed to get initial nvidia gpu information: %w", err)
	}

	diskCache := nvidia.loadPersistentCerts()
	cacheUpdated := false

	for i := range nvidia.gpuinfos {
		uuid := nvidia.gpuinfos[i].DeviceUUID

		if cachedCert, found := diskCache[uuid]; found && cachedCert != "" {
			log.Infof("Found cached hardware certificate for GPU UUID: %s", uuid)
			nvidia.gpuinfos[i].certs = cachedCert
		} else {
			log.Infof("Cache miss. Fetching device certificate directly from hardware for GPU: %s", uuid)

			device, err := GetHandle((int)(nvidia.gpuinfos[i].Index))
			if err != nil {
				return fmt.Errorf("failed to get handle for GPU %d: %w", nvidia.gpuinfos[i].Index, err)
			}

			certs, err := QueryGPUCertificate(device)
			if err != nil {
				return fmt.Errorf("failed fetching GPU certificate: %w", err)
			}

			nvidia.gpuinfos[i].certs = certs
			diskCache[uuid] = certs
			cacheUpdated = true
		}
	}

	if cacheUpdated {
		nvidia.savePersistentCerts(diskCache)
	}

	log.Debugf("GPU infos: %v", nvidia.gpuinfos)

	if err := nvidia.refreshCache(); err != nil {
		log.Errorf("Failed to populate initial collateral cache: %v", err)
		return err
	}

	return nil
}

// refreshCache handles the actual fetching mechanics and calculates the expiration window.
func (nvidia *Nvidia) refreshCache() error {
	collateralRequestSet := make(map[CollateralRequest]struct{})

	for _, gpuinfo := range nvidia.gpuinfos {
		driverArray := [4]string{gpuinfo.DriverVersion}
		vbiosArray := [4]string{gpuinfo.VBIOSVersion}
		deviceArray := [4]string{gpuinfo.DeviceUUID, gpuinfo.certs}

		collateralRequestSet[CollateralRequest{
			Type:       COLLATERAL_TYPE_NVIDIA_RIM_DRIVER,
			Identifier: driverArray,
		}] = struct{}{}

		collateralRequestSet[CollateralRequest{
			Type:       COLLATERAL_TYPE_NVIDIA_RIM_VBIOS,
			Identifier: vbiosArray,
		}] = struct{}{}

		collateralRequestSet[CollateralRequest{
			Type:       COLLATERAL_TYPE_NVIDIA_CERT_OCSP,
			Identifier: deviceArray,
		}] = struct{}{}
	}

	requests := make([]CollateralRequest, 0, len(collateralRequestSet))
	for key := range collateralRequestSet {
		requests = append(requests, key)
	}

	collaterals, err := nvidia.fetchCollateral(requests)
	if err != nil {
		return fmt.Errorf("failed fetching collaterals: %w", err)
	}

	// Calculate the next validation checkpoint based on OCSP expirations
	var earliestExpiry time.Time
	for _, gpuinfo := range nvidia.gpuinfos {
		certs, err := x509.ParseCertificates([]byte(gpuinfo.certs))
		if err != nil {
			continue
		}

		ocsps, err := nvidia.fetchOCSP(certs, true)
		if err != nil {
			continue
		}

		for _, b64Response := range ocsps {
			derBytes, err := base64.StdEncoding.DecodeString(b64Response)
			if err != nil {
				continue
			}
			resp, err := ocsp.ParseResponse(derBytes, nil)
			if err != nil {
				continue
			}
			if !resp.NextUpdate.IsZero() {
				if earliestExpiry.IsZero() || resp.NextUpdate.Before(earliestExpiry) {
					earliestExpiry = resp.NextUpdate
				}
			}
		}
	}

	// Fallback to a default safe duration if no explicit OCSP NextUpdate was resolved
	if earliestExpiry.IsZero() {
		earliestExpiry = time.Now().Add(1 * time.Hour)
	}

	nvidia.cachedCollaterals = collaterals
	nvidia.earliestExpiry = earliestExpiry
	return nil
}

func (nvidia *Nvidia) GetCollateral() ([]ar.Collateral, error) {
	nvidia.mu.Lock()
	defer nvidia.mu.Unlock()

	// Check if cache is empty or if the current time has surpassed the OCSP validity window
	if len(nvidia.cachedCollaterals) == 0 || time.Now().After(nvidia.earliestExpiry) {
		log.Info("Cached Nvidia collaterals are missing or OCSP is no longer valid. Refetching...")
		if err := nvidia.refreshCache(); err != nil {
			return nil, fmt.Errorf("failed to refresh collateral cache: %w", err)
		}
	} else {
		log.Debug("Returning cached Nvidia collaterals")
	}

	return nvidia.cachedCollaterals, nil
}

func (nvidia *Nvidia) GetEvidence(nonce []byte) ([]ar.Evidence, error) {
	log.Debug("Collecting Nvidia evidence")
	log.Debugf("Nvidia gpu infos %v", nvidia.gpuinfos)
	evidences := make([]ar.Evidence, len(nvidia.gpuinfos))

	for deviceIdx, infos := range nvidia.gpuinfos {
		device, err := GetHandle(deviceIdx)
		if err != nil {
			return nil, fmt.Errorf("failed to get handle for GPU %d: %w", deviceIdx, err)
		}
		log.Debugf("Handle %v for gpu %d", device, deviceIdx)
		attReport, err := QueryGPUAttestationReport(device, nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to query attestation report for GPU %d: %w", deviceIdx, err)
		}
		certs := nvidia.gpuinfos[deviceIdx].certs
		var unsignedMeasurements *internal.NvidiaDeviceUnsignedEvidence
		if nvidia.ExtendedChecks {
			m, err := QueryNonAttestationReportMeasurements(device)
			if err != nil {
				return nil, fmt.Errorf("failed to query supplemental measurements for GPU %d: %w",
					deviceIdx, err)
			}
			unsignedMeasurements = &m
		}
		gpuEvidence := internal.NvidiaGPUEvidence{
			// The driver only supports Hopper. NVML reports no architecture field
			// usable here, so this stays a constant until a second architecture is
			// added, at which point it has to be derived and validated at Init
			Architecture:            architectureHopper,
			UUID:                    infos.DeviceUUID,
			SignedAttestationReport: base64.StdEncoding.EncodeToString(attReport),
			Certificates:            base64.StdEncoding.EncodeToString([]byte(certs)),
			UnsignedMeasurements:    unsignedMeasurements,
		}
		encoded, err := cbor.Marshal(gpuEvidence)
		if err != nil {
			return nil, fmt.Errorf("failed to encode evidence for GPU %d: %w", deviceIdx, err)
		}
		evidences[deviceIdx] = ar.Evidence{Type: ar.TYPE_EVIDENCE_NVIDIA, Data: encoded}
	}
	return evidences, nil
}

func (nvidia *Nvidia) UpdateCerts() error {
	return nil
}
