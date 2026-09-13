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

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"golang.org/x/crypto/ocsp"
)

// CollateralRequest identifies a single piece of NVIDIA collateral to be fetched.
type CollateralRequest struct {
	Type       string
	Identifier [4]string /* fixed size to make it comparable. You really shouldn't need more */
}

const (
	COLLATERAL_TYPE_NVIDIA_RIM_DRIVER string = "NVIDIA_RIM_DRIVER"
	COLLATERAL_TYPE_NVIDIA_RIM_VBIOS  string = "NVIDIA_RIM_VBIOS"
	COLLATERAL_TYPE_NVIDIA_CERT_OCSP  string = "NVIDIA_CERT_OCSP"
)

// nvidiaCacheDir is the subfolder of the configured vendor cache folder in which the NVIDIA
// collateral is stored, keeping it apart from the collateral of the other vendors.
const nvidiaCacheDir = "nvidia"

type RIMPayload struct {
	ID  string `json:"id"`
	Rim string `json:"rim"`
}

// --- Cache Management Implementation ---

// initCollateralCache initializes the in-memory collateral caches. If a vendor cache folder
// is configured, the collateral already present in it is loaded and newly fetched collateral
// is stored in it. Otherwise, collateral is only cached in memory and therefore refetched on
// every start.
func (nvidia *Nvidia) initCollateralCache() error {
	nvidia.collateralMu.Lock()
	defer nvidia.collateralMu.Unlock()

	nvidia.driverRims = map[string]string{}
	nvidia.vbiosRims = map[string]string{}
	nvidia.ocsps = map[string][]string{}
	nvidia.certOcsps = map[string]string{}

	if nvidia.VendorCache == "" {
		log.Debug("No vendor cache folder configured, caching NVIDIA collateral in memory only")
		return nil
	}

	nvidia.rimsCacheDir = filepath.Join(nvidia.VendorCache, nvidiaCacheDir, "rims")
	nvidia.deviceCacheDir = filepath.Join(nvidia.VendorCache, nvidiaCacheDir, "device")

	for _, dir := range []string{nvidia.rimsCacheDir, nvidia.deviceCacheDir} {
		if _, err := os.Stat(dir); err != nil {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create vendor cache '%v': %w", dir, err)
			}
		}
	}

	nvidia.loadFileCache()

	return nil
}

// writeCacheFile stores a single piece of base64-encoded collateral in the vendor cache.
// Caching is best-effort: a failed write only means that the collateral is fetched again.
func writeCacheFile(dir, file, b64Content string) {
	if dir == "" {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(b64Content)
	if err != nil {
		log.Warnf("Failed to decode collateral %v for caching: %v", file, err)
		return
	}
	p := filepath.Join(dir, file)
	if err := os.WriteFile(p, raw, 0644); err != nil {
		log.Warnf("Failed to cache collateral %v: %v", p, err)
	}
}

// loadFileCache scans the vendor cache directories into the in-memory maps in a single pass.
// The caller must hold the collateral lock.
func (nvidia *Nvidia) loadFileCache() {

	// 1 & 2. Single-pass load RIMs and OCSPs from the rims directory
	if entries, err := os.ReadDir(nvidia.rimsCacheDir); err == nil {
		rimAggregator := make(map[string]map[int]string)

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()

			if strings.HasSuffix(name, ".rim") {
				fullPath := filepath.Join(nvidia.rimsCacheDir, name)
				fileBytes, err := os.ReadFile(fullPath)
				if err != nil {
					continue
				}
				b64Contents := base64.StdEncoding.EncodeToString(fileBytes)

				if strings.HasPrefix(name, "driver_rim_") {
					version := strings.TrimSuffix(strings.TrimPrefix(name, "driver_rim_"), ".rim")
					nvidia.driverRims[version] = b64Contents
				} else if strings.HasPrefix(name, "vbios_rim_") {
					version := strings.TrimSuffix(strings.TrimPrefix(name, "vbios_rim_"), ".rim")
					nvidia.vbiosRims[version] = b64Contents
				}
			} else if strings.HasSuffix(name, ".ocsp") {
				baseName := strings.TrimSuffix(name, ".ocsp")
				idx := strings.LastIndexAny(baseName, "0123456789")
				if idx <= 0 || idx == len(baseName)-1 {
					continue
				}
				startIdx := idx
				for startIdx > 0 && baseName[startIdx-1] >= '0' && baseName[startIdx-1] <= '9' {
					startIdx--
				}

				cacheKey := baseName[:startIdx]
				pos, err := strconv.Atoi(baseName[startIdx:])
				if err != nil {
					continue
				}

				fileBytes, err := os.ReadFile(filepath.Join(nvidia.rimsCacheDir, name))
				if err != nil {
					continue
				}

				if rimAggregator[cacheKey] == nil {
					rimAggregator[cacheKey] = make(map[int]string)
				}
				rimAggregator[cacheKey][pos] = base64.StdEncoding.EncodeToString(fileBytes)
			}
		}

		// Flatten sorted aggregated array indices back to the unified runtime cache map
		for key, indexMap := range rimAggregator {
			responses := make([]string, len(indexMap))
			for i := 0; i < len(indexMap); i++ {
				responses[i] = indexMap[i]
			}
			nvidia.ocsps[key] = responses
		}
	}

	// 3. Load Device Cert OCSPs from the explicit device directory
	if entries, err := os.ReadDir(nvidia.deviceCacheDir); err == nil {
		deviceAggregator := make(map[string]map[int]string)

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".ocsp") {
				continue
			}

			baseName := strings.TrimSuffix(entry.Name(), ".ocsp")
			idx := strings.LastIndexAny(baseName, "0123456789")
			if idx <= 0 || idx == len(baseName)-1 {
				continue
			}
			startIdx := idx
			for startIdx > 0 && baseName[startIdx-1] >= '0' && baseName[startIdx-1] <= '9' {
				startIdx--
			}

			cacheKey := baseName[:startIdx]
			pos, err := strconv.Atoi(baseName[startIdx:])
			if err != nil {
				continue
			}

			fileBytes, err := os.ReadFile(filepath.Join(nvidia.deviceCacheDir, entry.Name()))
			if err != nil {
				continue
			}

			if deviceAggregator[cacheKey] == nil {
				deviceAggregator[cacheKey] = make(map[int]string)
			}
			deviceAggregator[cacheKey][pos] = base64.StdEncoding.EncodeToString(fileBytes)
		}

		for key, indexMap := range deviceAggregator {
			responses := make([]string, len(indexMap))
			for i := 0; i < len(indexMap); i++ {
				responses[i] = indexMap[i]
			}
			nvidia.ocsps[key] = responses
		}
	}
}

// --- Request Processing Pipeline ---

func (nvidia *Nvidia) fetchCollateral(requests []CollateralRequest) ([]ar.Collateral, error) {
	var (
		driverRimsOut = make(map[string]string)
		vbiosRimsOut  = make(map[string]string)
		ocspDeviceOut = make(map[string][]string)
		ocspRimsOut   = make(map[string][]string)

		outMutex sync.Mutex
		wg       sync.WaitGroup
		errChan  = make(chan error, len(requests))
	)

	for _, req := range requests {
		if len(req.Identifier) == 0 {
			continue
		}

		wg.Add(1)
		go func(request CollateralRequest) {
			defer wg.Done()

			switch request.Type {
			case COLLATERAL_TYPE_NVIDIA_RIM_DRIVER:
				version := request.Identifier[0]

				nvidia.collateralMu.RLock()
				b64Rim, exists := nvidia.driverRims[version]
				nvidia.collateralMu.RUnlock()

				if !exists {
					log.Debugf("Cache miss. Fetching online RIM for driver version: %s", version)
					query := "NV_GPU_DRIVER_GH100_" + version
					fetchedRim, err := FetchRIMData(query)
					if err != nil {
						errChan <- fmt.Errorf("failed to fetch driver RIM online: %w", err)
						return
					}

					writeCacheFile(nvidia.rimsCacheDir,
						fmt.Sprintf("driver_rim_%s.rim", version), fetchedRim)

					nvidia.collateralMu.Lock()
					nvidia.driverRims[version] = fetchedRim
					nvidia.collateralMu.Unlock()
					b64Rim = fetchedRim
				}

				outMutex.Lock()
				driverRimsOut[version] = b64Rim
				outMutex.Unlock()

				rimCertOCSPKey := fmt.Sprintf("driver_rim_%s", version)
				nvidia.collateralMu.RLock()
				ocsps, oExists := nvidia.ocsps[rimCertOCSPKey]
				nvidia.collateralMu.RUnlock()

				if !oExists || verifyOCSPRecency(ocsps) != nil {
					log.Debugf("OCSP invalid or missing for driver RIM %s. Fetching fresh values...", version)
					certs, err := extractCertsFromRim(b64Rim)
					if err == nil {
						if freshOcsps, err := nvidia.fetchOCSP(certs, false); err == nil {
							for j, resp := range freshOcsps {
								writeCacheFile(nvidia.rimsCacheDir,
									fmt.Sprintf("driver_rim_%s%d.ocsp", version, j), resp)
							}
							nvidia.collateralMu.Lock()
							nvidia.ocsps[rimCertOCSPKey] = freshOcsps
							nvidia.collateralMu.Unlock()
							ocsps = freshOcsps
						}
					}
				}

				outMutex.Lock()
				ocspRimsOut[rimCertOCSPKey] = ocsps
				outMutex.Unlock()

			case COLLATERAL_TYPE_NVIDIA_RIM_VBIOS:
				version := request.Identifier[0]

				nvidia.collateralMu.RLock()
				b64Rim, exists := nvidia.vbiosRims[version]
				nvidia.collateralMu.RUnlock()

				if !exists {
					log.Debugf("Cache miss. Fetching online RIM for VBIOS version: %s", version)
					query := strings.ReplaceAll(version, ".", "")
					fetchedRim, err := FetchRIMData(query)
					if err != nil {
						errChan <- fmt.Errorf("failed to fetch VBIOS RIM online: %w", err)
						return
					}

					writeCacheFile(nvidia.rimsCacheDir,
						fmt.Sprintf("vbios_rim_%s.rim", version), fetchedRim)

					nvidia.collateralMu.Lock()
					nvidia.vbiosRims[version] = fetchedRim
					nvidia.collateralMu.Unlock()
					b64Rim = fetchedRim
				}

				outMutex.Lock()
				vbiosRimsOut[version] = b64Rim
				outMutex.Unlock()

				rimCertOCSPKey := fmt.Sprintf("vbios_rim_%s", version)
				nvidia.collateralMu.RLock()
				ocsps, oExists := nvidia.ocsps[rimCertOCSPKey]
				nvidia.collateralMu.RUnlock()

				if !oExists || verifyOCSPRecency(ocsps) != nil {
					log.Debugf("OCSP invalid or missing for VBIOS RIM %s. Fetching fresh values...", version)
					certs, err := extractCertsFromRim(b64Rim)
					if err == nil {
						if freshOcsps, err := nvidia.fetchOCSP(certs, false); err == nil {
							for j, resp := range freshOcsps {
								writeCacheFile(nvidia.rimsCacheDir,
									fmt.Sprintf("vbios_rim_%s%d.ocsp", version, j), resp)
							}
							nvidia.collateralMu.Lock()
							nvidia.ocsps[rimCertOCSPKey] = freshOcsps
							nvidia.collateralMu.Unlock()
							ocsps = freshOcsps
						}
					}
				}

				outMutex.Lock()
				ocspRimsOut[rimCertOCSPKey] = ocsps
				outMutex.Unlock()

			case COLLATERAL_TYPE_NVIDIA_CERT_OCSP:
				if len(request.Identifier) < 2 {
					log.Errorf("Malformed device cert OCSP request: missing required UUID or cert chain details")
					return
				}
				uuid := request.Identifier[0]
				rawCertChainToken := request.Identifier[1]
				deviceKey := fmt.Sprintf("device_%s", uuid)

				nvidia.collateralMu.RLock()
				responses, exists := nvidia.ocsps[deviceKey]
				nvidia.collateralMu.RUnlock()

				if !exists || len(responses) != 3 || verifyOCSPRecency(responses) != nil {
					log.Debugf("Cache miss/expiration for %s. Fetching live hardware OCSP...", deviceKey)

					certs, err := internal.ParseCertChain([]byte(rawCertChainToken))
					if err != nil {
						log.Errorf("Failed to parse incoming token certificates for %s: %v", deviceKey, err)
						return
					}
					log.Infof("fetching for deviceKey %s\n", uuid)
					freshResponses, err := nvidia.fetchOCSP(certs, true)
					if err != nil {
						log.Errorf("Failed to retrieve operational live network OCSP responses: %v", err)
						return
					}

					for j, responseString := range freshResponses {
						writeCacheFile(nvidia.deviceCacheDir,
							fmt.Sprintf("device_%s%d.ocsp", uuid, j), responseString)
					}

					nvidia.collateralMu.Lock()
					nvidia.ocsps[deviceKey] = freshResponses
					nvidia.collateralMu.Unlock()
					responses = freshResponses
				}

				outMutex.Lock()
				ocspDeviceOut[deviceKey] = responses
				outMutex.Unlock()
			}
		}(req)
	}

	wg.Wait()
	close(errChan)

	if len(errChan) > 0 {
		return nil, <-errChan
	}

	nvidiaCollateral := ar.NvidiaCollateral{
		OcspResponsesDeviceCerts: ocspDeviceOut,
		DriverRIMs:               driverRimsOut,
		VbiosRIMs:                vbiosRimsOut,
		OcspResponsesRIMCerts:    ocspRimsOut,
	}

	return []ar.Collateral{{
		Type: ar.TYPE_EVIDENCE_NVIDIA,
		Artifacts: []ar.Artifact{
			{
				Type: ar.TYPE_NVIDIA_COLLATERAL,
				Events: []ar.Component{{
					NvidiaCollateral: &nvidiaCollateral,
				}},
			},
		},
	}}, nil
}

// --- Supplementary Cryptographic Verification & Local Stubs ---

// nvidiaHttpTimeout bounds every request to NVIDIA's attestation services.
const nvidiaHttpTimeout = 10 * time.Second

var nvidiaHttpClient = &http.Client{Timeout: nvidiaHttpTimeout}

func FetchRIMData(query string) (string, error) {
	req, err := http.NewRequest("GET", "https://rim.attestation.nvidia.com/v1/rim/ids", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create IDs request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := nvidiaHttpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch IDs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IDs request failed with status: %s", resp.Status)
	}

	var wrapper struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return "", fmt.Errorf("failed to decode JSON IDs: %w", err)
	}

	var matchedID string
	for _, id := range wrapper.IDs {
		if strings.Contains(id, query) {
			matchedID = id
			break
		}
	}
	if matchedID == "" {
		return "", fmt.Errorf("no RIM ID found matching query: %s", query)
	}

	respDetails, err := nvidiaHttpClient.Get(fmt.Sprintf("https://rim.attestation.nvidia.com/v1/rim/%s", matchedID))
	if err != nil {
		return "", fmt.Errorf("failed to fetch details for %s: %w", matchedID, err)
	}
	defer respDetails.Body.Close()

	if respDetails.StatusCode != http.StatusOK {
		return "", fmt.Errorf("RIM request for %s failed with status: %s", matchedID, respDetails.Status)
	}

	var payload RIMPayload
	if err := json.NewDecoder(respDetails.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("failed to parse JSON payload details: %w", err)
	}
	return payload.Rim, nil
}

func extractCertsFromRim(rawRim64 string) ([]*x509.Certificate, error) {
	rimBytes, err := base64.StdEncoding.DecodeString(rawRim64)
	if err != nil {
		return nil, err
	}
	// The driver only needs the chain to determine which OCSP responders to query
	return internal.ExtractRimCerts(rimBytes)
}

func verifyOCSPRecency(ocsps []string) error {
	if len(ocsps) == 0 {
		return fmt.Errorf("empty response collection array")
	}
	now := time.Now()
	for i, b64Response := range ocsps {
		derBytes, err := base64.StdEncoding.DecodeString(b64Response)
		if err != nil {
			return fmt.Errorf("response [%d]: base64 decode crash: %v", i, err)
		}

		resp, err := ocsp.ParseResponse(derBytes, nil)
		if err != nil {
			return fmt.Errorf("response [%d]: failed parse validation: %v", i, err)
		}

		if now.Before(resp.ThisUpdate) {
			return fmt.Errorf("response [%d]: update window configured in the future", i)
		}

		if !resp.NextUpdate.IsZero() && now.After(resp.NextUpdate) {
			return fmt.Errorf("response [%d]: validation interval completely expired", i)
		}
	}
	return nil
}

var ocspSemaphore = make(chan struct{}, 10)

func (nvidia *Nvidia) fetchOCSP(certChain []*x509.Certificate, deviceCerts bool) ([]string, error) {
	if len(certChain) < 2 {
		return nil, fmt.Errorf("certificate chain must contain at least a certificate and its issuer")
	}

	var b64Responses []string
	httpClient := nvidiaHttpClient

	start := 0
	if deviceCerts {
		start = 1
	}

	for i := start; i < len(certChain)-1; i++ {
		cert := certChain[i]
		issuer := certChain[i+1]
		certKey := cert.SerialNumber.String()

		// --- Check Per-Certificate Cache ---
		nvidia.collateralMu.RLock()
		cachedResp, exists := nvidia.certOcsps[certKey]
		nvidia.collateralMu.RUnlock()

		if exists && verifyOCSPRecency([]string{cachedResp}) == nil {
			b64Responses = append(b64Responses, cachedResp)
			continue
		}

		cert.OCSPServer = append(cert.OCSPServer, "https://ocsp.ndis.nvidia.com")
		if len(cert.OCSPServer) == 0 {
			continue
		}
		ocspURL := cert.OCSPServer[0]

		ocspRequestBytes, err := ocsp.CreateRequest(cert, issuer, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request bytes object: %w", err)
		}

		var b64Response string
		err = func() error {
			// Acquire token only when we are forced to make a network request
			ocspSemaphore <- struct{}{}
			defer func() { <-ocspSemaphore }()

			resp, err := httpClient.Post(ocspURL, "application/ocsp-request", bytes.NewReader(ocspRequestBytes))

			if err != nil {
				return fmt.Errorf("HTTP target network failure post to %s: %w", ocspURL, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("responder issued non-200 transaction state code: %d", resp.StatusCode)
			}

			ocspResponseBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("failed to read target data transaction response buffer body: %w", err)
			}

			b64Response = base64.StdEncoding.EncodeToString(ocspResponseBytes)
			return nil
		}()

		if err != nil {
			return nil, err
		}

		// --- Update Per-Certificate Cache ---
		nvidia.collateralMu.Lock()
		nvidia.certOcsps[certKey] = b64Response
		nvidia.collateralMu.Unlock()

		b64Responses = append(b64Responses, b64Response)
	}
	return b64Responses, nil
}
