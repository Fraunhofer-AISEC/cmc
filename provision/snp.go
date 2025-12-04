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

package provision

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sync"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	log "github.com/sirupsen/logrus"
)

const (
	snpBaseUrl    = "https://kdsintf.amd.com"
	snpMaxRetries = 3
	lenChipId     = 64
)

type VcekInfo struct {
	ChipId [lenChipId]byte
	Tcb    uint64
}

type SnpConfig struct {
	VcekMutex       sync.Mutex
	VcekCacheFolder string
	Vceks           map[VcekInfo][]byte
	CaCacheFolder   string
}

type certFormat int

const (
	PEM = iota
	DER
)

func SnpCaUrl(aktype internal.AkType, codeName string) string {
	return fmt.Sprintf("%s/%s/v1/%s/cert_chain", snpBaseUrl, aktype.String(), codeName)
}

func SnpVcekUrl(codeName string, chipId []byte, tcbRaw uint64) string {

	tcb := ar.GetSnpTcb(codeName, tcbRaw)

	// Turin and later chip IP length is 8 and TCB additionally contains FMC SPL
	if codeName == "Turin" {
		return fmt.Sprintf("%s/vcek/v1/%s/%s?fmcSPL=%v&blSPL=%v&teeSPL=%v&snpSPL=%v&ucodeSPL=%v",
			snpBaseUrl,
			codeName,
			hex.EncodeToString(chipId[:8]), // 8 byte for Turin
			tcb.Fmc,
			tcb.Bl,
			tcb.Tee,
			tcb.Snp,
			tcb.Ucode)
	} else {
		return fmt.Sprintf("%s/vcek/v1/%s/%s?blSPL=%v&teeSPL=%v&snpSPL=%v&ucodeSPL=%v",
			snpBaseUrl,
			codeName,
			hex.EncodeToString(chipId), // full 64 byte for Milan and Genoa
			tcb.Bl,
			tcb.Tee,
			tcb.Snp,
			tcb.Ucode)
	}
}

// Get Vcek takes the TCB and chip ID, calculates the VCEK URL and gets the certificate
// in DER format from the cache or downloads it from the AMD server if not present
func (s *SnpConfig) GetVcek(codeName string, chipId []byte, tcb uint64) (*x509.Certificate, error) {

	log.Tracef("Fetching %q VCEK for chip ID %v, TCB %x", codeName, hex.EncodeToString(chipId), tcb)

	// Allow only one download and caching of the VCEK certificate in parallel
	// as the AMD KDF server allows only one request in 10s
	s.lockVcekMutex()
	defer s.unlockVcekMutex()

	if len(chipId) != lenChipId {
		return nil, fmt.Errorf("invalid chip ID length %v, must be %v", len(chipId), lenChipId)
	}

	var id [lenChipId]byte
	copy(id[:], chipId)

	der, ok := s.tryGetCachedVcek(id, tcb)
	if ok {
		vcek, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse VCEK: %w", err)
		}
		return vcek, nil
	}

	url := SnpVcekUrl(codeName, chipId, tcb)

	for i := 0; i < snpMaxRetries; i++ {
		log.Tracef("Requesting SNP VCEK certificate from: %v", url)
		vcek, statusCode, err := DownloadVcek(url)
		if err == nil {
			log.Tracef("Successfully downloaded VCEK certificate")
			if err := s.cacheVcek(vcek.Raw, id, tcb); err != nil {
				log.Warnf("Failed to cache VCEK: %v", err)
			}
			return vcek, nil
		}
		// If the status code is not 429 (too many requests), return
		if statusCode != 429 {
			return nil, fmt.Errorf("failed to get VCEK certificate: %w", err)
		}
		// The AMD KDS server accepts requests only every 10 seconds, try again
		log.Warnf("AMD server blocked VCEK request for ChipID %v TCB %x (HTTP 429 - Too many requests). Trying again in 11s",
			hex.EncodeToString(id[:]), tcb)
		time.Sleep(time.Duration(11) * time.Second)
	}

	return nil, fmt.Errorf("failed to get VCEK certificat after %v retries", snpMaxRetries)
}

func (s *SnpConfig) GetSnpCa(codeName string, akType internal.AkType) ([]*x509.Certificate, error) {

	log.Debugf("Fetching AMD SNP %v CA", codeName)

	der, ok := tryGetCachedCa(s.CaCacheFolder, codeName)
	if ok {
		ca, err := x509.ParseCertificates(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse VCEK: %w", err)
		}
		return ca, nil
	}

	url := SnpCaUrl(akType, codeName)
	ca, err := fetchSnpCa(url, PEM)
	if err != nil {
		return nil, fmt.Errorf("failed to ftch SNP CA: %w", err)
	}

	log.Debugf("Successfully downloaded SNP CA")
	rawCerts := internal.WriteCertsDer(ca)
	if err := cacheSnpCa(bytes.Join(rawCerts, nil), s.CaCacheFolder, codeName); err != nil {
		log.Warnf("Failed to cache SNP CA: %v", err)
	}
	return ca, nil
}

func (s *SnpConfig) lockVcekMutex() {
	log.Trace("Trying to get lock")
	s.VcekMutex.Lock()
	log.Trace("Got lock")
}

func (s *SnpConfig) unlockVcekMutex() {
	log.Trace("Releasing Lock")
	s.VcekMutex.Unlock()
	log.Trace("Released Lock")
}

// tryGetCachedVcek returns cached VCEKs in DER format if available
func (s *SnpConfig) tryGetCachedVcek(chipId [64]byte, tcb uint64) ([]byte, bool) {
	if s.VcekCacheFolder != "" {
		filePath := path.Join(s.VcekCacheFolder,
			fmt.Sprintf("%v_%x.der", hex.EncodeToString(chipId[:]), tcb))
		f, err := os.ReadFile(filePath)
		if err != nil {
			log.Tracef("VCEK not present at %v, will be downloaded", filePath)
			return nil, false
		}
		log.Tracef("Using offlince cached VCEK %v", filePath)
		return f, true
	} else {
		info := VcekInfo{
			ChipId: chipId,
			Tcb:    tcb,
		}
		if der, ok := s.Vceks[info]; ok {
			log.Trace("Using cached VCEK")
			return der, true
		}
		log.Trace("Could not find VCEK in cache")
	}
	return nil, false
}

// cacheVcek caches VCEKs in DER format
func (s *SnpConfig) cacheVcek(vcek []byte, chipId [64]byte, tcb uint64) error {
	if s.VcekCacheFolder != "" {
		if _, err := os.Stat(s.VcekCacheFolder); err != nil {
			if err := os.MkdirAll(s.VcekCacheFolder, 0755); err != nil {
				return fmt.Errorf("failed to create VCEK cache %q: %v", s.VcekCacheFolder, err)
			}
		}
		filePath := path.Join(s.VcekCacheFolder,
			fmt.Sprintf("%v_%x.der", hex.EncodeToString(chipId[:]), tcb))
		err := os.WriteFile(filePath, vcek, 0644)
		if err != nil {
			return fmt.Errorf("failed to write file %v: %w", filePath, err)
		}
		log.Tracef("Cached VCEK at %v", filePath)
		return nil
	} else {
		info := VcekInfo{
			ChipId: chipId,
			Tcb:    tcb,
		}
		s.Vceks[info] = vcek
		log.Trace("Cached VCEK")
		return nil
	}
}

func DownloadVcek(url string) (*x509.Certificate, int, error) {

	resp, err := http.Get(url)
	if err != nil {
		return nil, 0, fmt.Errorf("error HTTP GET: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, resp.StatusCode, fmt.Errorf("HTTP Response Status: %v (%v)", resp.StatusCode, resp.Status)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read HTTP body: %w", err)
	}

	cert, err := x509.ParseCertificate(content)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to parse x509 Certificate: %w", err)
	}
	return cert, resp.StatusCode, nil
}

// tryGetCachedCa returns the cached CA chain in DER format if available
func tryGetCachedCa(caCacheFolder, codeName string) ([]byte, bool) {
	if caCacheFolder != "" {
		filePath := path.Join(caCacheFolder, fmt.Sprintf("ask_ark_%v.cert", codeName))
		f, err := os.ReadFile(filePath)
		if err != nil {
			log.Tracef("%v CA not present at %v, will be downloaded", codeName, filePath)
			return nil, false
		}
		log.Tracef("Using offlince cached %v CA: %v", codeName, filePath)
		return f, true
	}
	return nil, false
}

func fetchSnpCa(url string, format certFormat) ([]*x509.Certificate, error) {

	log.Debugf("Requesting Cert from %v", url)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error HTTP GET: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP Response Status: %v (%v)", resp.StatusCode, resp.Status)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP body: %w", err)
	}

	var data []byte
	if format == PEM {
		rest := content
		var block *pem.Block
		for {
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			data = append(data, block.Bytes...)

		}
	} else if format == DER {
		data = content
	} else {
		return nil, fmt.Errorf("internal error: Unknown certificate format %v", format)
	}

	certs, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 Certificate: %w", err)
	}
	return certs, nil
}

func cacheSnpCa(ca []byte, caCacheFolder, codeName string) error {
	if caCacheFolder != "" {
		filePath := path.Join(caCacheFolder, fmt.Sprintf("ask_ark_%v.cert", codeName))
		err := os.WriteFile(filePath, ca, 0644)
		if err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
		log.Tracef("Cached VCEK at %v", filePath)
	}
	return nil
}
