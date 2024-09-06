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

package main

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	snpVcekUrlPrefix = "https://kdsintf.amd.com/vcek/v1/Milan/"
	snpMilanUrl      = "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain"
	snpMaxRetries    = 3
	lenChipId        = 64
)

type vcekInfo struct {
	ChipId [lenChipId]byte
	Tcb    uint64
}

type snpConfig struct {
	vcekMutex       sync.Mutex
	vcekCacheFolder string
	vceks           map[vcekInfo][]byte
}

func (s *Server) lockVcekMutex() {
	log.Trace("Trying to get lock")
	s.snpConf.vcekMutex.Lock()
	log.Trace("Got lock")
}

func (s *Server) unlockVcekMutex() {
	log.Trace("Releasing Lock")
	s.snpConf.vcekMutex.Unlock()
	log.Trace("Released Lock")
}

// Get Vcek takes the TCB and chip ID, calculates the VCEK URL and gets the certificate
// in DER format from the cache or downloads it from the AMD server if not present
func (s *Server) getVcek(chipId []byte, tcb uint64) (*x509.Certificate, error) {

	log.Tracef("Fetching VCEK for chip ID %v, TCB %x", hex.EncodeToString(chipId), tcb)

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

	ChipId := hex.EncodeToString(chipId)
	tcbInfo := fmt.Sprintf("?blSPL=%v&teeSPL=%v&snpSPL=%v&ucodeSPL=%v",
		tcb&0xFF,
		(tcb>>8)&0xFF,
		(tcb>>48)&0xFF,
		(tcb>>56)&0xFF)

	url := snpVcekUrlPrefix + ChipId + tcbInfo
	for i := 0; i < snpMaxRetries; i++ {
		log.Tracef("Requesting SNP VCEK certificate from: %v", url)
		vcek, statusCode, err := downloadCert(url)
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

// tryGetCachedVcek returns cached VCEKs in DER format if available
func (s *Server) tryGetCachedVcek(chipId [64]byte, tcb uint64) ([]byte, bool) {
	if s.snpConf.vcekCacheFolder != "" {
		filePath := path.Join(s.snpConf.vcekCacheFolder,
			fmt.Sprintf("%v_%x.der", hex.EncodeToString(chipId[:]), tcb))
		f, err := os.ReadFile(filePath)
		if err != nil {
			log.Tracef("VCEK not present at %v, will be downloaded", filePath)
			return nil, false
		}
		log.Tracef("Using offlince cached VCEK %v", filePath)
		return f, true
	} else {
		info := vcekInfo{
			ChipId: chipId,
			Tcb:    tcb,
		}
		if der, ok := s.snpConf.vceks[info]; ok {
			log.Trace("Using cached VCEK")
			return der, true
		}
		log.Trace("Could not find VCEK in cache")
	}
	return nil, false
}

// cacheVcek caches VCEKs in DER format
func (s *Server) cacheVcek(vcek []byte, chipId [64]byte, tcb uint64) error {
	if s.snpConf.vcekCacheFolder != "" {
		filePath := path.Join(s.snpConf.vcekCacheFolder,
			fmt.Sprintf("%v_%x.der", hex.EncodeToString(chipId[:]), tcb))
		err := os.WriteFile(filePath, vcek, 0644)
		if err != nil {
			return fmt.Errorf("failed to write file %v: %w", filePath, err)
		}
		log.Tracef("Cached VCEK at %v", filePath)
		return nil
	} else {
		info := vcekInfo{
			ChipId: chipId,
			Tcb:    tcb,
		}
		s.snpConf.vceks[info] = vcek
		log.Trace("Cached VCEK")
		return nil
	}
}

func downloadCert(url string) (*x509.Certificate, int, error) {

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
