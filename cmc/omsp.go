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

package cmc

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision"
	"golang.org/x/exp/maps"
)

func AddOmspToMetadata(metadata map[string][]byte, ser ar.Serializer, rootCas []*x509.Certificate, alg crypto.Hash) (map[string][]byte, []string, error) {
	log.Tracef("Requesting revocation information for manifests from OMSP server")
	omspReqs, err := getOmspRequests(metadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive OMSP requests from metadata: %v", err)
	}

	omspData := make([][]byte, 0)
	omspHashes := make([]string, 0)
	for server, omspReq := range omspReqs {
		omspResp, err := provision.FetchRevocationStatus(server, omspReq, ser, rootCas, false)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch revocation status for manifests from %v: %v", server, err)
		}
		omspData = append(omspData, omspResp)
		hash, err := internal.Hash(alg, omspResp)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to compute hash for OMSP response: %w", err)
		}
		omspHashes = append(omspHashes, hex.EncodeToString(hash[:]))
	}
	omspmap, err := internal.ConvertToMap(omspData, alg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert omspData to map: %w", err)
	}
	maps.Copy(metadata, omspmap)
	return metadata, omspHashes, nil
}

func getOmspRequests(metadata map[string][]byte) (map[string]provision.OmspRequest, error) {
	omspReqs := make(map[string]provision.OmspRequest)

	log.Debugf("Building OMSP requests for checking revocation of all SW manifests")
	for hash, elem := range metadata {
		log.Debugf("Checking manifest with hash %v", hash)

		// Get serialization format
		s, err := ar.DetectSerialization(elem)
		if err != nil {
			log.Warnf("Failed to detect serialization of metadata element with hash %v. Ignoring object..", hash)
			continue
		}

		// Extract plain payload (i.e. the manifest/description itself)
		data, err := s.GetPayload(elem)
		if err != nil {
			log.Warnf("Failed to parse metadata object with hash %v: %v. Ignoring object..", hash, err)
			continue
		}

		in := new(ar.Metadata)
		err = s.Unmarshal(data, in)
		if err != nil {
			log.Warnf("Failed to unmarshal data from metadata object with hash %v: %v. Ignoring object..", hash, err)
			continue
		}

		if in.Type == ar.TYPE_MANIFEST {
			if in.OmspServer == "" {
				log.Debugf("Manifest %v with hash %v does not contain a server URL for OmspRequests. Manifest is ignored during revocation check...", in.Name, hash)
			} else {
				log.Debugf("Adding hash %v for manifest %v to OmspRequest for server %v", in.Name, hash, in.OmspServer)
				var omspReq provision.OmspRequest
				omspReq.ArVersion = ar.GetReportVersion()
				omspReq.ManifestHashes = append(omspReqs[in.OmspServer].ManifestHashes, hash)
				omspReqs[in.OmspServer] = omspReq
			}
		}
	}

	return omspReqs, nil
}

func (cmc *Cmc) UpdateOmsps() {
	reqList := make(map[string]provision.OmspRequest)
	metadata := cmc.GetMetadata()

	newOmspHashes := make([]string, 0)
	for _, hash := range cmc.OmspHashes {
		elem := metadata[hash]
		log.Tracef("Checking available OMSP Response with hash %v", hash)

		// Get serialization format
		s, err := ar.DetectSerialization(elem)
		if err != nil {
			log.Warnf("Failed to detect serialization of OMSP response with hash %v. Ignoring object..", hash)
			continue
		}

		requestNewOmsp := false
		var omspResp ar.OmspResponse
		omspData, err := s.GetPayload(elem)
		//new OMSP response is requested if there are issues with parsing the OMSP response or
		// if the available OMSP response is older than two days
		if err != nil {
			requestNewOmsp = true
		} else {
			err = s.Unmarshal(omspData, omspResp)
			if err != nil {
				requestNewOmsp = true
			} else {
				omspTime, err := time.Parse(time.RFC3339, omspResp.ProducedAt)
				if err != nil {
					requestNewOmsp = true
				} else {
					if omspTime.Before(time.Now().Add(-48 * time.Hour)) {
						requestNewOmsp = true
					}
				}
			}
		}

		if requestNewOmsp {
			log.Tracef("Requesting revocation information for manifests from OMSP server %v", omspResp.Server)

			//Generate OMSP requests only once when the first OMSP response needs to be updated
			if _, found := reqList[omspResp.Server]; !found {
				reqList, err = getOmspRequests(cmc.GetMetadata())
				if err != nil {
					log.Warnf("failed to generate OMSP requests from metadata: %v", err)
					return
				}
			}

			newOmspResp, err := provision.FetchRevocationStatus(omspResp.Server, reqList[omspResp.Server], cmc.OmspSerializer, cmc.RootCas, false)
			if err != nil {
				log.Warnf("failed to fetch revocation status for manifests: %v", err)
				return
			}

			newHash, err := internal.Hash(cmc.HashAlg, newOmspResp)
			if err != nil {
				log.Warnf("failed to compute hash for OMSP response: %v", err)
				return
			}
			newOmspHashes = append(newOmspHashes, hex.EncodeToString(newHash[:]))
			metadata[hex.EncodeToString(newHash[:])] = newOmspResp
			delete(metadata, hash)
			cmc.UpdateMetadata(metadata)
		} else {
			newOmspHashes = append(newOmspHashes, hash)
		}
	}
	cmc.OmspHashes = newOmspHashes
}
