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
	"encoding/json"
	"fmt"

	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	g "github.com/Fraunhofer-AISEC/cmc/generate"
	v "github.com/Fraunhofer-AISEC/cmc/verify"
)

func Generate(req *api.AttestationRequest, cmc *Cmc) ([]byte, []string, error) {

	if req == nil {
		return nil, nil, fmt.Errorf("internal error: attestation request is nil")
	}

	// Generate attestation report
	report, err := g.Generate(req.Nonce, req.Cached, cmc.Metadata, cmc.Drivers, cmc.Serializer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate: %w", err)
	}

	// Return cache misses, so that verifier can discard obsolete metadata
	cacheMisses := GetCacheMisses(req.Cached, cmc.Metadata)

	// Marshal data to bytes
	r, err := cmc.Serializer.Marshal(report)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal the Attestation Report: %v", err)
	}

	// Sign attestation report
	log.Debug("Prover: Signing Attestation Report")
	data, err := g.Sign(r, cmc.Drivers[0], cmc.Serializer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign attestation report: %w", err)
	}

	return data, cacheMisses, nil
}

func Verify(req *api.VerificationRequest, cmc *Cmc) ([]byte, error) {

	if req == nil {
		return nil, fmt.Errorf("internal error: attestation request is nil")
	}
	if cmc == nil {
		return nil, fmt.Errorf("internal error: cmc is nil")
	}

	result := VerifyInternal(req, cmc)

	// Marshal attestation report
	log.Debug("Verifier: marshaling attestation result")
	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Attestation Result: %w", err)
	}

	return data, nil
}

func VerifyInternal(req *api.VerificationRequest, cmc *Cmc) ar.VerificationResult {

	if req == nil {
		log.Errorf("Internal error: request is nil")
		return ar.VerificationResult{}
	}

	// Verify attetation report
	result := v.Verify(req.AttestationReport, req.Nonce, req.Ca, req.Policies, req.Peer,
		cmc.PolicyEngineSelect, cmc.CachedPeerMetadata, cmc.PeerCache, cmc.IntelStorage)

	// Persistently cache peer metadata
	err := StoreCacheMetadata(cmc.PeerCache, req.Peer, cmc.CachedPeerMetadata[req.Peer], req.CacheMisses)
	if err != nil {
		log.Warnf("Internal error: failed to cache metadata: %v", err)
	}

	return result
}
