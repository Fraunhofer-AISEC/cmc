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
	"fmt"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/prover"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
)

func Generate(nonce []byte, cached []string, cmc *Cmc) ([]byte, map[string][]byte, []string, error) {

	if cmc == nil {
		return nil, nil, nil, fmt.Errorf("internal errro: cmc is nil")
	}

	// Generate attestation report
	report, metadata, err := prover.Generate(nonce, cached, cmc.Metadata, cmc.Drivers, cmc.Serializer)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate: %w", err)
	}

	// Return cache misses, so that verifier can discard obsolete metadata
	cacheMisses := GetCacheMisses(cached, cmc.Metadata)

	// Marshal data to bytes
	r, err := cmc.Serializer.Marshal(report)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal the Attestation Report: %v", err)
	}

	// Sign attestation report
	if len(cmc.Drivers) == 0 {
		return nil, nil, nil, fmt.Errorf("internal error: failed to sign: no driver configured")
	}
	log.Debugf("Prover: Signing attestation report using %v", cmc.Drivers[0].Name())
	signedReport, err := prover.Sign(r, cmc.Drivers[0], cmc.Serializer, ar.IK)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to sign attestation report: %w", err)
	}

	return signedReport, metadata, cacheMisses, nil
}

func Verify(
	ar, nonce []byte,
	identityCasDer [][]byte,
	metadataCasDer [][]byte,
	policies []byte,
	peer string,
	cacheMisses []string,
	metadata map[string][]byte,
	cmc *Cmc,
) (*ar.VerificationResult, error) {

	if cmc == nil {
		return nil, fmt.Errorf("internal error: cmc is nil")
	}

	// Update volatile peer cache
	UpdateCacheMetadata(peer, cmc.CachedPeerMetadata, metadata, cacheMisses)

	metadataCas, err := internal.ParseCertsPem(metadataCasDer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse metadata CAs: %w", err)
	}

	identityCas, err := internal.ParseCertsPem(identityCasDer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse metadata CAs: %w", err)
	}

	// Verify attetation report
	result := verifier.Verify(ar, nonce, identityCas, metadataCas, policies,
		cmc.PolicyEngineSelect, cmc.CachedPeerMetadata[peer])

	// Update persistent peer cache
	err = StoreCacheMetadata(cmc.PeerCache, peer, cmc.CachedPeerMetadata[peer], cacheMisses)
	if err != nil {
		log.Warnf("Internal error: failed to cache metadata: %v", err)
	}

	return result, nil
}
