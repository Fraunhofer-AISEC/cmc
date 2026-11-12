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

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	pub "github.com/Fraunhofer-AISEC/cmc/publish"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	log "github.com/sirupsen/logrus"
)

// verifyAttestationReport verifies the report against the metadata CAs and the optional policies,
// with the hash of the CSR public key as nonce, and publishes the result. Results with status warn
// are only accepted if configured
func (s *Server) verifyAttestationReport(csr *x509.CertificateRequest, report []byte,
) (*ar.AttestationResult, error) {

	if len(report) == 0 {
		return nil, fmt.Errorf("failed to verify attestation report: no report was provided")
	}

	// Use Subject Key Identifier (SKI) as nonce
	// We use SHA-256 instead of SHA-1 for the SKI as we control both sides
	pubKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR public key: %w", err)
	}
	nonce := sha256.Sum256(pubKey)

	log.Debugf("Verifying attestation report with SKI as nonce: %v",
		hex.EncodeToString(nonce[:]))

	// Verify the attestation report
	result := verifier.VerifyBootstrap(report, nonce[:],
		s.policies, s.policyEngine, s.policyOverwrite, s.rootCas)

	hostname, _ := internal.Fqdn()
	result.Verifier = ar.Endpoint{Hostname: hostname}

	log.Debug("Publishing result...")
	wg := new(sync.WaitGroup)
	wg.Add(1)
	defer wg.Wait()
	go pub.PublishAsync(s.publishResults, s.publishOcsf, s.publishNetwork, s.publishToken,
		s.publishFile, result, wg, s.rootCas, s.allowSystemCerts, s.publishClientCert)

	switch result.Summary.Status {
	case ar.StatusSuccess:
	case ar.StatusWarn:
		if !s.acceptWarn {
			return nil, fmt.Errorf("attestation result has status %v, which is not accepted",
				result.Summary.Status)
		}
	default:
		return nil, fmt.Errorf("failed to verify attestation report: status %v",
			result.Summary.Status)
	}

	return result, nil
}
