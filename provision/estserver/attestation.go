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
	"crypto/tls"
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

func verifyAttestationReport(csr *x509.CertificateRequest, cas []*x509.Certificate,
	report []byte, publishResults, publishOcsf, publishNetwork, publishFile string, publishToken []byte,
	publishRootCas []*x509.Certificate, publishAllowSystemCerts bool,
	publishClientCert *tls.Certificate,
) error {

	if len(report) == 0 {
		return fmt.Errorf("failed to verify attestation report: no report was provided")
	}

	// Use Subject Key Identifier (SKI) as nonce
	// We use SHA-256 instead of SHA-1 for the SKI as we control both sides
	pubKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse CSR public key: %w", err)
	}
	nonce := sha256.Sum256(pubKey)

	log.Debugf("Verifying attestation report with SKI as nonce: %v",
		hex.EncodeToString(nonce[:]))

	// Verify the attestation report
	result := verifier.Verify(report, nonce[:],
		nil, verifier.PolicyEngineSelect_None, false,
		cas, nil, "", "")

	hostname, _ := internal.Fqdn()
	result.Verifier = ar.Endpoint{Hostname: hostname}

	log.Debug("Publishing result...")
	wg := new(sync.WaitGroup)
	wg.Add(1)
	defer wg.Wait()
	go pub.PublishAsync(publishResults, publishOcsf, publishNetwork, publishToken, publishFile, result, wg,
		publishRootCas, publishAllowSystemCerts, publishClientCert)

	if result.Summary.Status != ar.StatusSuccess && result.Summary.Status != ar.StatusWarn {
		return fmt.Errorf("failed to verify attestation report")
	}

	return nil
}
