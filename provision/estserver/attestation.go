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
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	pub "github.com/Fraunhofer-AISEC/cmc/publish"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	log "github.com/sirupsen/logrus"
)

func verifyAttestationReport(csr *x509.CertificateRequest, cas []*x509.Certificate,
	report []byte, publishAddr, publishFile string, publishToken []byte,
) error {

	if len(report) == 0 {
		return fmt.Errorf("failed to verify attestation report: no report was provided")
	}

	// Use Subject Key Identifier (SKI) as nonce
	pubKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse CSR public key: %w", err)
	}
	nonce := sha1.Sum(pubKey)

	log.Debugf("Verifying attestation report with SKI as nonce: %v",
		hex.EncodeToString(nonce[:]))

	// Call verify with pubkey instead of identity CAs for verification in provisioning mode, which
	// only checks the signature, but not the certificate chains (which are about to
	// be created)
	result := verifier.Verify(report, nonce[:], csr.PublicKey,
		nil, verifier.PolicyEngineSelect_None, false,
		cas, nil, "")

	log.Debug("Publishing result...")
	wg := new(sync.WaitGroup)
	wg.Add(1)
	defer wg.Wait()
	go pub.PublishResultAsync(publishAddr, publishToken, publishFile, result, wg)

	if result.Summary.Status != ar.StatusSuccess && result.Summary.Status != ar.StatusWarn {
		return fmt.Errorf("failed to verify attestation report")
	}

	return nil
}
