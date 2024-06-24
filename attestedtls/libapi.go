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

//go:build !nodefaults || libapi

package attestedtls

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Fraunhofer-AISEC/cmc/generate"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/verify"
)

type LibApi struct{}

func init() {
	log.Trace("Adding Lib API to APIs")
	CmcApis[CmcApi_Lib] = LibApi{}
}

// Obtains attestation report from CMCd
func (a LibApi) obtainAR(cc CmcConfig, chbindings []byte) ([]byte, error) {

	if cc.Cmc == nil {
		return nil, errors.New("internal error: cmc is nil")
	}

	if len(cc.Cmc.Drivers) == 0 {
		return nil, errors.New("no drivers configured")
	}

	log.Debug("Prover: Generating Attestation Report with nonce: ", hex.EncodeToString(chbindings))

	report, err := generate.Generate(chbindings, cc.Cmc.Metadata, cc.Cmc.Drivers, cc.Cmc.Serializer)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation report: %w", err)
	}

	log.Debug("Prover: Signing Attestation Report")
	signedReport, err := generate.Sign(report, cc.Cmc.Drivers[0], cc.Cmc.Serializer)
	if err != nil {
		return nil, errors.New("prover: failed to sign Attestion Report ")
	}

	return signedReport, nil
}

// Checks Attestation report by calling the CMC to Verify and checking its status response
func (a LibApi) verifyAR(chbindings, report []byte, cc CmcConfig) error {

	log.Debug("Verifier: Verifying Attestation Report")
	result := verify.Verify(report, chbindings, cc.Ca, nil, cc.Cmc.PolicyEngineSelect, cc.Cmc.IntelStorage)

	// Return attestation result via callback if specified
	if cc.ResultCb != nil {
		cc.ResultCb(&result)
	} else {
		log.Tracef("Will not return attestation result: no callback specified")
	}

	if !result.Success {
		return errors.New("attestation report verification failed")
	}
	return nil
}

func (a LibApi) fetchSignature(cc CmcConfig, digest []byte, opts crypto.SignerOpts) ([]byte, error) {

	if len(cc.Cmc.Drivers) == 0 {
		return nil, errors.New("no drivers configured")
	}

	// Get key handle from (hardware) interface
	tlsKeyPriv, _, err := cc.Cmc.Drivers[0].GetSigningKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to get IK: %w", err)
	}

	// Sign
	log.Trace("TLSSign using opts: ", opts)
	signature, err := tlsKeyPriv.(crypto.Signer).Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, nil
}

func (a LibApi) fetchCerts(cc CmcConfig) ([][]byte, error) {

	if cc.Cmc == nil {
		return nil, errors.New("internal error: cmc is nil")
	}

	if len(cc.Cmc.Drivers) == 0 {
		return nil, errors.New("no drivers configured")
	}

	certChain, err := cc.Cmc.Drivers[0].GetCertChain()
	if err != nil {
		return nil, fmt.Errorf("failed to get cert chain: %w", err)
	}

	return internal.WriteCertsPem(certChain), nil
}
