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

	"golang.org/x/exp/maps"

	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/internal"
)

type LibApi struct{}

func init() {
	CmcApis["libapi"] = LibApi{}
}

// Obtains attestation report from CMCd
func (a LibApi) obtainAR(cc CmcConfig, chbindings []byte, cached []string) ([]byte, map[string][]byte, []string, error) {

	if cc.Cmc == nil {
		return nil, nil, nil, errors.New("internal error: cmc is nil")
	}

	if len(cc.Cmc.Drivers) == 0 {
		return nil, nil, nil, errors.New("no drivers configured")
	}

	log.Debug("Prover: Generating Attestation Report with nonce: ", hex.EncodeToString(chbindings))

	report, metadata, cacheMisses, err := cmc.Generate(chbindings, cached, cc.Cmc)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate attestation report: %w", err)
	}

	resp := &api.AttestationResponse{
		Report:      report,
		Metadata:    metadata,
		CacheMisses: cacheMisses,
	}

	return resp.Report, resp.Metadata, resp.CacheMisses, nil
}

// Checks Attestation report by calling the CMC to Verify and checking its status response
func (a LibApi) verifyAR(
	cc CmcConfig,
	report, nonce, policies []byte,
	peer string,
	cacheMisses []string,
	metadata map[string][]byte,
) error {

	if cc.Cmc == nil {
		return errors.New("internal error: cmc is nil")
	}

	req := &api.VerificationRequest{
		Nonce:       nonce,
		Report:      report,
		Metadata:    metadata,
		Peer:        peer,
		CacheMisses: cacheMisses,
		Policies:    policies,
	}

	log.Debug("Verifier: verifying attestation report")
	result, err := cmc.Verify(req.Report, req.Nonce, req.Policies,
		req.Peer, req.CacheMisses, req.Metadata, cc.Cmc)
	if err != nil {
		return fmt.Errorf("failed to verify: %w", err)
	}

	// Return attestation result via callback if specified
	if cc.ResultCb != nil {
		cc.ResultCb(result)
	} else {
		log.Tracef("Will not return attestation result: no callback specified")
	}

	if result.Summary.Status == ar.StatusSuccess {
		log.Debugf("Attestation report verification successful")
	} else if result.Summary.Status == ar.StatusWarn {
		log.Debugf("Attestation report verification passed with warnings")
	} else {
		return errors.New("attestation report verification failed")
	}
	return nil
}

func (a LibApi) fetchSignature(cc CmcConfig, digest []byte, opts crypto.SignerOpts) ([]byte, error) {

	if cc.Cmc == nil {
		return nil, errors.New("internal error: cmc is nil")
	}

	if len(cc.Cmc.Drivers) == 0 {
		return nil, errors.New("no drivers configured")
	}
	d := cc.Cmc.Drivers[0]

	// Get key handle from (hardware) interface
	tlsKeyPriv, _, err := d.GetKeyHandles(ar.IK)
	if err != nil {
		return nil, fmt.Errorf("failed to get IK: %w", err)
	}

	// Sign
	log.Debugf("TLSSign using opts: %v, driver %v", opts, d.Name())
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
	d := cc.Cmc.Drivers[0]

	certChain, err := d.GetCertChain(ar.IK)
	if err != nil {
		return nil, fmt.Errorf("failed to get cert chain: %w", err)
	}

	log.Debugf("Obtained TLS cert from %v", d.Name())

	return internal.WriteCertsPem(certChain), nil
}

// Fetches the peer cache from the cmcd
func (a LibApi) fetchPeerCache(cc CmcConfig, fingerprint string) ([]string, error) {

	if cc.Cmc == nil {
		return nil, errors.New("internal error: cmc is nil")
	}

	log.Debugf("Fetching peer cache for peer: %v", fingerprint)

	c, ok := cc.Cmc.CachedPeerMetadata[fingerprint]
	if !ok {
		log.Tracef("No data cached for peer %v", fingerprint)
		return nil, nil
	}

	cache := maps.Keys(c)

	return cache, nil
}
