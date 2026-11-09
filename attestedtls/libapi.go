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
	"errors"
	"fmt"

	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/keymgr"
	"github.com/Fraunhofer-AISEC/cmc/prover"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
)

type LibApi struct{}

func init() {
	CmcApis["libapi"] = LibApi{}
}

// libApiCmc returns the embedded CMC the connection is configured with
func libApiCmc(cc *CmcConfig) (*cmc.Cmc, error) {
	if cc == nil {
		return nil, errors.New("internal error: CMC config is nil")
	}
	if cc.LibApiCmc == nil {
		return nil, errors.New("no embedded CMC configured: use WithLibApiCmc")
	}
	return cc.LibApiCmc, nil
}

// Obtains attestation report from the embedded CMC
func (a LibApi) obtainAR(cc *CmcConfig, chbindings []byte, cached []string) ([]byte, error) {

	cmcInst, err := libApiCmc(cc)
	if err != nil {
		return nil, err
	}

	if len(cmcInst.Drivers) == 0 {
		return nil, errors.New("no drivers configured")
	}

	// Request updated OMSP responses if stored ones are too old
	cmcInst.UpdateOmsps()

	report, err := prover.Generate(chbindings, nil, cached, cmcInst.GetMetadata(), cmcInst.Drivers,
		cc.Serializer, cmcInst.HashAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation report: %w", err)
	}

	resp := &api.AttestationResponse{
		Report: report,
	}

	return resp.Report, nil
}

// Checks Attestation report by calling the CMC to Verify and checking its status response
func (a LibApi) verifyAR(
	cc *CmcConfig,
	report, nonce, policies []byte,
	peer, peerAddr string,
) error {

	cmcInst, err := libApiCmc(cc)
	if err != nil {
		return err
	}

	req := &api.VerificationRequest{
		Nonce:    nonce,
		Report:   report,
		Peer:     peer,
		PeerAddr: peerAddr,
		Policies: policies,
	}

	log.Debug("Verifier: verifying attestation report")
	result := verifier.Verify(req.Report, req.Nonce, req.Policies, cmcInst.PolicyEngineSelect,
		cmcInst.PolicyOverwrite, cmcInst.RootCas, cmcInst.PeerCache, req.Peer, req.PeerAddr, cmcInst.Metadata.Omsp.Enabled,
		cmcInst.LocalRole)

	// Return attestation result via callback if specified
	if cc.ResultCb != nil {
		cc.ResultCb(result)
	} else {
		log.Tracef("Will not return attestation result: no callback specified")
	}

	switch result.Summary.Status {
	case ar.StatusSuccess:
		log.Debugf("Attestation report verification successful")
	case ar.StatusWarn:
		log.Debugf("Attestation report verification passed with warnings")
	default:
		return errors.New("attestation report verification failed")
	}
	return nil
}

func (a LibApi) fetchSignature(cc *CmcConfig, digest []byte, opts crypto.SignerOpts) ([]byte, error) {

	cmcInst, err := libApiCmc(cc)
	if err != nil {
		return nil, err
	}

	key, err := cmcInst.KeyMgr.GetKey(cc.KeyId)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	signature, err := key.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, nil
}

func (a LibApi) fetchCerts(cc *CmcConfig) ([][]byte, error) {

	cmcInst, err := libApiCmc(cc)
	if err != nil {
		return nil, err
	}

	// Retrieve certificates
	certChain, err := cmcInst.KeyMgr.GetCertChain(cc.KeyId)
	if err != nil {
		return nil, fmt.Errorf("failed to get cert chain: %v", err)
	}
	log.Debugf("Obtained TLS cert %v", certChain[0].Subject.CommonName)

	return internal.WriteCertsPem(certChain), nil
}

// Fetches the peer cache from the cmcd
func (a LibApi) fetchPeerCache(cc *CmcConfig, fingerprint string) ([]string, error) {

	cmcInst, err := libApiCmc(cc)
	if err != nil {
		return nil, err
	}

	log.Debugf("Fetching peer cache for peer: %v", fingerprint)

	return cmcInst.PeerCache.GetKeys(fingerprint), nil
}

func (a LibApi) createKey(cc *CmcConfig) (string, error) {

	cmcInst, err := libApiCmc(cc)
	if err != nil {
		return "", err
	}

	keyId, err := cmcInst.KeyMgr.EnrollKey(&keymgr.KeyEnrollmentParams{
		KeyConfig:  cc.KeyConfig,
		Metadata:   cmcInst.GetMetadata(),
		Drivers:    cmcInst.Drivers,
		Serializer: cc.Serializer,
		ArHashAlg:  cmcInst.HashAlg,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create key: %v", err)
	}

	return keyId, nil
}
