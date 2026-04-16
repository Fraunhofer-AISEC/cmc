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

type LibApi struct {
	cmc *cmc.Cmc
}

func init() {
	CmcApis["libapi"] = LibApi{}
}

// Obtains attestation report from CMCd
func (a LibApi) obtainAR(cc *CmcConfig, chbindings []byte, cached []string) ([]byte, error) {

	if cc == nil {
		return nil, errors.New("internal error: cmc is nil")
	}

	if a.cmc == nil {
		cmc, err := cmc.NewCmc(cc.LibApiConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize CMC: %v", err)
		}
		a.cmc = cmc
	}

	if len(a.cmc.Drivers) == 0 {
		return nil, errors.New("no drivers configured")
	}

	report, err := prover.Generate(chbindings, cached, a.cmc.GetMetadata(), a.cmc.Drivers,
		cc.Serializer, a.cmc.HashAlg)
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

	if cc == nil {
		return errors.New("internal error: cmc is nil")
	}

	if a.cmc == nil {
		cmc, err := cmc.NewCmc(cc.LibApiConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize CMC: %v", err)
		}
		a.cmc = cmc
	}

	req := &api.VerificationRequest{
		Nonce:    nonce,
		Report:   report,
		Peer:     peer,
		PeerAddr: peerAddr,
		Policies: policies,
	}

	log.Debug("Verifier: verifying attestation report")
	result := verifier.Verify(req.Report, req.Nonce, req.Policies, a.cmc.PolicyEngineSelect,
		a.cmc.PolicyOverwrite, a.cmc.RootCas, a.cmc.PeerCache, req.Peer, req.PeerAddr)

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

	if cc == nil {
		return nil, errors.New("internal error: cmc is nil")
	}

	if a.cmc == nil {
		cmc, err := cmc.NewCmc(cc.LibApiConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize CMC: %v", err)
		}
		a.cmc = cmc
	}

	key, err := a.cmc.KeyMgr.GetKey(cc.KeyId)
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

	if cc == nil {
		return nil, errors.New("internal error: cmc is nil")
	}

	if a.cmc == nil {
		cmc, err := cmc.NewCmc(cc.LibApiConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize CMC: %v", err)
		}
		a.cmc = cmc
	}

	// Retrieve certificates
	certChain, err := a.cmc.KeyMgr.GetCertChain(cc.KeyId)
	if err != nil {
		return nil, fmt.Errorf("failed to get cert chain: %v", err)
	}
	log.Debugf("Obtained TLS cert %v", certChain[0].Subject.CommonName)

	return internal.WriteCertsPem(certChain), nil
}

// Fetches the peer cache from the cmcd
func (a LibApi) fetchPeerCache(cc *CmcConfig, fingerprint string) ([]string, error) {

	if cc == nil {
		return nil, errors.New("internal error: cmc is nil")
	}

	if a.cmc == nil {
		cmc, err := cmc.NewCmc(cc.LibApiConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize CMC: %v", err)
		}
		a.cmc = cmc
	}

	log.Debugf("Fetching peer cache for peer: %v", fingerprint)

	return a.cmc.PeerCache.GetKeys(fingerprint), nil
}

func (a LibApi) createKey(cc *CmcConfig) (string, error) {

	if cc == nil {
		return "", errors.New("internal error: cmc is nil")
	}

	keyId, err := a.cmc.KeyMgr.EnrollKey(&keymgr.KeyEnrollmentParams{
		KeyConfig:  cc.KeyConfig,
		Metadata:   a.cmc.GetMetadata(),
		Drivers:    a.cmc.Drivers,
		Serializer: cc.Serializer,
		ArHashAlg:  a.cmc.HashAlg,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create key: %v", err)
	}

	return keyId, nil
}
