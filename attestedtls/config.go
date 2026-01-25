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

package attestedtls

import (
	"crypto"
	"crypto/x509"
	"fmt"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
)

type AttestSelect uint32

const (
	Attest_Mutual AttestSelect = 0
	Attest_Client AttestSelect = 1
	Attest_Server AttestSelect = 2
	Attest_None   AttestSelect = 3
)

type Endpoint uint32

const (
	Endpoint_Client = 0
	Endpoint_Server = 1
)

const (
	cmcAddrDefault      = "127.0.0.1:9955"
	cmcApiSelectDefault = "grpc"
	attestDefault       = Attest_Mutual
	timeoutSec          = 10
)

// Struct that holds information on cmc address and port
// to be used by Listener and DialConfig
type CmcConfig struct {
	CmcAddr       string
	CmcApi        CmcApi
	ApiSerializer ar.Serializer
	IdentityCas   []*x509.Certificate
	Policies      []byte
	Mtls          bool
	Attest        AttestSelect
	ResultCb      func(result *ar.VerificationResult)
	Cmc           *cmc.Cmc
}

type CmcApi interface {
	obtainAR(cc *CmcConfig, chbindings []byte, cached []string) ([]byte, map[string][]byte, []string, error)
	verifyAR(cc *CmcConfig, report, nonce, policies []byte, peer string, cacheMisses []string, metadata map[string][]byte) error
	fetchSignature(cc *CmcConfig, digest []byte, opts crypto.SignerOpts) ([]byte, error)
	fetchCerts(cc *CmcConfig) ([][]byte, error)
	fetchPeerCache(cc *CmcConfig, fingerprint string) ([]string, error)
}

var CmcApis = map[string]CmcApi{}

type ConnectionOption[T any] func(*T) error

// NewCmcConfig creates a new CMC config based on default and specified values
func NewCmcConfig(opts ...ConnectionOption[CmcConfig]) (*CmcConfig, error) {

	// Start with defaults
	cc := &CmcConfig{
		CmcAddr:       cmcAddrDefault,
		CmcApi:        CmcApis[cmcApiSelectDefault],
		Attest:        attestDefault,
		ApiSerializer: ar.CborSerializer{},
	}

	// Overwrite with specified configuration options
	for _, opt := range opts {
		err := opt(cc)
		if err != nil {
			return nil, fmt.Errorf("failed to apply connection option: %w", err)
		}
	}

	return cc, nil
}

// WithCmcAddress sets the address with which to contact the CMC.
// If not specified, default is "localhost"
func WithCmcAddr(address string) ConnectionOption[CmcConfig] {
	return func(c *CmcConfig) error {
		c.CmcAddr = address
		return nil
	}
}

// WithCmcApi specifies the API to be used to connect to the cmcd
// If not specified, default is grpc
func WithCmcApi(api string) ConnectionOption[CmcConfig] {
	return func(c *CmcConfig) error {
		cmcApi, ok := CmcApis[api]
		if !ok {
			return fmt.Errorf("unsupported CMC API %q", api)
		}
		c.CmcApi = cmcApi
		return nil
	}
}

// WithCmcPolicies specifies optional custom policies the attestation report should
// be verified against
func WithCmcPolicies(policies []byte) ConnectionOption[CmcConfig] {
	return func(c *CmcConfig) error {
		c.Policies = policies
		return nil
	}
}

// WithApiSerializer specifies the serializer for internal requests
func WithApiSerializer(apiSerializer ar.Serializer) ConnectionOption[CmcConfig] {
	return func(c *CmcConfig) error {
		if apiSerializer == nil {
			return fmt.Errorf("cannot configure api serializer nil")
		}
		c.ApiSerializer = apiSerializer
		return nil
	}
}

// WithMtls specifies whether to perform mutual TLS with mutual attestation
// or server-side authentication and attestation only
func WithMtls(mtls bool) ConnectionOption[CmcConfig] {
	return func(c *CmcConfig) error {
		c.Mtls = mtls
		return nil
	}
}

// WithAttest specifies whether to perform mutual, dialer only, or listener only attestation
func WithAttest(attest AttestSelect) ConnectionOption[CmcConfig] {
	return func(c *CmcConfig) error {
		c.Attest = attest
		return nil
	}
}

// WithResultCb is a callback for further processing of attestation results
func WithResultCb(cb func(result *ar.VerificationResult)) ConnectionOption[CmcConfig] {
	return func(c *CmcConfig) error {
		c.ResultCb = cb
		return nil
	}
}

// WithLibApiCmc takes a CMC object. This is only required for the Lib API, where
// the CMC is integrated directly into binary (instead of using the cmcd)
func WithLibApiCmc(cmc *cmc.Cmc) ConnectionOption[CmcConfig] {
	return func(c *CmcConfig) error {
		c.Cmc = cmc
		return nil
	}
}

func (s AttestSelect) String() string {
	switch s {
	case Attest_Mutual:
		return "mutual"
	case Attest_Client:
		return "client"
	case Attest_Server:
		return "server"
	case Attest_None:
		return "none"
	default:
		return "unknown"
	}
}
