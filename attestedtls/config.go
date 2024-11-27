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

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
)

type CmcApiSelect uint32

const (
	CmcApi_GRPC   CmcApiSelect = 0
	CmcApi_COAP   CmcApiSelect = 1
	CmcApi_Socket CmcApiSelect = 2
	CmcApi_Lib    CmcApiSelect = 3
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
	cmcApiSelectDefault = CmcApi_GRPC
	attestDefault       = Attest_Mutual
	timeoutSec          = 10
)

// Struct that holds information on cmc address and port
// to be used by Listener and DialConfig
type CmcConfig struct {
	CmcAddr  string
	CmcApi   CmcApi
	Network  string
	Ca       []byte
	Policies []byte
	Mtls     bool
	Attest   AttestSelect
	ResultCb func(result *ar.VerificationResult)
	Cmc      *cmc.Cmc
}

type CmcApi interface {
	obtainAR(cc CmcConfig, chbindings []byte, params *AtlsHandshakeRequest) ([]byte, []string, error)
	verifyAR(chbindings, report []byte, peer string, cacheMisses []string, cc CmcConfig) error
	fetchSignature(cc CmcConfig, digest []byte, opts crypto.SignerOpts) ([]byte, error)
	fetchCerts(cc CmcConfig) ([][]byte, error)
	fetchPeerCache(cc CmcConfig, fingerprint string) ([]string, error)
}

var CmcApis = map[CmcApiSelect]CmcApi{}

type ConnectionOption[T any] func(*T)

// WithCmcAddress sets the address with which to contact the CMC.
// If not specified, default is "localhost"
func WithCmcAddr(address string) ConnectionOption[CmcConfig] {
	return func(c *CmcConfig) {
		c.CmcAddr = address
	}
}

// WithCmcApi specifies the API to be used to connect to the cmcd
// If not specified, default is grpc
func WithCmcApi(api CmcApiSelect) ConnectionOption[CmcConfig] {
	return func(c *CmcConfig) {
		c.CmcApi = CmcApis[api]
	}
}

// WithCmcNetwork specifies the network type to be used to connect
// to the cmcd in case the socket API is selected
func WithCmcNetwork(network string) ConnectionOption[CmcConfig] {
	return func(c *CmcConfig) {
		c.Network = network
	}
}

// WithCmcCa specifies the CA the attestation report should be verified against
// in PEM format
func WithCmcCa(pem []byte) ConnectionOption[CmcConfig] {
	return func(c *CmcConfig) {
		c.Ca = pem
	}
}

// WithCmcPolicies specifies optional custom policies the attestation report should
// be verified against
func WithCmcPolicies(policies []byte) ConnectionOption[CmcConfig] {
	return func(c *CmcConfig) {
		c.Policies = policies
	}
}

// WithMtls specifies whether to perform mutual TLS with mutual attestation
// or server-side authentication and attestation only
func WithMtls(mtls bool) ConnectionOption[CmcConfig] {
	return func(c *CmcConfig) {
		c.Mtls = mtls
	}
}

// WithAttest specifies whether to perform mutual, dialer only, or listener only attestation
func WithAttest(attest AttestSelect) ConnectionOption[CmcConfig] {
	return func(c *CmcConfig) {
		c.Attest = attest
	}
}

// WithResultCb is a callback for further processing of attestation results
func WithResultCb(cb func(result *ar.VerificationResult)) ConnectionOption[CmcConfig] {
	return func(c *CmcConfig) {
		c.ResultCb = cb
	}
}

// WithCmc takes a CMC object. This is only required for the Lib API, where
// the CMC is integrated directly into binary (instead of using the cmcd)
func WithCmc(cmc *cmc.Cmc) ConnectionOption[CmcConfig] {
	return func(c *CmcConfig) {
		c.Cmc = cmc
	}
}

// WithCmc specifies an entire CMC configuration
func WithCmcConfig(cmcConfig *CmcConfig) ConnectionOption[CmcConfig] {
	return func(c *CmcConfig) {
		*c = *cmcConfig
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
