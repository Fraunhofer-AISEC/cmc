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

import "crypto"

type CmcApiSelect uint32

const (
	CmcApi_GRPC CmcApiSelect = 0
	CmcApi_COAP CmcApiSelect = 1
)

const (
	cmcAddressDefault   = "localhost"
	cmcPortDefault      = "9955"
	cmcApiSelectDefault = CmcApi_GRPC
	timeoutSec          = 10
)

// Struct that holds information on cmc address and port
// to be used by Listener and DialConfig
type cmcConfig struct {
	cmcPort    string
	cmcAddress string
	cmcApi     CmcApi
	ca         []byte
	policies   []byte
}

type CmcApi interface {
	createARRequest(nonce []byte) ([]byte, error)
	parseARResponse(data []byte) ([]byte, error)
	obtainAR(request []byte, cc cmcConfig, cert []byte) ([]byte, error)
	verifyAR(nonce, report []byte, cc cmcConfig) error
	fetchSignature(cc cmcConfig, digest []byte, opts crypto.SignerOpts) ([]byte, error)
	fetchCerts(cc cmcConfig) ([][]byte, error)
}

var cmcApis = map[CmcApiSelect]CmcApi{}

type ConnectionOption[T any] func(*T)

// WithCmcPort sets the port on which to contact the CMC.
// If not specified, default is "9955"
func WithCmcPort(port string) ConnectionOption[cmcConfig] {
	return func(c *cmcConfig) {
		c.cmcPort = port
	}
}

// WithCmcAddress sets the address with which to contact the CMC.
// If not specified, default is "localhost"
func WithCmcAddress(address string) ConnectionOption[cmcConfig] {
	return func(c *cmcConfig) {
		c.cmcAddress = address
	}
}

// WithCmcApi specifies the API to be used to connect to the cmcd
// If not specified, default is grpc
func WithCmcApi(api CmcApiSelect) ConnectionOption[cmcConfig] {
	return func(c *cmcConfig) {
		c.cmcApi = cmcApis[api]
	}
}

// WithCmcCa specifies the CA the attestation report should be verified against
// in PEM format
func WithCmcCa(pem []byte) ConnectionOption[cmcConfig] {
	return func(c *cmcConfig) {
		c.ca = pem
	}
}

// WithCmcPolicies specifies optional custom policies the attestation report should
// be verified against
func WithCmcPolicies(policies []byte) ConnectionOption[cmcConfig] {
	return func(c *cmcConfig) {
		c.policies = policies
	}
}
