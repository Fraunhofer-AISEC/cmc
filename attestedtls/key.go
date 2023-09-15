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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// PrivateKey Wrapper Implementing crypto.Signer interface
// Used to contact cmcd for signing operations
type PrivateKey struct {
	cmcConfig // embedded struct
	pubKey    crypto.PublicKey
}

// Implementation of Sign() in crypto.Signer iface
// Contacts cmcd for sign operation and returns received signature
func (priv PrivateKey) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if priv.cmcConfig.cmcApi == nil {
		return nil, errors.New("failed to get CMC API: nil")
	}
	return priv.cmcConfig.cmcApi.fetchSignature(priv.cmcConfig, digest, opts)
}

func (priv PrivateKey) Public() crypto.PublicKey {
	return priv.pubKey
}

// Obtains Certificate for the Identity Key (IK) used for the connection from cmcd
func GetCert(moreConfigs ...ConnectionOption[cmcConfig]) (tls.Certificate, error) {
	var tlsCert tls.Certificate

	// Get cmc Config: start with defaults
	cc := cmcConfig{
		cmcAddr: cmcAddrDefault,
		cmcApi:  cmcApis[cmcApiSelectDefault],
		attest:  attestDefault,
	}
	for _, c := range moreConfigs {
		c(&cc)
	}

	// Check that selected API is implemented
	if cc.cmcApi == nil {
		return tls.Certificate{}, fmt.Errorf("selected CMC API is not implemented")
	}

	certs, err := cc.cmcApi.fetchCerts(cc)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to fetch certificate from cmc: %w", err)
	}

	// Convert each certificate (assuming it has superfluous "---------[]BEGIN CERTIFICATE[]-----" still there)
	for _, cert := range certs {
		var currentBlock *pem.Block
		var remain []byte
		currentBlock, remain = pem.Decode(cert)
		if currentBlock == nil {
			return tls.Certificate{}, errors.New("certificate inside the certificate chain could not be decoded")
		}
		if newBlock, _ := pem.Decode(remain); newBlock != nil {
			return tls.Certificate{}, errors.New("certificate inside certificate chain contain superfluous data. Expecting separate Certificates")
		}
		if currentBlock.Type == "CERTIFICATE" {
			tlsCert.Certificate = append(tlsCert.Certificate, currentBlock.Bytes)
		} else {
			return tls.Certificate{}, errors.New("certificate inside the certificate chain not of correct type")
		}
	}
	if len(tlsCert.Certificate) == 0 {
		return tls.Certificate{}, errors.New("could not parse any certificate")
	}

	// Convert TLS cert (first cert)
	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not parse certificate: %w", err)
	}

	// Create TLS Cert
	tlsCert.Leaf = x509Cert
	tlsCert.PrivateKey = PrivateKey{
		pubKey:    x509Cert.PublicKey,
		cmcConfig: cc,
	}

	// Return cert
	return tlsCert, nil
}
