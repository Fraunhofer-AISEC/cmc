// Copyright (c) 2021 - 2026 Fraunhofer AISEC
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
	"net"
	"os"
	"path/filepath"
	"slices"

	"github.com/Fraunhofer-AISEC/cmc/api"
)

// PrivateKey Wrapper implementing crypto.Signer interface
// Used to contact cmcd for signing operations
type PrivateKey struct {
	*CmcConfig // embedded struct
	pubKey     crypto.PublicKey
}

// Implementation of Sign() in crypto.Signer iface
// Contacts cmcd for sign operation and returns received signature
func (priv PrivateKey) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if priv.CmcConfig.CmcApi == nil {
		return nil, errors.New("failed to get CMC API: nil")
	}
	return priv.CmcConfig.CmcApi.fetchSignature(priv.CmcConfig, digest, opts)
}

func (priv PrivateKey) Public() crypto.PublicKey {
	return priv.pubKey
}

// GetOrCreateCert retrieves an existing TLS certificate by key ID, or creates
// a new one if retrieval fails or the certificate names do not match the
// configured CN, DNS names and IP addresses. The key ID is updated in place
// and persisted to keyIdFile if non-empty.
func GetOrCreateCert(keyId *string, keyIdFile string, opts ...ConnectionOption[CmcConfig]) (tls.Certificate, error) {
	if *keyId != "" {
		cert, err := GetCert(append(opts, WithKeyId(*keyId))...)
		if err == nil {
			cc, err := NewCmcConfig(opts...)
			if err != nil {
				return tls.Certificate{}, fmt.Errorf("failed to retrieve CMC config: %w", err)
			}
			err = matchesKeyConfig(cert.Leaf, cc.KeyConfig)
			if err == nil {
				log.Tracef("Found key with key id %s", *keyId)
				return cert, nil
			}
			log.Warnf("Certificate for key ID %v does not match configuration: %v. Creating new key",
				*keyId, err)
		} else {
			log.Warnf("Failed to retrieve certificate for key ID %v. Creating new key", *keyId)
		}
	}

	newId, err := CreateCert(append(opts, WithKeyId(*keyId))...)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create TLS key and cert: %w", err)
	}
	*keyId = newId

	if keyIdFile != "" {
		if err := os.MkdirAll(filepath.Dir(keyIdFile), 0755); err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to create key ID file directory: %w", err)
		}
		if err := os.WriteFile(keyIdFile, []byte(newId), 0600); err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to write key ID: %w", err)
		}
	}

	cert, err := GetCert(append(opts, WithKeyId(*keyId))...)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to retrieve certificate for key ID %v: %w", newId, err)
	}
	return cert, nil
}

// matchesKeyConfig checks whether the certificate subject CN and SANs equal the configured ones
func matchesKeyConfig(cert *x509.Certificate, kc api.TLSKeyConfig) error {
	if cert.Subject.CommonName != kc.Cn {
		return fmt.Errorf("CN %q, configured %q", cert.Subject.CommonName, kc.Cn)
	}

	if !slices.Equal(sortedUnique(cert.DNSNames), sortedUnique(kc.DNSNames)) {
		return fmt.Errorf("DNS names %v, configured %v", cert.DNSNames, kc.DNSNames)
	}

	certIps := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		certIps = append(certIps, ip.String())
	}
	confIps := make([]string, 0, len(kc.IPAddresses))
	for _, s := range kc.IPAddresses {
		ip := net.ParseIP(s)
		if ip == nil {
			return fmt.Errorf("failed to parse configured IP %v", s)
		}
		confIps = append(confIps, ip.String())
	}
	if !slices.Equal(sortedUnique(certIps), sortedUnique(confIps)) {
		return fmt.Errorf("IP addresses %v, configured %v", cert.IPAddresses, kc.IPAddresses)
	}

	return nil
}

func sortedUnique(s []string) []string {
	c := slices.Clone(s)
	slices.Sort(c)
	return slices.Compact(c)
}

func CreateCert(moreConfigs ...ConnectionOption[CmcConfig]) (string, error) {

	cc, err := NewCmcConfig(moreConfigs...)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve CMC config: %w", err)
	}

	keyId, err := cc.CmcApi.createKey(cc)
	if err != nil {
		return "", fmt.Errorf("failed to create new CMC key: %w", err)
	}

	return keyId, nil
}

// Retrieves TLS Certificate by key id. Note: Usually GetOrCreateCert() can be used
func GetCert(moreConfigs ...ConnectionOption[CmcConfig]) (tls.Certificate, error) {
	var tlsCert tls.Certificate

	cc, err := NewCmcConfig(moreConfigs...)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to retrieve CMC config: %w", err)
	}

	certs, err := cc.CmcApi.fetchCerts(cc)
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
		CmcConfig: cc,
	}

	// Return cert
	return tlsCert, nil
}
