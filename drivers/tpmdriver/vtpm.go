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

package tpmdriver

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/Fraunhofer-AISEC/cmc/internal"
)

// provisionSelfSigned provisions a fresh AK inside the vTPM and wraps its
// public key in a self-signed X.509 certificate. This is only to be used for
// CVMs where the primary trust anchor is the Confidential Computing hardware
// and the vTPM resides within the CVM (e.g., via COCONUT SVSM). As such vTPMs
// do not have an EK rooting back to a manufacturer CA, we use the context-hash
// binding mechanism to ensure integrity of the vTPM: the self-signed vTPM AK
// certificate is part of the SNP/TDX REPORTDATA (nonce), and this binding
// is verified during remote attestation.
func (t *Tpm) provisionSelfSigned() error {

	log.Debug("Performing vTPM AK self-provisioning..")

	ak, err := createAk(t.tpm, t.KeyAlg)
	if err != nil {
		return fmt.Errorf("failed to create AK: %w", err)
	}
	t.ak = ak

	fqdn, err := internal.Fqdn()
	if err != nil {
		return fmt.Errorf("failed to get FQDN: %w", err)
	}

	akCert, err := t.createSelfSignedAkCert(fqdn + " vTPM AK")
	if err != nil {
		return fmt.Errorf("failed to create self-signed AK certificate: %w", err)
	}
	t.akChain = []*x509.Certificate{akCert}

	log.Debugf("Provisioned self-signed vTPM AK cert: %v", akCert.Subject.CommonName)

	return nil
}

// createSelfSignedAkCert creates a self-signed X.509 certificate
// signed by the AK public key.
func (t *Tpm) createSelfSignedAkCert(cn string) (*x509.Certificate, error) {

	if t.ak == nil {
		return nil, errors.New("AK not initialized")
	}
	akPub := t.ak.Public()
	if akPub == nil {
		return nil, errors.New("AK has no public key")
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: cn,
		},
		Issuer: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKey:             akPub,
	}

	der, err := CreateCertificate(rand.Reader, template, template, akPub, t.ak, t.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to create self-signed AK certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse self-signed AK certificate: %w", err)
	}

	return cert, nil
}
