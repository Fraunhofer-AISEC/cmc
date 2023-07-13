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

package snpdriver

/*
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "ioctl.h"
*/
import "C"
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path"

	"net/http"
	"unsafe"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	est "github.com/Fraunhofer-AISEC/cmc/est/estclient"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "snpdriver")

const (
	PEM = iota
	DER = iota
)
const (
	snpChainFile     = "akchain.pem"
	signingChainFile = "ikchain.pem"
	snpPrivFile      = "ikpriv.key"
)

type certFormat int

var (
	vcekUrlPrefix = "https://kdsintf.amd.com/vcek/v1/Milan/"
	milanUrl      = "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain"
)

// Snp is a structure required for implementing the Measure method
// of the attestation report Measurer interface
type Snp struct {
	snpCertChain     []*x509.Certificate
	signingCertChain []*x509.Certificate
	priv             crypto.PrivateKey
}

// Init initializaes the SNP driver with the specifified configuration
func (snp *Snp) Init(c *ar.DriverConfig) error {
	var err error

	// Initial checks
	if snp == nil {
		return errors.New("internal error: SNP object is nil")
	}
	switch c.Serializer.(type) {
	case ar.JsonSerializer:
	case ar.CborSerializer:
	default:
		return fmt.Errorf("serializer not initialized in driver config")
	}

	// Create storage folder for storage of internal data if not existing
	if c.StoragePath != "" {
		if _, err := os.Stat(c.StoragePath); err != nil {
			if err := os.MkdirAll(c.StoragePath, 0755); err != nil {
				return fmt.Errorf("failed to create directory for internal data '%v': %w",
					c.StoragePath, err)
			}
		}
	}

	if provisioningRequired(c.StoragePath) {
		// Create new private key for signing
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate private key: %w", err)
		}
		snp.priv = priv

		// Create IK CSR and fetch new certificate including its chain from EST server
		snp.signingCertChain, err = getSigningCertChain(priv, c.Serializer, c.Metadata,
			c.ServerAddr)
		if err != nil {
			return fmt.Errorf("failed to get signing cert chain: %w", err)
		}

		// Fetch SNP certificate chain for VCEK (AK)
		snp.snpCertChain, err = getSnpCertChain(c.ServerAddr)
		if err != nil {
			return fmt.Errorf("failed to get SNP cert chain: %w", err)
		}

		if c.StoragePath != "" {
			err = saveCredentials(c.StoragePath, snp)
			if err != nil {
				return fmt.Errorf("failed to save SNP credentials: %w", err)
			}
		}
	} else {
		snp.snpCertChain, snp.signingCertChain, snp.priv, err = loadCredentials(c.StoragePath)
		if err != nil {
			return fmt.Errorf("failed to load SNP credentials: %w", err)
		}
	}

	return nil
}

// Measure implements the attestation reports generic Measure interface to be called
// as a plugin during attestation report generation
func (snp *Snp) Measure(nonce []byte) (ar.Measurement, error) {

	if snp == nil {
		return ar.SnpMeasurement{}, errors.New("internal error: SNP object is nil")
	}

	data, err := getSnpMeasurement(nonce)
	if err != nil {
		return ar.SnpMeasurement{}, fmt.Errorf("failed to get SNP Measurement: %w", err)
	}

	measurement := ar.SnpMeasurement{
		Type:   "SNP Measurement",
		Report: data,
		Certs:  internal.WriteCertsDer(snp.snpCertChain),
	}

	return measurement, nil
}

// Lock implements the locking method for the attestation report signer interface
func (snp *Snp) Lock() error {
	// No locking mechanism required for software key
	return nil
}

// Lock implements the unlocking method for the attestation report signer interface
func (snp *Snp) Unlock() error {
	// No unlocking mechanism required for software key
	return nil
}

// GetSigningKeys returns the TLS private and public key as a generic
// crypto interface
func (snp *Snp) GetSigningKeys() (crypto.PrivateKey, crypto.PublicKey, error) {
	if snp == nil {
		return nil, nil, errors.New("internal error: SW object is nil")
	}
	return snp.priv, &snp.priv.(*ecdsa.PrivateKey).PublicKey, nil
}

func (snp *Snp) GetCertChain() ([]*x509.Certificate, error) {
	if snp == nil {
		return nil, errors.New("internal error: SW object is nil")
	}
	log.Tracef("Returning %v certificates", len(snp.signingCertChain))
	return snp.signingCertChain, nil
}

func getSnpMeasurement(nonce []byte) ([]byte, error) {

	if len(nonce) > 64 {
		return nil, errors.New("user Data must be at most 64 bytes")
	}

	log.Tracef("Generating SNP attestation report with nonce: %v", hex.EncodeToString(nonce))

	buf := make([]byte, 4000)
	cBuf := (*C.uint8_t)(unsafe.Pointer(&buf[0]))
	cLen := C.size_t(4000)
	cUserData := (*C.uint8_t)(unsafe.Pointer(&nonce[0]))
	cUserDataLen := C.size_t(len(nonce))

	cRes, err := C.snp_dump_ar(cBuf, cLen, cUserData, cUserDataLen)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve SNP AR: %w", err)
	}

	res := int(cRes)
	if res != 0 {
		return nil, fmt.Errorf("failed to retrieve SNP AR. C.snp_dump_ar returned %v", res)
	}

	log.Trace("Generated SNP attestation report")

	return buf, nil
}

func getCerts(url string, format certFormat) ([]*x509.Certificate, int, error) {

	log.Tracef("Requesting Cert from %v", url)

	resp, err := http.Get(url)
	if err != nil {
		return nil, 0, fmt.Errorf("error HTTP GET: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, resp.StatusCode, fmt.Errorf("HTTP Response Status: %v (%v)", resp.StatusCode, resp.Status)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read HTTP body: %w", err)
	}

	var data []byte
	if format == PEM {
		rest := content
		var block *pem.Block
		for {
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			data = append(data, block.Bytes...)

		}
	} else if format == DER {
		data = content
	} else {
		return nil, resp.StatusCode, fmt.Errorf("internal error: Unknown certificate format %v", format)
	}

	certs, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to parse x509 Certificate: %w", err)
	}
	return certs, resp.StatusCode, nil
}

func getSnpCertChain(addr string) ([]*x509.Certificate, error) {
	ca, _, err := getCerts(milanUrl, PEM)
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP certificate chain: %w", err)
	}
	if len(ca) != 2 {
		return nil,
			fmt.Errorf("failed to get SNP certificate chain. Expected 2 certificates, got %v",
				len(ca))
	}

	// Fetch the VCEK. TODO as a workaround, we get the parameters through
	// fetching an initial attestation report and request the VCEK from the
	// Provisioning server. As soon as we can reliably get the correct TCB,
	// the host should provide the VCEK
	arRaw, err := getSnpMeasurement(make([]byte, 64))
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP report: %w", err)
	}
	s, err := ar.DecodeSnpReport(arRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SNP report: %w", err)
	}

	// TODO mandate server authentication in the future, otherwise
	// this step has to happen in a secure environment
	log.Warn("Creating new EST client without server authentication")
	client := est.NewClient(nil)

	vcek, err := client.SnpEnroll(addr, s.ChipId, s.CurrentTcb)
	if err != nil {
		return nil, fmt.Errorf("failed to enroll SNP: %w", err)
	}

	return append([]*x509.Certificate{vcek}, ca...), nil
}

func getSigningCertChain(priv crypto.PrivateKey, s ar.Serializer, metadata [][]byte,
	addr string,
) ([]*x509.Certificate, error) {

	csr, err := ar.CreateCsr(priv, s, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSRs: %w", err)
	}

	// Get CA certificates and enroll newly created CSR
	// TODO provision EST server certificate with a different mechanism,
	// otherwise this step has to happen in a secure environment. Allow
	// different CAs for metadata and the EST server authentication
	log.Warn("Creating new EST client without server authentication")
	client := est.NewClient(nil)

	log.Info("Retrieving CA certs")
	caCerts, err := client.CaCerts(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve certs: %w", err)
	}
	log.Debug("Received certs:")
	for _, c := range caCerts {
		log.Debugf("\t%v", c.Subject.CommonName)
	}
	if len(caCerts) == 0 {
		return nil, fmt.Errorf("no certs provided")
	}

	log.Warn("Setting retrieved cert for future authentication")
	err = client.SetCAs([]*x509.Certificate{caCerts[len(caCerts)-1]})
	if err != nil {
		return nil, fmt.Errorf("failed to set EST CA: %w", err)
	}

	cert, err := client.SimpleEnroll(addr, csr)
	if err != nil {
		return nil, fmt.Errorf("failed to enroll cert: %w", err)
	}

	return append([]*x509.Certificate{cert}, caCerts...), nil
}

func provisioningRequired(p string) bool {
	// Stateless operation always requires provisioning
	if p == "" {
		log.Info("SNP Provisioning REQUIRED")
		return true
	}

	// If any of the required files is not present, we need to provision
	if _, err := os.Stat(path.Join(p, snpChainFile)); err != nil {
		log.Info("SNP Provisioning REQUIRED")
		return true
	}
	if _, err := os.Stat(path.Join(p, signingChainFile)); err != nil {
		log.Info("SNP Provisioning REQUIRED")
		return true
	}
	if _, err := os.Stat(path.Join(p, snpPrivFile)); err != nil {
		log.Info("SNP Provisioning REQUIRED")
		return true
	}

	log.Info("SNP Provisioning NOT REQUIRED")

	return false
}

func loadCredentials(p string) ([]*x509.Certificate, []*x509.Certificate,
	crypto.PrivateKey, error,
) {
	data, err := os.ReadFile(path.Join(p, snpChainFile))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read AK chain from %v: %w", p, err)
	}
	akchain, err := internal.ParseCertsPem(data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse AK certs: %w", err)
	}
	log.Tracef("Parsed stored AK chain of length %v", len(akchain))

	data, err = os.ReadFile(path.Join(p, signingChainFile))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read IK chain from %v: %w", p, err)
	}
	ikchain, err := internal.ParseCertsPem(data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse IK certs: %w", err)
	}
	log.Tracef("Parsed stored IK chain of length %v", len(akchain))

	data, err = os.ReadFile(path.Join(p, snpPrivFile))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read SNP private key from %v: %w", p, err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse SNP private key: %w", err)
	}

	return akchain, ikchain, priv, nil
}

func saveCredentials(p string, snp *Snp) error {
	akchainPem := make([]byte, 0)
	for _, cert := range snp.snpCertChain {
		c := internal.WriteCertPem(cert)
		akchainPem = append(akchainPem, c...)
	}
	if err := os.WriteFile(path.Join(p, snpChainFile), akchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(p, snpChainFile), err)
	}

	ikchainPem := make([]byte, 0)
	for _, cert := range snp.signingCertChain {
		c := internal.WriteCertPem(cert)
		ikchainPem = append(ikchainPem, c...)
	}
	if err := os.WriteFile(path.Join(p, signingChainFile), ikchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(p, signingChainFile), err)
	}

	key, err := x509.MarshalPKCS8PrivateKey(snp.priv)
	if err != nil {
		return fmt.Errorf("failed marshal private key: %w", err)
	}
	if err := os.WriteFile(path.Join(p, snpPrivFile), key, 0600); err != nil {
		return fmt.Errorf("failed to write %v: %w", path.Join(p, snpPrivFile), err)
	}

	return nil
}
