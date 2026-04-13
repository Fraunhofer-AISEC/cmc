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

package keymgr

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path"

	"golang.org/x/exp/maps"

	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers"
	"github.com/Fraunhofer-AISEC/cmc/drivers/tpmdriver"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/prover"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

var (
	log = logrus.WithField("service", "keymgr")
)

type KeyFormat int

const (
	KeyUnknown KeyFormat = iota
	KeyPEM
	KeyTPM
)

type KeyMgr struct {
	keys        map[string]key
	keyPath     string
	certsPath   string
	tpm         *tpmdriver.Tpm
	provisioner Enroller
}

type key struct {
	private   crypto.Signer
	certChain []*x509.Certificate
}

type KeyEnrollmentParams struct {
	KeyConfig  api.TLSKeyConfig
	Metadata   map[string][]byte
	Drivers    []drivers.Driver
	Serializer ar.Serializer
	ArHashAlg  crypto.Hash
}

func NewKeyMgr(storagePath string, drivers []drivers.Driver, provisioner Enroller) (*KeyMgr, error) {

	mgr := &KeyMgr{
		keyPath:     path.Join(storagePath, "keys"),
		certsPath:   path.Join(storagePath, "certs"),
		keys:        map[string]key{},
		provisioner: provisioner,
	}

	// Add drivers for hardware keys (currently only tpm keys supported)
	for _, driver := range drivers {
		if tpm, ok := driver.(*tpmdriver.Tpm); ok {
			mgr.tpm = tpm
		}
	}

	err := os.MkdirAll(mgr.keyPath, 0755)
	if err != nil {
		return nil, fmt.Errorf("failed to create keys path: %w", err)
	}
	err = os.MkdirAll(mgr.certsPath, 0755)
	if err != nil {
		return nil, fmt.Errorf("failed to create certs path: %w", err)
	}

	err = mgr.loadKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to load keys: %w", err)
	}

	err = mgr.loadCerts()
	if err != nil {
		return nil, fmt.Errorf("failed to load certs: %w", err)
	}

	return mgr, nil
}

func (mgr *KeyMgr) EnrollKey(p *KeyEnrollmentParams) (string, error) {

	keyId := uuid.New().String()

	switch p.KeyConfig.Type {
	case "tpm":
		if mgr.tpm == nil {
			return "", fmt.Errorf("failed to enroll tpm key: tpm support disabled")
		}
		tpmKey, err := tpmdriver.NewKey(mgr.tpm, p.KeyConfig.Alg)
		if err != nil {
			return "", fmt.Errorf("failed to create TPM key: %w", err)
		}

		certChain, err := tpmEnroll(mgr.provisioner, tpmKey, mgr.tpm.GetAkPublic(), p)
		if err != nil {
			return "", fmt.Errorf("failed to enroll cert: %w", err)
		}

		// Store key and cert in memory and persistently
		err = tpmKey.Export(path.Join(mgr.keyPath, keyId))
		if err != nil {
			return "", fmt.Errorf("failed to export tpm key: %w", err)
		}
		err = os.WriteFile(path.Join(mgr.certsPath, keyId), internal.WriteCertsPemBlob(certChain), 0644)
		if err != nil {
			// Delete key file, as it is useless without a valid certificate
			os.Remove(path.Join(mgr.keyPath, keyId))
			return "", fmt.Errorf("failed to write certs: %w", err)
		}
		mgr.keys[keyId] = key{
			private:   tpmKey,
			certChain: certChain,
		}

	case "sw":
		priv, err := newSwKey(p.KeyConfig.Alg)
		if err != nil {
			return "", fmt.Errorf("failed to create key: %w", err)
		}

		certChain, err := simpleEnroll(mgr.provisioner, priv, p)
		if err != nil {
			return "", fmt.Errorf("failed to enroll cert: %w", err)
		}

		// Store key and cert in memory and persistently
		err = internal.StorePrivateKeyPem(path.Join(mgr.keyPath, keyId), priv)
		if err != nil {
			return "", fmt.Errorf("failed to store private key: %w", err)
		}
		err = os.WriteFile(path.Join(mgr.certsPath, keyId), internal.WriteCertsPemBlob(certChain), 0644)
		if err != nil {
			// Delete key file, as it is useless without a valid certificate
			os.Remove(path.Join(mgr.keyPath, keyId))
			return "", fmt.Errorf("failed to write certs: %w", err)
		}
		mgr.keys[keyId] = key{
			private:   priv,
			certChain: certChain,
		}

	default:
		return "", fmt.Errorf("unsupported key type %q", p.KeyConfig.Type)
	}

	return keyId, nil
}

func (mgr *KeyMgr) GetKey(id string) (crypto.Signer, error) {

	key, ok := mgr.keys[id]
	if !ok {
		return nil, fmt.Errorf("key with id %q not present", id)
	}

	return key.private, nil
}

func (mgr *KeyMgr) GetCertChain(id string) ([]*x509.Certificate, error) {

	key, ok := mgr.keys[id]
	if !ok {
		return nil, fmt.Errorf("cert with id %q not present", id)
	}

	return key.certChain, nil
}

func (mgr *KeyMgr) GetKeyIds() []string {
	return maps.Keys(mgr.keys)
}

func newSwKey(keyAlg string) (crypto.Signer, error) {

	switch keyAlg {
	case "EC256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "EC384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "EC521":
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "RSA2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "RSA4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, fmt.Errorf("unsupported key algorithm %q", keyAlg)
	}
}

func (mgr *KeyMgr) loadKeys() error {

	if _, err := os.Stat(mgr.keyPath); err != nil {
		log.Debug("No IKs to load")
		return nil
	}

	files, err := os.ReadDir(mgr.keyPath)
	if err != nil {
		return fmt.Errorf("failed to read storage path: %w", err)
	}

	log.Debugf("Loading %v keys", len(files))

	for _, f := range files {
		id := f.Name()
		path := path.Join(mgr.keyPath, f.Name())
		keyBytes, err := os.ReadFile(path)
		if err != nil {
			log.Warnf("Failed to read key file: %v", err)
			continue
		}

		// Parse file and determine whether this is an sw key (ecdsa, rsa) or a tpm key
		switch detectKeyFormat(keyBytes) {
		case KeyPEM:
			p, err := internal.ParsePrivateKey(keyBytes)
			if err != nil {
				log.Warnf("Failed to parse private key: %v", err)
				continue
			}
			priv, ok := p.(crypto.Signer)
			if !ok {
				log.Warnf("Private key type %T does not implement signer interface", p)
				continue
			}
			mgr.keys[id] = key{
				private: priv,
			}
			log.Tracef("Successfully loaded key with id %s", id)
		case KeyTPM:
			if mgr.tpm == nil {
				log.Warnf("Failed to load tpm key: tpm support disabled")
				continue
			}
			tpmKey, err := tpmdriver.ImportKey(mgr.tpm, keyBytes)
			if err != nil {
				log.Warnf("Failed to import tpm key: %v", err)
				continue
			}
			mgr.keys[id] = key{
				private: tpmKey,
			}
			log.Tracef("Successfully loaded tpm key with id %s", id)
		default:
			log.Warnf("Failed to detect key format")
			continue
		}
	}
	return nil
}

func (mgr *KeyMgr) loadCerts() error {

	if _, err := os.Stat(mgr.certsPath); err != nil {
		log.Debug("No IK certs to load")
		return nil
	}

	files, err := os.ReadDir(mgr.certsPath)
	if err != nil {
		return fmt.Errorf("failed to read storage path: %v", err)
	}

	log.Debugf("Loading %v certs", len(files))

	for _, f := range files {
		id := f.Name()
		path := path.Join(mgr.certsPath, f.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			log.Warnf("Failed to read cert file: %v", err)
			continue
		}
		certs, err := internal.ParseCertsPem(data)
		if err != nil {
			log.Warnf("Failed to parse certs: %v", err)
			continue
		}

		key, ok := mgr.keys[id]
		if !ok {
			log.Warnf("No key exists for certificate with ID %s. Do not load", id)
			continue
		}

		key.certChain = certs

		mgr.keys[id] = key
	}
	return nil
}

func detectKeyFormat(data []byte) KeyFormat {
	data = bytes.TrimSpace(data)

	// JSON TPM key detection
	if json.Valid(data) {
		return KeyTPM
	}

	// PEM SW key detection
	if block, _ := pem.Decode(data); block != nil {
		return KeyPEM
	}

	return KeyUnknown
}

func simpleEnroll(provisioner Enroller, priv crypto.PrivateKey, p *KeyEnrollmentParams) ([]*x509.Certificate, error) {

	caCerts, err := provisioner.CaCerts()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve certs: %w", err)
	}

	csr, report, err := prepareEnroll(priv, p)
	if err != nil {
		return nil, err
	}

	cert, err := provisioner.AttestEnroll(csr, report)
	if err != nil {
		return nil, fmt.Errorf("failed to enroll IK cert: %w", err)
	}

	return append([]*x509.Certificate{cert}, caCerts...), nil
}

func tpmEnroll(provisioner Enroller, tpmKey *tpmdriver.TpmKey, akPublic []byte, p *KeyEnrollmentParams) ([]*x509.Certificate, error) {

	caCerts, err := provisioner.CaCerts()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve certs: %w", err)
	}

	csr, report, err := prepareEnroll(tpmKey, p)
	if err != nil {
		return nil, err
	}

	ikParams, err := tpmKey.GetCertificationParameters()
	if err != nil {
		return nil, fmt.Errorf("failed to get tpm key certification parameters: %w", err)
	}

	cert, err := provisioner.TpmCertifyEnroll(csr, ikParams, akPublic, report)
	if err != nil {
		return nil, fmt.Errorf("failed to enroll IK cert: %w", err)
	}

	return append([]*x509.Certificate{cert}, caCerts...), nil
}

func prepareEnroll(priv crypto.PrivateKey, p *KeyEnrollmentParams) (*x509.CertificateRequest, []byte, error) {

	// Create CSR for authentication with provided properties
	csr, err := internal.CreateCsr(priv, p.KeyConfig.Cn, p.KeyConfig.DNSNames, p.KeyConfig.IPAddresses)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSRs: %w", err)
	}

	// Use Subject Key Identifier (SKI) as nonce for attestation report
	// We use SHA-256 instead of SHA-1 for the SKI as we control both sides
	pubKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CSR public key: %v", err)
	}
	nonce := sha256.Sum256(pubKey)

	// Fetch attestation report as part of client authentication
	report, err := prover.Generate(nonce[:], nil, p.Metadata, p.Drivers, p.Serializer, p.ArHashAlg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate attestation report: %w", err)
	}

	return csr, report, nil
}
