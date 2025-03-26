// Copyright (c) 2021 - 2024 Fraunhofer AISEC
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

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	est "github.com/Fraunhofer-AISEC/cmc/est/estclient"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/google/go-sev-guest/client"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "snpdriver")

type certFormat int

const (
	PEM = iota
	DER
)

const (
	snpChainFile     = "snp_ak_chain.pem"
	signingChainFile = "snp_ik_chain.pem"
	snpPrivFile      = "snp_ik_private.key"
)

var (
	vlekUuid = []byte{0xa8, 0x07, 0x4b, 0xc2, 0xa2, 0x5a, 0x48, 0x3e, 0xaa, 0xe6, 0x39, 0xc0, 0x45, 0xa0, 0xb8, 0xa1}
)

// Snp is a structure required for implementing the Measure method
// of the attestation report Measurer interface
type Snp struct {
	akChain []*x509.Certificate // SNP VCEK / VLEK certificate chain
	ikChain []*x509.Certificate
	ikPriv  crypto.PrivateKey
}

type SnpCertTableEntry struct {
	Uuid   [16]byte
	Offset uint32
	Length uint32
}

// Name returns the name of the driver
func (s *Snp) Name() string {
	return "SNP driver"
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
		log.Info("Performing SNP provisioning")
		// Create new private key for signing
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate private key: %w", err)
		}
		snp.ikPriv = priv

		snp.akChain, snp.ikChain, err = provisionSnp(priv, c.DeviceConfig, c.ServerAddr)
		if err != nil {
			return fmt.Errorf("failed to provision snp driver: %w", err)
		}

		if c.StoragePath != "" {
			err = saveCredentials(c.StoragePath, snp)
			if err != nil {
				return fmt.Errorf("failed to save SNP credentials: %w", err)
			}
		}
	} else {
		snp.akChain, snp.ikChain, snp.ikPriv, err = loadCredentials(c.StoragePath)
		if err != nil {
			return fmt.Errorf("failed to load SNP credentials: %w", err)
		}
	}

	return nil
}

// Measure implements the attestation reports generic Measure interface to be called
// as a plugin during attestation report generation
func (snp *Snp) Measure(nonce []byte) (ar.Measurement, error) {

	log.Debug("Collecting SNP measurements")

	if snp == nil {
		return ar.Measurement{}, errors.New("internal error: SNP object is nil")
	}

	data, err := getMeasurement(nonce)
	if err != nil {
		return ar.Measurement{}, fmt.Errorf("failed to get SNP Measurement: %w", err)
	}

	measurement := ar.Measurement{
		Type:     "SNP Measurement",
		Evidence: data,
		Certs:    internal.WriteCertsDer(snp.akChain),
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

// GetKeyHandles returns private and public key handles as a generic crypto interface
func (snp *Snp) GetKeyHandles(sel ar.KeySelection) (crypto.PrivateKey, crypto.PublicKey, error) {
	if snp == nil {
		return nil, nil, errors.New("internal error: TDX object is nil")
	}

	if sel == ar.AK {
		if len(snp.akChain) == 0 {
			return nil, nil, fmt.Errorf("internal error: SNP AK certificate not present")
		}
		// Only return the public key, as the VCEK / VLEK is not directly accessible
		return nil, snp.akChain[0].PublicKey, nil
	} else if sel == ar.IK {
		return snp.ikPriv, &snp.ikPriv.(*ecdsa.PrivateKey).PublicKey, nil
	}
	return nil, nil, fmt.Errorf("internal error: unknown key selection %v", sel)
}

// GetCertChain returns the certificate chain for the specified key
func (snp *Snp) GetCertChain(sel ar.KeySelection) ([]*x509.Certificate, error) {
	if snp == nil {
		return nil, errors.New("internal error: SW object is nil")
	}

	if sel == ar.AK {
		log.Debugf("Returning %v AK certificates", len(snp.akChain))
		return snp.akChain, nil
	} else if sel == ar.IK {
		log.Debugf("Returning %v IK certificates", len(snp.ikChain))
		return snp.ikChain, nil
	}
	return nil, fmt.Errorf("internal error: unknown key selection %v", sel)
}

func getMeasurement(nonce []byte) ([]byte, error) {

	if len(nonce) > 64 {
		return nil, errors.New("user Data must be at most 64 bytes")
	}

	log.Debugf("Generating SNP attestation report with nonce: %v", hex.EncodeToString(nonce))

	d, err := client.OpenDevice()
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/sev-guest")
	}
	defer d.Close()

	var ud [64]byte
	copy(ud[:], nonce)
	//lint:ignore SA1019 will be updated later
	buf, err := client.GetRawReport(d, ud)
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP attestation report")
	}

	log.Debug("Generated SNP attestation report")

	return buf, nil
}

func getVlek() ([]byte, error) {

	log.Debug("Fetching VLEK via extended attestation report request")

	d, err := client.OpenDevice()
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/sev-guest")
	}
	defer d.Close()

	//lint:ignore SA1019 will be updated later
	_, certs, err := client.GetRawExtendedReport(d, [64]byte{0})
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP attestation report")
	}

	log.Debugf("Fetched extended SNP attestation report with certs length %v", len(certs))

	b := bytes.NewBuffer(certs)
	for {
		log.Debug("Parsing cert table entry..")
		var entry SnpCertTableEntry
		err = binary.Read(b, binary.LittleEndian, &entry)
		if err != nil {
			return nil, fmt.Errorf("failed to decode cert table entry: %w", err)
		}

		if entry == (SnpCertTableEntry{}) {
			log.Debugf("Reached last (zero) SNP cert table entry")
			break
		}

		log.Debugf("Found cert table entry with UUID %v", hex.EncodeToString(entry.Uuid[:]))

		if bytes.Equal(entry.Uuid[:], vlekUuid) {
			log.Debugf("Found VLEK offset %v length %v", entry.Offset, entry.Length)
			return certs[entry.Offset : entry.Offset+entry.Length], nil
		}
	}

	return nil, errors.New("could not find VLEK in certificates")
}

func provisionSnp(priv crypto.PrivateKey, devConf ar.DeviceConfig, addr string,
) ([]*x509.Certificate, []*x509.Certificate, error) {

	// Create IK CSR and fetch new certificate including its chain from EST server
	ikchain, err := provisionIk(priv, devConf, addr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signing cert chain: %w", err)
	}

	// Fetch SNP certificate chain for VCEK/VLEK (SNP Attestation Key)
	akchain, err := fetchAk(addr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get SNP cert chain: %w", err)
	}

	return akchain, ikchain, nil
}

func fetchAk(addr string) ([]*x509.Certificate, error) {

	// Fetch the SNP attestation report signing key. Usually, this is the VCEK. However,
	// in cloud environments, the CSP might disable VCEK usage, instead the VLEK is used.
	// Fetch an initial attestation report to determine which key is used.
	arRaw, err := getMeasurement(make([]byte, 64))
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP report: %w", err)
	}
	s, err := verifier.DecodeSnpReport(arRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SNP report: %w", err)
	}

	akType, err := verifier.GetAkType(s.KeySelection)
	if err != nil {
		return nil, fmt.Errorf("could not determine SNP attestation report attestation key")
	}

	// TODO mandate server authentication in the future, otherwise
	// this step has to happen in a secure environment
	log.Warn("Creating new EST client without server authentication")
	client := est.NewClient(nil)

	var signingCert *x509.Certificate
	if akType == verifier.VCEK {
		// VCEK is used, simply request EST enrollment for SNP chip ID and TCB
		log.Debug("Enrolling VCEK via EST")
		signingCert, err = client.GetSnpVcek(addr, s.ChipId, s.CurrentTcb)
		if err != nil {
			return nil, fmt.Errorf("failed to enroll SNP: %w", err)
		}
	} else if akType == verifier.VLEK {
		// VLEK is used, in this case we fetch the VLEK from the host
		vlek, err := getVlek()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch VLEK: %w", err)
		}
		log.Debug("Parsing VLEK")
		signingCert, err = x509.ParseCertificate(vlek)
		if err != nil {
			return nil, fmt.Errorf("failed to parse VLEK")
		}
		log.Debugf("Successfully parsed VLEK CN=%v", signingCert.Subject.CommonName)
	} else {
		return nil, fmt.Errorf("internal error: signing cert not initialized")
	}

	// Fetch intermediate CAs and CA depending on signing key (VLEK / VCEK)
	log.Debugf("Fetching SNP CA for %v from %v", akType.String(), addr)
	ca, err := client.GetSnpCa(addr, akType)
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP CA from EST server: %w", err)
	}

	return append([]*x509.Certificate{signingCert}, ca...), nil
}

func provisionIk(priv crypto.PrivateKey, devConf ar.DeviceConfig, addr string,
) ([]*x509.Certificate, error) {

	// Get CA certificates and enroll newly created CSR
	// TODO provision EST server certificate with a different mechanism,
	// otherwise this step has to happen in a secure environment. Allow
	// different CAs for metadata and the EST server authentication
	log.Warn("Creating new EST client without server authentication")
	client := est.NewClient(nil)

	log.Debug("Retrieving CA certs")
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

	// Create IK CSR for authentication
	csr, err := ar.CreateCsr(priv, devConf.Snp.IkCsr)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSRs: %w", err)
	}

	// Request IK certificate from EST server
	cert, err := client.SimpleEnroll(addr, csr)
	if err != nil {
		return nil, fmt.Errorf("failed to enroll IK cert: %w", err)
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
	log.Debugf("Parsed stored AK chain of length %v", len(akchain))

	data, err = os.ReadFile(path.Join(p, signingChainFile))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read IK chain from %v: %w", p, err)
	}
	ikchain, err := internal.ParseCertsPem(data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse IK certs: %w", err)
	}
	log.Debugf("Parsed stored IK chain of length %v", len(akchain))

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
	for _, cert := range snp.akChain {
		c := internal.WriteCertPem(cert)
		akchainPem = append(akchainPem, c...)
	}
	if err := os.WriteFile(path.Join(p, snpChainFile), akchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(p, snpChainFile), err)
	}

	ikchainPem := make([]byte, 0)
	for _, cert := range snp.ikChain {
		c := internal.WriteCertPem(cert)
		ikchainPem = append(ikchainPem, c...)
	}
	if err := os.WriteFile(path.Join(p, signingChainFile), ikchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(p, signingChainFile), err)
	}

	key, err := x509.MarshalPKCS8PrivateKey(snp.ikPriv)
	if err != nil {
		return fmt.Errorf("failed marshal private key: %w", err)
	}
	if err := os.WriteFile(path.Join(p, snpPrivFile), key, 0600); err != nil {
		return fmt.Errorf("failed to write %v: %w", path.Join(p, snpPrivFile), err)
	}

	return nil
}
