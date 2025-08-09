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

//go:build amd64 && (!nodefaults || snp)

package snpdriver

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/prover"
	"github.com/Fraunhofer-AISEC/cmc/provision"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/google/go-sev-guest/client"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "snpdriver")

const (
	akChainFile = "snp_ak_chain.pem"
	ikChainFile = "snp_ik_chain.pem"
	ikFile      = "snp_ik_private.key"
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
	vmpl    int
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

		err = snp.provision(c)
		if err != nil {
			return fmt.Errorf("failed to provision snp driver: %w", err)
		}

		if c.StoragePath != "" {
			err = snp.saveCredentials(c.StoragePath)
			if err != nil {
				return fmt.Errorf("failed to save SNP credentials: %w", err)
			}
		}
	} else {
		err = snp.loadCredentials(c.StoragePath)
		if err != nil {
			return fmt.Errorf("failed to load SNP credentials: %w", err)
		}
	}

	snp.vmpl = c.Vmpl

	return nil
}

// Measure implements the attestation reports generic Measure interface to be called
// as a plugin during attestation report generation
func (snp *Snp) Measure(nonce []byte) ([]ar.Measurement, error) {

	log.Debug("Collecting SNP measurements")

	if snp == nil {
		return nil, errors.New("internal error: SNP object is nil")
	}

	data, err := GetMeasurement(nonce, snp.vmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP Measurement: %w", err)
	}

	measurement := ar.Measurement{
		Type:     "SNP Measurement",
		Evidence: data,
		Certs:    internal.WriteCertsDer(snp.akChain),
	}

	return []ar.Measurement{measurement}, nil
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
		return nil, nil, errors.New("internal error: SNP object is nil")
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

func GetMeasurement(nonce []byte, vmpl int) ([]byte, error) {

	if len(nonce) > 64 {
		return nil, errors.New("user Data must be at most 64 bytes")
	}

	log.Debugf("Generating SNP attestation report on VMPL %v with nonce: %v", vmpl,
		hex.EncodeToString(nonce))

	d, err := client.OpenDevice()
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/sev-guest")
	}
	defer d.Close()

	var ud [64]byte
	copy(ud[:], nonce)
	//lint:ignore SA1019 will be updated later
	buf, err := client.GetRawReportAtVmpl(d, ud, vmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP attestation report")
	}

	log.Debug("Generated SNP attestation report")

	return buf, nil
}

func getVlek(vmpl int) ([]byte, error) {

	log.Debugf("Fetching VLEK via extended attestation report request on VMPL %v", vmpl)

	d, err := client.OpenDevice()
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/sev-guest")
	}
	defer d.Close()

	//lint:ignore SA1019 will be updated later
	_, certs, err := client.GetRawExtendedReportAtVmpl(d, [64]byte{0}, vmpl)
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

func (snp *Snp) provision(c *ar.DriverConfig) error {
	var err error

	// Create new private key for signing
	snp.ikPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	log.Debug("Retrieving CA certs")
	caCerts, err := c.Provisioner.CaCerts()
	if err != nil {
		return fmt.Errorf("failed to retrieve certs: %w", err)
	}

	// Fetch SNP certificate chain for VCEK/VLEK (SNP Attestation Key)
	snp.akChain, err = fetchAk(c)
	if err != nil {
		return fmt.Errorf("failed to get SNP cert chain: %w", err)
	}

	// Create IK CSR and fetch new certificate including its chain from EST server
	ikCert, err := snp.provisionIk(c.Provisioner, snp.ikPriv, c)
	if err != nil {
		return fmt.Errorf("failed to get signing cert chain: %w", err)
	}
	snp.ikChain = append([]*x509.Certificate{ikCert}, caCerts...)

	return nil
}

func fetchAk(c *ar.DriverConfig) ([]*x509.Certificate, error) {

	// Generate random nonce
	nonce := make([]byte, 64)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to read random bytes: %w", err)
	}

	// Fetch the SNP attestation report signing key. Usually, this is the VCEK. However,
	// in cloud environments, the CSP might disable VCEK usage, instead the VLEK is used.
	// Fetch an initial attestation report to determine which key is used.
	arRaw, err := GetMeasurement(nonce, c.Vmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP report: %w", err)
	}
	s, err := verifier.DecodeSnpReport(arRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SNP report: %w", err)
	}

	// Verify nonce
	if !bytes.Equal(nonce, s.ReportData[:]) {
		return nil, fmt.Errorf("failed to verify SNP report nonce (expected %v, got %v)",
			hex.EncodeToString(nonce), hex.EncodeToString(s.ReportData[:]))
	}
	log.Debugf("Successfully decoded attestation report and verified nonce")

	akType, err := internal.GetAkType(s.KeySelection)
	if err != nil {
		return nil, fmt.Errorf("could not determine SNP attestation report attestation key")
	}

	var akCert *x509.Certificate
	if akType == internal.VCEK {
		// VCEK is used, simply request EST enrollment for SNP chip ID and TCB
		log.Debug("Enrolling VCEK via EST")
		akCert, err = c.Provisioner.GetSnpVcek(s.ChipId, s.CurrentTcb)
		if err != nil {
			return nil, fmt.Errorf("failed to enroll SNP: %w", err)
		}
	} else if akType == internal.VLEK {
		// VLEK is used, in this case we fetch the VLEK from the host
		vlek, err := getVlek(c.Vmpl)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch VLEK: %w", err)
		}
		log.Debug("Parsing VLEK")
		akCert, err = x509.ParseCertificate(vlek)
		if err != nil {
			return nil, fmt.Errorf("failed to parse VLEK")
		}
		log.Debugf("Successfully parsed VLEK CN=%v", akCert.Subject.CommonName)
	} else {
		return nil, fmt.Errorf("internal error: signing cert not initialized")
	}

	// Fetch intermediate CAs and CA depending on signing key (VLEK / VCEK)
	log.Debugf("Fetching SNP CA for %v from %v", akType.String(), c.ServerAddr)
	ca, err := c.Provisioner.GetSnpCa(akType)
	if err != nil {
		return nil, fmt.Errorf("failed to get SNP CA from EST server: %w", err)
	}

	return append([]*x509.Certificate{akCert}, ca...), nil
}

func (snp *Snp) provisionIk(provisioner provision.Provisioner, priv crypto.PrivateKey, c *ar.DriverConfig,
) (*x509.Certificate, error) {

	// Create IK CSR for authentication
	csr, err := ar.CreateCsr(priv, c.DeviceConfig.Snp.IkCsr)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSRs: %w", err)
	}

	// Use Subject Key Identifier (SKI) as nonce for attestation report
	pubKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR public key: %v", err)
	}
	nonce := sha1.Sum(pubKey)

	// Fetch attestation report as part of client authentication
	report, metadata, err := prover.Generate(nonce[:], nil, c.Metadata, []ar.Driver{snp}, c.Serializer)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation report: %w", err)
	}
	r, err := c.Serializer.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal the Attestation Report: %v", err)
	}
	signedReport, err := prover.Sign(r, snp, c.Serializer, ar.IK)
	if err != nil {
		return nil, fmt.Errorf("failed to sign attestation report: %w", err)
	}

	// Request IK certificate from EST server
	cert, err := provisioner.CcEnroll(csr, signedReport, internal.ConvertToArray(metadata))
	if err != nil {
		return nil, fmt.Errorf("failed to enroll IK cert: %w", err)
	}

	return cert, nil
}

func provisioningRequired(p string) bool {
	// Stateless operation always requires provisioning
	if p == "" {
		log.Info("SNP Provisioning REQUIRED")
		return true
	}

	// If any of the required files is not present, we need to provision
	if _, err := os.Stat(path.Join(p, akChainFile)); err != nil {
		log.Info("SNP Provisioning REQUIRED")
		return true
	}
	if _, err := os.Stat(path.Join(p, ikChainFile)); err != nil {
		log.Info("SNP Provisioning REQUIRED")
		return true
	}
	if _, err := os.Stat(path.Join(p, ikFile)); err != nil {
		log.Info("SNP Provisioning REQUIRED")
		return true
	}

	log.Info("SNP Provisioning NOT REQUIRED")

	return false
}

func (snp *Snp) loadCredentials(p string) error {

	data, err := os.ReadFile(path.Join(p, akChainFile))
	if err != nil {
		return fmt.Errorf("failed to read AK chain from %v: %w", p, err)
	}
	snp.akChain, err = internal.ParseCertsPem(data)
	if err != nil {
		return fmt.Errorf("failed to parse AK certs: %w", err)
	}
	log.Debugf("Parsed stored AK chain of length %v", len(snp.akChain))

	data, err = os.ReadFile(path.Join(p, ikChainFile))
	if err != nil {
		return fmt.Errorf("failed to read IK chain from %v: %w", p, err)
	}
	snp.ikChain, err = internal.ParseCertsPem(data)
	if err != nil {
		return fmt.Errorf("failed to parse IK certs: %w", err)
	}
	log.Debugf("Parsed stored IK chain of length %v", len(snp.ikChain))

	data, err = os.ReadFile(path.Join(p, ikFile))
	if err != nil {
		return fmt.Errorf("failed to read SNP private key from %v: %w", p, err)
	}
	snp.ikPriv, err = x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return fmt.Errorf("failed to parse SNP private key: %w", err)
	}

	return nil
}

func (snp *Snp) saveCredentials(p string) error {
	akchainPem := make([]byte, 0)
	for _, cert := range snp.akChain {
		c := internal.WriteCertPem(cert)
		akchainPem = append(akchainPem, c...)
	}
	if err := os.WriteFile(path.Join(p, akChainFile), akchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(p, akChainFile), err)
	}

	ikchainPem := make([]byte, 0)
	for _, cert := range snp.ikChain {
		c := internal.WriteCertPem(cert)
		ikchainPem = append(ikchainPem, c...)
	}
	if err := os.WriteFile(path.Join(p, ikChainFile), ikchainPem, 0644); err != nil {
		return fmt.Errorf("failed to write  %v: %w", path.Join(p, ikChainFile), err)
	}

	key, err := x509.MarshalPKCS8PrivateKey(snp.ikPriv)
	if err != nil {
		return fmt.Errorf("failed marshal private key: %w", err)
	}
	if err := os.WriteFile(path.Join(p, ikFile), key, 0600); err != nil {
		return fmt.Errorf("failed to write %v: %w", path.Join(p, ikFile), err)
	}

	return nil
}
